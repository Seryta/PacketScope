package io.github.packetscope.core.decrypt

import io.github.packetscope.core.pcap.Field
import io.github.packetscope.core.pcap.FieldNames
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols

/**
 * Post-processing：扫描 frames，按 5-tuple 聚类 TLS session，用 KeyLogStore 里的
 * secret 解密 ApplicationData，把结果作为新 Field 挂到 TLS layer 上。
 *
 * 支持：
 *   - TLS 1.3 + TLS_AES_128_GCM_SHA256 (0x1301)
 *   - TLS 1.2 AES-GCM (0xC02F/0xC02B/0x009C/0xC030/0xC02C/0x009D)
 *
 * 其它 cipher suite 在 layer 上标 "unsupported cipher"，不做处理。
 */
object TlsDecryptionPass {

    private val TLS13_CIPHERS = setOf(0x1301, 0x1302, 0x1303)
    private val TLS12_CIPHERS = setOf(
        // AES-GCM
        0xC02F, 0xC02B, 0x009C, 0xC030, 0xC02C, 0x009D,
        // ChaCha20-Poly1305
        0xCCA8, 0xCCA9, 0xCCAA,
    )

    fun process(frames: List<Frame>): List<Frame> {
        if (!KeyLogStore.isLoaded) return frames

        val sessions = buildSessions(frames)
        val replacements = mutableMapOf<Int, Frame>()
        for (session in sessions.values) {
            val pair = prepareDecryptors(session)
            for (idx in session.frameIndices.sorted()) {
                val frame = frameAt(frames, idx) ?: continue
                val tls = frame.layers.firstOrNull { it.protocol == Protocols.TLS } ?: continue
                val contentType = tls.fields.firstOrNull { it.name == "Content type" }
                    ?.value?.substringBefore(" ")?.toIntOrNull() ?: continue
                if (contentType != 23) continue  // 只解 ApplicationData
                val extras = decryptOne(frame, tls, session, pair) ?: continue
                if (extras.isEmpty()) continue
                val newTls = tls.copy(fields = tls.fields + extras)
                val newLayers = frame.layers.map { if (it === tls) newTls else it }
                replacements[frame.index] = frame.copy(layers = newLayers)
            }
        }
        if (replacements.isEmpty()) return frames
        return frames.map { replacements[it.index] ?: it }
    }

    /** pass 1：按 5-tuple 聚类，记录每个 session 的 client/server randoms + cipher */
    private fun buildSessions(frames: List<Frame>): Map<String, TlsSession> {
        val sessions = mutableMapOf<String, TlsSession>()
        for (frame in frames) {
            val tls = frame.layers.firstOrNull { it.protocol == Protocols.TLS } ?: continue
            val endpoints = endpointsOf(frame) ?: continue
            val (a, b) = endpoints
            val sKey = sessionKey(a, b)
            val handshake = tls.fields.firstOrNull { it.name == FieldNames.HANDSHAKE }
            val hsType = handshake?.children?.firstOrNull { it.name == "Handshake type" }
                ?.value?.substringBefore(" ")?.toIntOrNull()
            when (hsType) {
                1 -> {  // ClientHello
                    val random = handshake.children
                        .firstOrNull { it.name == "Client random" }
                        ?.let { extractBytes(frame, it) }
                    sessions[sKey] = TlsSession(client = a, server = b, clientRandom = random)
                }
                2 -> {  // ServerHello
                    val s = sessions[sKey] ?: continue
                    s.serverRandom = handshake.children
                        .firstOrNull { it.name == "Server random" }
                        ?.let { extractBytes(frame, it) }
                    s.cipherSuite = handshake.children
                        .firstOrNull { it.name == "Cipher suite" }
                        ?.value
                        ?.substringAfter("0x")?.substringBefore(" ")
                        ?.toIntOrNull(16)
                }
            }
            sessions[sKey]?.frameIndices?.add(frame.index)
        }
        return sessions
    }

    private fun extractBytes(frame: Frame, f: Field): ByteArray? {
        val r = f.byteRange ?: return null
        return frame.data.copyOfRange(r.first, r.last + 1)
    }

    /** 根据 cipher suite 派出 TLS 1.3 / TLS 1.2 decryptor 或 status 错误信息 */
    private fun prepareDecryptors(s: TlsSession): SessionDecryptors {
        val cipher = s.cipherSuite ?: return SessionDecryptors(null, null, null, null, null)
        if (cipher in TLS13_CIPHERS) return prepareTls13(s, cipher)
        if (cipher in TLS12_CIPHERS) return prepareTls12(s, cipher)
        return SessionDecryptors(
            status = "✗ unsupported cipher 0x%04x".format(cipher),
        )
    }

    private fun prepareTls13(s: TlsSession, cipher: Int): SessionDecryptors {
        val random = s.clientRandom
            ?: return SessionDecryptors(status = null)
        val secrets = KeyLogStore.lookup(random)
            ?: return SessionDecryptors(status = "✗ no key for this session")
        val cSec = secrets["CLIENT_TRAFFIC_SECRET_0"]
        val sSec = secrets["SERVER_TRAFFIC_SECRET_0"]
        if (cSec == null || sSec == null) {
            return SessionDecryptors(status = "✗ key log missing CLIENT/SERVER_TRAFFIC_SECRET_0")
        }
        return SessionDecryptors(
            tls13Client = Tls13Decryptor.forDirection(cSec, cipher),
            tls13Server = Tls13Decryptor.forDirection(sSec, cipher),
        )
    }

    private fun prepareTls12(s: TlsSession, cipher: Int): SessionDecryptors {
        val cr = s.clientRandom ?: return SessionDecryptors(status = null)
        val sr = s.serverRandom ?: return SessionDecryptors(status = "✗ missing server_random")
        val secrets = KeyLogStore.lookup(cr)
            ?: return SessionDecryptors(status = "✗ no key for this session")
        val master = secrets["CLIENT_RANDOM"]
            ?: return SessionDecryptors(status = "✗ key log missing CLIENT_RANDOM (TLS 1.2 master_secret)")
        return SessionDecryptors(
            tls12Client = Tls12Decryptor.forDirection(master, cr, sr, cipher, isClient = true),
            tls12Server = Tls12Decryptor.forDirection(master, cr, sr, cipher, isClient = false),
        )
    }

    /** 解一条 record，返回要追加给 TLS layer 的 Field 列表（含 status / 明文等） */
    private fun decryptOne(
        frame: Frame, tls: Layer, session: TlsSession, pair: SessionDecryptors,
    ): List<Field>? {
        if (pair.status != null) return listOf(Field("Decryption", pair.status))
        val endpoints = endpointsOf(frame) ?: return null
        val isFromClient = endpoints.first == session.client
        return when {
            pair.tls13Client != null -> decryptTls13(frame, tls,
                if (isFromClient) pair.tls13Client else pair.tls13Server!!)
            pair.tls12Client != null -> decryptTls12(frame, tls,
                if (isFromClient) pair.tls12Client else pair.tls12Server!!)
            else -> null
        }
    }

    private fun decryptTls13(frame: Frame, tls: Layer, dec: Tls13Decryptor): List<Field> {
        val range = tls.byteRange
        if (range.last - range.first < 5 + 16) return emptyList()
        val header = frame.data.copyOfRange(range.first, range.first + 5)
        val ciphertext = frame.data.copyOfRange(range.first + 5, range.last + 1)
        val plaintext = dec.decryptNext(header, ciphertext)
            ?: return listOf(Field("Decryption", "✗ auth failed (key 不匹配或顺序错)"))
        val unwrapped = dec.unwrapInnerPlaintext(plaintext)
            ?: return listOf(Field("Decryption", "✓ but empty plaintext"))
        return describePlaintext(unwrapped.contentTypeName, unwrapped.data)
    }

    private fun decryptTls12(frame: Frame, tls: Layer, dec: Tls12Decryptor): List<Field> {
        val range = tls.byteRange
        if (range.last - range.first < 5 + 8 + 16) return emptyList()
        // 从 layer fields 取 content_type + version（已被 dissector 解出）
        val contentType = tls.fields.firstOrNull { it.name == "Content type" }
            ?.value?.substringBefore(" ")?.toIntOrNull() ?: return emptyList()
        val versionRaw = tls.fields.firstOrNull { it.name == "Version" }?.value
        val version = parseVersion(versionRaw) ?: return emptyList()
        val body = frame.data.copyOfRange(range.first + 5, range.last + 1)
        val plaintext = dec.decryptNext(contentType, version, body)
            ?: return listOf(Field("Decryption", "✗ auth failed (key 不匹配或顺序错)"))
        return describePlaintext("ApplicationData", plaintext)
    }

    private fun describePlaintext(typeName: String, data: ByteArray): List<Field> = buildList {
        add(Field("Decryption", "✓ $typeName (${data.size}B)"))
        add(Field("Decrypted (hex)", data.toHexLower()))
        decodeText(data)?.let { add(Field("Decrypted (text)", it)) }
    }

    /** "TLS 1.2 (0x0303)" → 0x0303 */
    private fun parseVersion(s: String?): Int? {
        if (s == null) return null
        val idx = s.indexOf("0x")
        if (idx < 0) return null
        return s.substring(idx + 2).substringBefore(")").substringBefore(" ").toIntOrNull(16)
    }

    /** 试探把 plaintext 当成可读 UTF-8 文本 */
    private fun decodeText(data: ByteArray): String? {
        if (data.isEmpty()) return null
        var printable = 0
        for (b in data) {
            val v = b.toInt() and 0xFF
            if (v in 0x20..0x7E || v == 0x09 || v == 0x0A || v == 0x0D) printable++
        }
        if (printable * 5 < data.size * 4) return null
        return data.toString(Charsets.UTF_8)
    }

    private fun endpointsOf(frame: Frame): Pair<Endpoint, Endpoint>? {
        val ip = frame.layers.firstOrNull {
            it.protocol == Protocols.IPV4 || it.protocol == Protocols.IPV6
        } ?: return null
        val tcp = frame.layers.firstOrNull { it.protocol == Protocols.TCP } ?: return null
        val src = ip.fields.firstOrNull { it.name == FieldNames.SOURCE }?.value ?: return null
        val dst = ip.fields.firstOrNull { it.name == FieldNames.DESTINATION }?.value ?: return null
        val sport = tcp.fields.firstOrNull { it.name == FieldNames.SOURCE_PORT }
            ?.value?.toIntOrNull() ?: return null
        val dport = tcp.fields.firstOrNull { it.name == FieldNames.DESTINATION_PORT }
            ?.value?.toIntOrNull() ?: return null
        return Endpoint(src, sport) to Endpoint(dst, dport)
    }

    private fun sessionKey(a: Endpoint, b: Endpoint): String {
        val sa = "${a.ip}:${a.port}"
        val sb = "${b.ip}:${b.port}"
        return if (sa < sb) "$sa|$sb" else "$sb|$sa"
    }

    private fun frameAt(frames: List<Frame>, index: Int): Frame? =
        frames.getOrNull(index - 1)?.takeIf { it.index == index }
            ?: frames.firstOrNull { it.index == index }
}

private data class Endpoint(val ip: String, val port: Int)

private class TlsSession(
    val client: Endpoint,
    val server: Endpoint,
    var clientRandom: ByteArray? = null,
    var serverRandom: ByteArray? = null,
    var cipherSuite: Int? = null,
    val frameIndices: MutableList<Int> = mutableListOf(),
)

/** 一个 TLS session 对应的双向 decryptor 槽 + 错误信息槽。一个 session 只走
 *  TLS 1.3 一对或 TLS 1.2 一对，另一组为 null。 */
private class SessionDecryptors(
    val tls13Client: Tls13Decryptor? = null,
    val tls13Server: Tls13Decryptor? = null,
    val tls12Client: Tls12Decryptor? = null,
    val tls12Server: Tls12Decryptor? = null,
    val status: String? = null,
)
