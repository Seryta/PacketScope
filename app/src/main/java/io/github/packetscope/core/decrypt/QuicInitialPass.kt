package io.github.packetscope.core.decrypt

import io.github.packetscope.core.pcap.Field
import io.github.packetscope.core.pcap.FieldNames
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols

/**
 * QUIC Initial 解密 pass：扫所有 QUIC layer，对 v1 Initial 包用 RFC 9001 §5.2
 * 派生 initial keys 解出 CRYPTO frame 内的 ClientHello / ServerHello。
 *
 * **不依赖 keylog**——Initial keys 完全由 packet 内的 Destination CID 派生。
 *
 * 会话方向判定：按 UDP 5-tuple 聚类，第一个 QUIC Initial 包的 src 端视作 client，
 * 后续包根据 src 是否匹配 client 切换 decryptor；同一会话双向都用同一组 Initial
 * keys（来自 client 第一个 Initial 的 DCID）。
 */
object QuicInitialPass {

    fun process(frames: List<Frame>): List<Frame> {
        val sessions = buildSessions(frames)
        if (sessions.isEmpty()) return frames
        val replacements = mutableMapOf<Int, Frame>()
        for (session in sessions.values) processSession(frames, session, replacements)
        if (replacements.isEmpty()) return frames
        return frames.map { replacements[it.index] ?: it }
    }

    private fun processSession(
        frames: List<Frame>, session: QuicSession, out: MutableMap<Int, Frame>,
    ) {
        val (cDec, sDec) = QuicInitialDecryptor.fromDcid(session.dcid)
        for (idx in session.frameIndices.sorted()) {
            val newFrame = decryptFrame(frames, idx, session, cDec, sDec) ?: continue
            out[newFrame.index] = newFrame
        }
    }

    /** 用 runCatching + checkNotNull 把 5~7 个边界 null 校验合到一条路径，
     *  让 detekt ReturnCount 满意；失败时统一 getOrNull() → null */
    private fun decryptFrame(
        frames: List<Frame>, idx: Int, session: QuicSession,
        cDec: QuicInitialDecryptor, sDec: QuicInitialDecryptor,
    ): Frame? = runCatching {
        val frame = checkNotNull(frameAt(frames, idx))
        val quic = checkNotNull(frame.layers.firstOrNull { it.protocol == Protocols.QUIC })
        val info = checkNotNull(parseQuicInitialOffsets(frame, quic))
        val src = checkNotNull(udpEndpoints(frame)).first
        val dec = if (src == session.clientSrc) cDec else sDec
        val res = checkNotNull(dec.decrypt(info.packetBytes, info.pnOffset, info.totalLen))
        val extras = describeDecrypted(res)
        check(extras.isNotEmpty())
        val newQuic = quic.copy(fields = quic.fields + extras)
        frame.copy(layers = frame.layers.map { if (it === quic) newQuic else it })
    }.getOrNull()

    /** 按 4-tuple 聚类，记录每个会话第一个 Initial 的 DCID + client src */
    private fun buildSessions(frames: List<Frame>): Map<String, QuicSession> {
        val sessions = mutableMapOf<String, QuicSession>()
        frames.forEach { tryAddToSession(it, sessions) }
        return sessions
    }

    private fun tryAddToSession(frame: Frame, sessions: MutableMap<String, QuicSession>) {
        runCatching {
            val quic = checkNotNull(frame.layers.firstOrNull { it.protocol == Protocols.QUIC })
            val info = checkNotNull(parseQuicInitialOffsets(frame, quic))
            val (src, dst) = checkNotNull(udpEndpoints(frame))
            val key = sessionKey(src, dst)
            val s = sessions.getOrPut(key) { QuicSession(clientSrc = src, dcid = info.dcid) }
            s.frameIndices.add(frame.index)
        }
    }

    /**
     * 从 [quic] layer 重新走 QUIC long header 解析，得 packetBytes 切片 + packet
     * number 起始 offset + Length 字段值。仅识别 v1 Initial。
     *
     * 用 runCatching 一把吞掉所有边界异常 / null 校验失败，简化数十个 ?: return。
     */
    private fun parseQuicInitialOffsets(frame: Frame, quic: Layer): QuicPacketInfo? =
        // tryParseInitial 内部用 ByteArray + readVarInt 局部 helper；为不展开整条 QUIC
        // 解析链到 FrameBytes，这里 asByteArray() 一次性桥接。HeapBytes 零拷贝；
        // Phase 2 MmapBytes 路径会触发整帧 copy，QUIC Initial 仅在握手包出现，频率低。
        // 若 Phase 5 真机数据显示是热点再单独转换（LAZY-006 范围）。
        runCatching { tryParseInitial(frame.data.asByteArray(), quic.byteRange.first) }.getOrNull()

    private fun tryParseInitial(data: ByteArray, start: Int): QuicPacketInfo? {
        require(start + 7 <= data.size)
        val byte0 = data[start].toInt() and 0xFF
        require(byte0 and 0xC0 == 0xC0)
        require((byte0 ushr 4) and 0x03 == 0)
        require(readU32(data, start + 1) == 1L)  // QUIC v1 only
        var c = start + 5
        val dcidLen = data[c].toInt() and 0xFF; c += 1
        require(c + dcidLen <= data.size)
        val dcid = data.copyOfRange(c, c + dcidLen); c += dcidLen
        val scidLen = data[c].toInt() and 0xFF; c += 1
        require(c + scidLen <= data.size); c += scidLen
        val tokenLen = checkNotNull(readVarInt(data, c)); c += tokenLen.bytes
        require(c + tokenLen.value <= data.size); c += tokenLen.value.toInt()
        val pktLen = checkNotNull(readVarInt(data, c)); c += pktLen.bytes
        val pnOffsetAbs = c
        val totalLen = pktLen.value.toInt()
        require(pnOffsetAbs + totalLen <= data.size)
        val packetBytes = data.copyOfRange(start, pnOffsetAbs + totalLen)
        return QuicPacketInfo(packetBytes, pnOffsetAbs - start, totalLen, dcid)
    }

    private fun describeDecrypted(res: DecryptedInitial): List<Field> = buildList {
        add(Field("Initial decryption", "✓ pn=${res.packetNumber} (${res.plaintext.size}B plaintext)"))
        add(Field("Decrypted (hex)", res.plaintext.toHexLower()))
        parseCryptoFrames(res.plaintext, this)
    }

    private fun parseCryptoFrames(pt: ByteArray, out: MutableList<Field>) {
        var off = 0
        while (off < pt.size) {
            val ft = pt[off].toInt() and 0xFF
            if (ft == 0x00 || ft == 0x01) { off++; continue }  // PADDING / PING
            if (ft != 0x06) return                              // 不识别的 frame type
            off = consumeCrypto(pt, off, out) ?: return
        }
    }

    /** 消费一个 CRYPTO frame (type 0x06)，返回下一个 frame 起始 offset，
     *  失败返回 null 让 caller 停止解析。 */
    private fun consumeCrypto(pt: ByteArray, off: Int, out: MutableList<Field>): Int? {
        val offRes = readVarInt(pt, off + 1) ?: return null
        val lenRes = readVarInt(pt, off + 1 + offRes.bytes) ?: return null
        val cs = off + 1 + offRes.bytes + lenRes.bytes
        val ce = cs + lenRes.value.toInt()
        if (ce > pt.size) return null
        val cryptoData = pt.copyOfRange(cs, ce)
        out += Field("CRYPTO frame", "offset=${offRes.value} length=${lenRes.value}")
        out += Field("CRYPTO data (hex)", cryptoData.toHexLower())
        if (cryptoData.isNotEmpty()) {
            val hsType = cryptoData[0].toInt() and 0xFF
            out += Field("Handshake", "$hsType (${tlsHandshakeName(hsType)})")
        }
        return ce
    }

    private fun tlsHandshakeName(t: Int) = when (t) {
        1 -> "Client Hello"
        2 -> "Server Hello"
        4 -> "New Session Ticket"
        8 -> "Encrypted Extensions"
        11 -> "Certificate"
        else -> "Type$t"
    }

    private fun udpEndpoints(frame: Frame): Pair<UdpEndpoint, UdpEndpoint>? = runCatching {
        val ip = frame.layers.first {
            it.protocol == Protocols.IPV4 || it.protocol == Protocols.IPV6
        }
        val udp = frame.layers.first { it.protocol == Protocols.UDP }
        val src = ip.fields.first { it.name == FieldNames.SOURCE }.value
        val dst = ip.fields.first { it.name == FieldNames.DESTINATION }.value
        val sport = udp.fields.first { it.name == FieldNames.SOURCE_PORT }.value.toInt()
        val dport = udp.fields.first { it.name == FieldNames.DESTINATION_PORT }.value.toInt()
        UdpEndpoint(src, sport) to UdpEndpoint(dst, dport)
    }.getOrNull()

    private fun sessionKey(a: UdpEndpoint, b: UdpEndpoint): String {
        val sa = "${a.ip}:${a.port}"
        val sb = "${b.ip}:${b.port}"
        return if (sa < sb) "$sa|$sb" else "$sb|$sa"
    }

    private fun frameAt(frames: List<Frame>, index: Int): Frame? =
        frames.getOrNull(index - 1)?.takeIf { it.index == index }
            ?: frames.firstOrNull { it.index == index }

    private fun readU32(data: ByteArray, off: Int): Long {
        return ((data[off].toLong() and 0xFF) shl 24) or
            ((data[off + 1].toLong() and 0xFF) shl 16) or
            ((data[off + 2].toLong() and 0xFF) shl 8) or
            (data[off + 3].toLong() and 0xFF)
    }

    internal class VarIntResult(val value: Long, val bytes: Int)

    private fun readVarInt(data: ByteArray, offset: Int): VarIntResult? {
        if (offset >= data.size) return null
        val first = data[offset].toInt() and 0xFF
        val prefix = first ushr 6
        val len = 1 shl prefix
        if (offset + len > data.size) return null
        var value = (first and 0x3F).toLong()
        for (i in 1 until len) {
            value = (value shl 8) or (data[offset + i].toLong() and 0xFF)
        }
        return VarIntResult(value, len)
    }
}

private data class UdpEndpoint(val ip: String, val port: Int)

private class QuicSession(
    val clientSrc: UdpEndpoint,
    val dcid: ByteArray,
    val frameIndices: MutableList<Int> = mutableListOf(),
)

private class QuicPacketInfo(
    val packetBytes: ByteArray,
    /** 在 [packetBytes] 内的 packet number 起始 offset */
    val pnOffset: Int,
    /** QUIC "Length" 字段值：pn + payload + 16 字节 tag */
    val totalLen: Int,
    val dcid: ByteArray,
)
