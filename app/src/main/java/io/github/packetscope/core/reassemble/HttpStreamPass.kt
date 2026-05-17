package io.github.packetscope.core.reassemble

import io.github.packetscope.core.pcap.Field
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPInputStream
import java.util.zip.InflaterInputStream

/**
 * 跨 segment HTTP body 解析 pass：用 [TcpReassembler] 把 TCP stream 拼起来，
 * 在拼接后的 byte stream 上完整解 HTTP/1.x request / response（含 body）。
 *
 * 支持：
 * - Content-Length 显式长度
 * - Transfer-Encoding: chunked
 * - Content-Encoding: gzip / deflate → 解压成明文
 *
 * 解出的 body 元信息（长度 / encoding / 跨帧 / 解压结果预览）作为新 Field 挂到
 * **message 起始字节所在 frame** 的 HTTP layer 上。完整 body bytes 不直接塞回
 * frame.data（避免重复）；用户走 Follow Stream 看完整 stream。
 */
object HttpStreamPass {

    fun process(frames: List<Frame>): List<Frame> {
        val streams = TcpReassembler.assemble(frames)
        if (streams.isEmpty()) return frames
        val extras = mutableMapOf<Int, MutableList<Field>>()
        for (stream in streams.values) {
            scanFlow(stream.clientToServer, extras)
            scanFlow(stream.serverToClient, extras)
        }
        if (extras.isEmpty()) return frames
        return frames.map { f -> extras[f.index]?.let { applyHttpExtras(f, it) } ?: f }
    }

    /** 把要追加的 Field 列表挂到 frame.layers 内的 HTTP layer 上 */
    private fun applyHttpExtras(frame: Frame, fields: List<Field>): Frame {
        val http = frame.layers.firstOrNull { it.protocol == Protocols.HTTP } ?: return frame
        val newHttp = http.copy(fields = http.fields + fields)
        return frame.copy(layers = frame.layers.map { if (it === http) newHttp else it })
    }

    /** 扫单方向 stream，找出所有 HTTP message + 描述它们 */
    private fun scanFlow(flow: ReassembledFlow, out: MutableMap<Int, MutableList<Field>>) {
        val data = flow.data
        var cursor = 0
        var safety = 0
        while (cursor < data.size && safety++ < MAX_MESSAGES) {
            val start = cursor
            val msg = parseMessage(data, cursor) ?: return
            val anchor = chunkAt(flow.chunks, cursor)?.frameIndex ?: return
            out.getOrPut(anchor) { mutableListOf() } += describeMessage(msg, flow.chunks)
            cursor = msg.endOffset
            // 死循环防御：本轮 cursor 未推进（message 长度为 0）就停。原来的
            // `msg.endOffset <= cursor - msg.bodyLength` 因 cursor 已等于
            // msg.endOffset，化简为 `bodyLength <= 0` —— 把 204 No Content /
            // HEAD response / Content-Length: 0 当死循环结束 keep-alive 流，
            // 后续 message 全吞（review v0.6-round7 F-003）
            if (cursor <= start) return
        }
    }

    private fun parseMessage(data: ByteArray, offset: Int): HttpMessage? = runCatching {
        val headerEnd = checkNotNull(findCrlfCrlf(data, offset))
        val headerText = String(data, offset, headerEnd - offset, Charsets.ISO_8859_1)
        val lines = headerText.split("\r\n").filter { it.isNotEmpty() }
        val firstLine = checkNotNull(lines.firstOrNull())
        val headers = parseHeaders(lines.drop(1))
        val bodyStart = headerEnd
        val cl = headers.firstOrNull { it.first.equals("Content-Length", ignoreCase = true) }
            ?.second?.toIntOrNull()
        val te = headers.firstOrNull { it.first.equals("Transfer-Encoding", ignoreCase = true) }
            ?.second?.lowercase()
        val ce = headers.firstOrNull { it.first.equals("Content-Encoding", ignoreCase = true) }
            ?.second?.lowercase()

        val (bodyRaw, bodyEnd) = when {
            cl != null -> readContentLengthBody(data, bodyStart, cl)
            te == "chunked" -> readChunkedBody(data, bodyStart)
            else -> ByteArray(0) to bodyStart  // 无长度声明，跳过 body 解析
        }
        val bodyDecoded = decompressBody(bodyRaw, ce) ?: bodyRaw
        HttpMessage(
            firstLine = firstLine,
            headers = headers,
            startOffset = offset,
            bodyStart = bodyStart,
            body = HttpBodyInfo(
                rawLength = bodyRaw.size,
                decodedLength = bodyDecoded.size,
                decoded = bodyDecoded,
                contentEncoding = ce,
                transferEncoding = te,
            ),
            endOffset = bodyEnd,
        )
    }.getOrNull()

    private fun parseHeaders(lines: List<String>): List<Pair<String, String>> = lines.mapNotNull {
        val sep = it.indexOf(':')
        if (sep < 0) null else it.substring(0, sep).trim() to it.substring(sep + 1).trim()
    }

    private fun readContentLengthBody(
        data: ByteArray, start: Int, length: Int,
    ): Pair<ByteArray, Int> {
        val safeLen = length.coerceAtMost((data.size - start).coerceAtLeast(0))
        return data.copyOfRange(start, start + safeLen) to (start + safeLen)
    }

    /** Transfer-Encoding: chunked 解码，返回 (decoded body, 末尾 offset) 或 null */
    private fun readChunkedBody(data: ByteArray, start: Int): Pair<ByteArray, Int> {
        val out = ByteArrayOutputStream()
        var c = start
        var safety = 0
        while (c < data.size && safety++ < MAX_CHUNKS) {
            val eol = findCrlf(data, c) ?: return out.toByteArray() to c
            val sizeHex = String(data, c, eol - c, Charsets.ISO_8859_1)
                .substringBefore(';').trim()
            val size = sizeHex.toIntOrNull(16) ?: return out.toByteArray() to c
            c = eol + 2  // past size-line CRLF
            if (size == 0) {
                // last-chunk: 跳过 trailer 直到 CRLF CRLF
                val tEnd = findCrlfCrlf(data, c - 2) ?: c
                return out.toByteArray() to tEnd
            }
            if (c + size > data.size) return out.toByteArray() to c
            out.write(data, c, size)
            c += size + 2  // skip chunk + trailing CRLF
        }
        return out.toByteArray() to c
    }

    /** gzip / deflate 解压；失败返回 null（上层用原 body） */
    private fun decompressBody(body: ByteArray, encoding: String?): ByteArray? {
        if (body.isEmpty() || encoding == null) return null
        return runCatching {
            when (encoding) {
                "gzip" -> GZIPInputStream(body.inputStream()).use { it.readBytes() }
                "deflate" -> InflaterInputStream(body.inputStream()).use { it.readBytes() }
                else -> null
            }
        }.getOrNull()
    }

    private fun describeMessage(msg: HttpMessage, chunks: List<Chunk>): List<Field> {
        val crossFrames = chunks.count { c ->
            c.dataOffset + c.length > msg.startOffset && c.dataOffset < msg.endOffset
        }
        val decoded = msg.bodyDecoded  // local 取一次，避免 custom getter smart-cast 报错
        val ce = msg.contentEncoding
        val encInfo = when {
            ce != null && decoded != null -> "$ce → ${msg.bodyLength}B decoded"
            ce != null -> "$ce (decompress failed)"
            msg.transferEncoding == "chunked" -> "chunked → ${msg.bodyRawLength}B"
            else -> "${msg.bodyRawLength}B"
        }
        return buildList {
            add(Field("Body", "$encInfo across $crossFrames frame(s)"))
            if (decoded != null && decoded.isNotEmpty()) {
                add(Field("Body (preview)", previewText(decoded)))
            }
        }
    }

    private fun previewText(data: ByteArray): String {
        val sample = data.copyOfRange(0, minOf(data.size, BODY_PREVIEW_BYTES))
        val printable = sample.count { isPrintableByte(it.toInt() and 0xFF) }
        return if (printable * 5 >= sample.size * 4) {
            String(sample, Charsets.UTF_8).take(BODY_PREVIEW_BYTES)
        } else {
            sample.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        }
    }

    private fun isPrintableByte(v: Int): Boolean = v in 0x20..0x7E || v in PRINTABLE_CTRL

    /** 可打印控制字符：\t \n \r */
    private val PRINTABLE_CTRL = setOf(0x09, 0x0A, 0x0D)

    private fun matchCrlf(data: ByteArray, i: Int): Boolean {
        if (i + 1 >= data.size) return false
        return data[i] == 0x0D.toByte() && data[i + 1] == 0x0A.toByte()
    }

    private fun findCrlfCrlf(data: ByteArray, from: Int): Int? {
        var i = from
        while (i + 3 < data.size) {
            if (matchCrlf(data, i) && matchCrlf(data, i + 2)) return i + 4
            i++
        }
        return null
    }

    private fun findCrlf(data: ByteArray, from: Int): Int? {
        var i = from
        while (i + 1 < data.size) {
            if (matchCrlf(data, i)) return i
            i++
        }
        return null
    }

    private fun chunkAt(chunks: List<Chunk>, offset: Int): Chunk? =
        chunks.firstOrNull { offset in it.dataOffset until (it.dataOffset + it.length) }

    private const val MAX_MESSAGES = 1000     // 每方向最多解析的 message 数
    private const val MAX_CHUNKS = 10_000     // chunked body 最多块数
    private const val BODY_PREVIEW_BYTES = 1024
}

private class HttpMessage(
    val firstLine: String,
    val headers: List<Pair<String, String>>,
    val startOffset: Int,
    val bodyStart: Int,
    val body: HttpBodyInfo,
    val endOffset: Int,
) {
    val bodyLength: Int get() = body.decodedLength
    val bodyRawLength: Int get() = body.rawLength
    val bodyDecoded: ByteArray? get() = body.decoded
    val contentEncoding: String? get() = body.contentEncoding
    val transferEncoding: String? get() = body.transferEncoding
}

private class HttpBodyInfo(
    /** body 在 wire 上的字节数（chunked 解码前 / Content-Length 值） */
    val rawLength: Int,
    /** 解压解码后的 body 字节数 */
    val decodedLength: Int,
    /** 解压后的 body bytes；解压失败 / 未压缩时直接是 raw body */
    val decoded: ByteArray?,
    val contentEncoding: String?,
    val transferEncoding: String?,
)
