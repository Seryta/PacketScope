package io.github.packetscope.core.dissector.l7

import io.github.packetscope.core.dissector.Dissector
import io.github.packetscope.core.dissector.DissectResult
import io.github.packetscope.core.pcap.Field
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols
import java.nio.charset.StandardCharsets

/**
 * 明文 HTTP/1.x。识别请求/响应首行 + headers。
 *
 * 不做 body 解析；TCP 重组尚未实现（v0.8 排期），payload 跨多个 segment 时
 * 只看单 segment 的前若干字节，headers 不完整时返回 truncated=true 的 Layer
 * 并把 summary 标"headers 跨包，未重组"，让用户看到提示而不是"没有 L7"的假象。
 */
object HttpDissector : Dissector {

    private val METHODS = listOf(
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
        "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
    )

    override fun dissect(data: ByteArray, offset: Int): DissectResult? {
        if (offset >= data.size) return null

        val payloadLen = data.size - offset
        // 取一个合理上限避免大 payload 全转字符串
        val sniffLen = minOf(payloadLen, 4096)
        val text = String(data, offset, sniffLen, StandardCharsets.ISO_8859_1)

        val isResponse = text.startsWith("HTTP/")
        val isRequest = METHODS.any { text.startsWith(it) }
        if (!isRequest && !isResponse) return null

        // 找 headers 结束位置（\r\n\r\n 或 \n\n）
        val headersEnd = findHeadersEnd(text).coerceAtMost(sniffLen)
        val headerText = text.substring(0, headersEnd)
        val headerEndOffset = offset + headersEnd

        val lines = headerText.split("\r\n", "\n").filter { it.isNotEmpty() }
        // headers 完全空的边界情况：返回最小 truncated Layer 而非 null，
        // 这样 layer 列表里有提示，用户知道命中了 HTTP 但解析不完整
        val firstLine = lines.firstOrNull() ?: ""
        val firstField = Field(
            name = if (isResponse) "Status line" else "Request line",
            value = firstLine,
            byteRange = offset..(offset + firstLine.length - 1)
                .coerceAtMost(data.size - 1).coerceAtLeast(offset),
        )

        var cursor = offset + firstLine.length + 2  // 跳过 \r\n
        val headerFields = lines.drop(1).map { line ->
            val range = cursor..(cursor + line.length - 1).coerceAtMost(data.size - 1)
            cursor += line.length + 2
            Field(name = line.substringBefore(':', missingDelimiterValue = line),
                value = line.substringAfter(':', missingDelimiterValue = "").trim(),
                byteRange = range)
        }

        // headers 未见结束符即视为跨包截断
        val headersComplete = text.contains("\r\n\r\n") || text.contains("\n\n")
        val truncated = !headersComplete

        val baseSummary = if (isResponse) {
            "HTTP Response: " + firstLine.removePrefix("HTTP/").trim().take(40)
        } else {
            "HTTP Request: " + firstLine.take(60)
        }
        val summary = if (truncated) "$baseSummary  (headers 跨包，未重组)" else baseSummary

        return DissectResult(
            layer = Layer(
                protocol = Protocols.HTTP,
                byteRange = offset..(headerEndOffset - 1).coerceAtMost(data.size - 1).coerceAtLeast(offset),
                fields = listOf(firstField) + headerFields,
                summary = summary,
                truncated = truncated,
            ),
        )
    }

    /** 返回 headers 结束位置（包含分隔符），找不到则返回 text.length */
    private fun findHeadersEnd(text: String): Int {
        val crlfcrlf = text.indexOf("\r\n\r\n")
        if (crlfcrlf >= 0) return crlfcrlf + 4
        val lflf = text.indexOf("\n\n")
        if (lflf >= 0) return lflf + 2
        return text.length
    }
}
