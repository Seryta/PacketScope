package io.github.packetscope.core.dissector.l7

import io.github.packetscope.core.dissector.Dissector
import io.github.packetscope.core.dissector.DissectResult
import io.github.packetscope.core.pcap.ByteReader
import io.github.packetscope.core.pcap.Field
import io.github.packetscope.core.pcap.FieldNames
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols

/**
 * DNS over UDP（RFC 1035）。
 *
 * MVP：解析 header + 第一个 question + 第一个 answer。
 * Question/Answer 数 > 1 时仍只展示第一个；后续可扩展。
 */
object DnsDissector : Dissector {

    private const val HEADER_SIZE = 12

    override fun dissect(data: ByteArray, offset: Int): DissectResult? {
        if (offset + HEADER_SIZE > data.size) {
            return DissectResult(
                layer = Layer(
                    protocol = Protocols.DNS,
                    byteRange = offset..(data.size - 1).coerceAtLeast(offset),
                    fields = emptyList(),
                    truncated = true,
                ),
            )
        }

        val txId = ByteReader.u16Be(data, offset)
        val flags = ByteReader.u16Be(data, offset + 2)
        val qdCount = ByteReader.u16Be(data, offset + 4)
        val anCount = ByteReader.u16Be(data, offset + 6)
        val nsCount = ByteReader.u16Be(data, offset + 8)
        val arCount = ByteReader.u16Be(data, offset + 10)

        val isResponse = (flags ushr 15) and 1 == 1
        val opcode = (flags ushr 11) and 0x0F
        val rcode = flags and 0x0F

        val headerFields = mutableListOf(
            Field("Transaction ID", "0x%04x".format(txId), offset..(offset + 1)),
            Field("Flags",
                "0x%04x (${if (isResponse) "response" else "query"}, opcode=${opcodeName(opcode)}, rcode=${rcodeName(rcode)})".format(flags),
                (offset + 2)..(offset + 3)),
            Field("Questions", qdCount.toString(), (offset + 4)..(offset + 5)),
            Field("Answer RRs", anCount.toString(), (offset + 6)..(offset + 7)),
            Field("Authority RRs", nsCount.toString(), (offset + 8)..(offset + 9)),
            Field("Additional RRs", arCount.toString(), (offset + 10)..(offset + 11)),
        )

        var cursor = offset + HEADER_SIZE
        var firstQName: String? = null
        var firstQType: Int? = null
        var firstAName: String? = null
        var firstAType: Int? = null
        var firstARData: String? = null

        // 第一个 Question
        if (qdCount > 0 && cursor < data.size) {
            val (name, after) = readName(data, offset, cursor) ?: return truncated(data, offset)
            if (after + 4 > data.size) return truncated(data, offset)
            val qtype = ByteReader.u16Be(data, after)
            val qclass = ByteReader.u16Be(data, after + 2)
            firstQName = name
            firstQType = qtype
            headerFields += Field(
                name = "Query",
                value = "$name  ${typeName(qtype)}  ${classNameOf(qclass)}",
                byteRange = cursor..(after + 3),
                children = listOf(
                    Field(FieldNames.NAME, name, cursor..(after - 1)),
                    Field("Type", "$qtype (${typeName(qtype)})", after..(after + 1)),
                    Field("Class", "$qclass (${classNameOf(qclass)})", (after + 2)..(after + 3)),
                ),
            )
            cursor = after + 4

            // 跳过后续 questions（v0.4 MVP 不展示但要算偏移以解析后续 answer）
            for (i in 1 until qdCount) {
                val (_, qAfter) = readName(data, offset, cursor) ?: return truncated(data, offset)
                if (qAfter + 4 > data.size) return truncated(data, offset)
                cursor = qAfter + 4
            }
        }

        // 第一个 Answer
        if (anCount > 0 && cursor < data.size) {
            val (name, after) = readName(data, offset, cursor) ?: return truncated(data, offset)
            if (after + 10 > data.size) return truncated(data, offset)
            val type = ByteReader.u16Be(data, after)
            val klass = ByteReader.u16Be(data, after + 2)
            val ttl = ByteReader.u32Be(data, after + 4)
            val rdLen = ByteReader.u16Be(data, after + 8)
            val rdataStart = after + 10
            if (rdataStart + rdLen > data.size) return truncated(data, offset)

            val rdataText = formatRdata(data, offset, rdataStart, rdLen, type)
            firstAName = name
            firstAType = type
            firstARData = rdataText

            headerFields += Field(
                name = "Answer",
                value = "$name  ${typeName(type)}  $rdataText  TTL=$ttl",
                byteRange = cursor..(rdataStart + rdLen - 1),
                children = listOf(
                    Field(FieldNames.NAME, name, cursor..(after - 1)),
                    Field("Type", "$type (${typeName(type)})", after..(after + 1)),
                    Field("Class", "$klass (${classNameOf(klass)})", (after + 2)..(after + 3)),
                    Field("TTL", ttl.toString(), (after + 4)..(after + 7)),
                    Field("Data length", rdLen.toString(), (after + 8)..(after + 9)),
                    Field("Data", rdataText, rdataStart..(rdataStart + rdLen - 1)),
                ),
            )
        }

        val summary = when {
            isResponse && firstAName != null ->
                "A: $firstAName → $firstARData"
            isResponse ->
                "Response (rcode=${rcodeName(rcode)})"
            firstQName != null ->
                "Q: $firstQName ${typeName(firstQType ?: 0)}"
            else -> "DNS"
        }

        return DissectResult(
            layer = Layer(
                protocol = Protocols.DNS,
                byteRange = offset..(data.size - 1),
                fields = headerFields,
                summary = summary,
            ),
        )
    }

    private fun truncated(data: ByteArray, offset: Int) = DissectResult(
        layer = Layer(
            protocol = Protocols.DNS,
            byteRange = offset..(data.size - 1).coerceAtLeast(offset),
            fields = emptyList(),
            truncated = true,
        ),
    )

    /**
     * 读 DNS 域名（labels 序列 + 终止 0，可能含 0xC0 压缩指针）。
     * 返回 (name, 下一字段的绝对 offset)；递归时跟随指针但限制深度。
     */
    private fun readName(data: ByteArray, dnsStart: Int, pos: Int): Pair<String, Int>? {
        val labels = mutableListOf<String>()
        var cur = pos
        var jumped = false
        var afterJump = -1
        var depth = 0

        while (cur < data.size) {
            val len = data[cur].toInt() and 0xFF
            when {
                len == 0 -> {
                    val end = if (jumped) afterJump else cur + 1
                    return labels.joinToString(".") to end
                }
                (len and 0xC0) == 0xC0 -> {
                    if (cur + 1 >= data.size) return null
                    if (!jumped) afterJump = cur + 2
                    val ptr = ((len and 0x3F) shl 8) or (data[cur + 1].toInt() and 0xFF)
                    cur = dnsStart + ptr
                    jumped = true
                    if (++depth > MAX_NAME_DEPTH) return null
                }
                (len and 0xC0) == 0 -> {
                    if (cur + 1 + len > data.size) return null
                    labels += String(data, cur + 1, len, Charsets.US_ASCII)
                    cur += 1 + len
                }
                else -> return null  // 0x40/0x80 保留位
            }
        }
        return null
    }

    private fun formatRdata(data: ByteArray, dnsStart: Int, rdataStart: Int, rdLen: Int, type: Int): String {
        return when (type) {
            1 -> if (rdLen == 4) ByteReader.ipv4(data, rdataStart) else "?"
            28 -> if (rdLen == 16) ByteReader.ipv6(data, rdataStart) else "?"
            5, 2, 12 -> readName(data, dnsStart, rdataStart)?.first ?: "?"
            else -> "(${rdLen}B)"
        }
    }

    private fun typeName(type: Int): String = when (type) {
        1 -> "A"
        2 -> "NS"
        5 -> "CNAME"
        6 -> "SOA"
        12 -> "PTR"
        15 -> "MX"
        16 -> "TXT"
        28 -> "AAAA"
        33 -> "SRV"
        65 -> "HTTPS"
        else -> "TYPE$type"
    }

    private fun classNameOf(klass: Int): String = when (klass) {
        1 -> "IN"
        else -> "CLASS$klass"
    }

    private fun opcodeName(opcode: Int): String = when (opcode) {
        0 -> "Query"
        1 -> "IQuery"
        2 -> "Status"
        4 -> "Notify"
        5 -> "Update"
        else -> "Op$opcode"
    }

    private fun rcodeName(rcode: Int): String = when (rcode) {
        0 -> "NoError"
        1 -> "FormErr"
        2 -> "ServFail"
        3 -> "NXDomain"
        5 -> "Refused"
        else -> "R$rcode"
    }

    private const val MAX_NAME_DEPTH = 16
}
