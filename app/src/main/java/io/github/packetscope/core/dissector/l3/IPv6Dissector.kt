package io.github.packetscope.core.dissector.l3

import io.github.packetscope.core.dissector.Dissector
import io.github.packetscope.core.dissector.DissectResult
import io.github.packetscope.core.dissector.NextLayer
import io.github.packetscope.core.dissector.NextStep
import io.github.packetscope.core.pcap.ByteReader
import io.github.packetscope.core.pcap.Field
import io.github.packetscope.core.pcap.FieldNames
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols

/**
 * IPv6 头（固定 40 字节）。
 *
 *   |4 ver|8 traffic class|20 flow label|16 payload len|
 *   |8 next header|8 hop limit|128 src|128 dst|
 *
 * v0.2 简化：不展开扩展头（Hop-by-hop / Routing 等），如果 next header 是扩展头
 * 类型直接停在 IPv6 这一层，标记 truncated 提示后续完善。
 */
object IPv6Dissector : Dissector {

    private const val HEADER_SIZE = 40

    override fun dissect(data: ByteArray, offset: Int): DissectResult? {
        if (offset + HEADER_SIZE > data.size) {
            return DissectResult(
                layer = Layer(
                    protocol = Protocols.IPV6,
                    byteRange = offset..(data.size - 1).coerceAtLeast(offset),
                    fields = emptyList(),
                    truncated = true,
                ),
            )
        }

        val verTcFlow = ByteReader.u32Be(data, offset)
        val trafficClass = ((verTcFlow ushr 20) and 0xFF).toInt()
        val flowLabel = (verTcFlow and 0xFFFFF).toInt()
        val payloadLen = ByteReader.u16Be(data, offset + 4)
        val nextHeader = ByteReader.u8(data, offset + 6)
        val hopLimit = ByteReader.u8(data, offset + 7)
        val src = ByteReader.ipv6(data, offset + 8)
        val dst = ByteReader.ipv6(data, offset + 24)

        val fields = listOf(
            Field("Version", "6", offset..offset),
            Field("Traffic class", "0x%02x".format(trafficClass), offset..(offset + 1)),
            Field("Flow label", "0x%05x".format(flowLabel), (offset + 1)..(offset + 3)),
            Field("Payload length", payloadLen.toString(), (offset + 4)..(offset + 5)),
            Field(
                name = "Next header",
                value = "$nextHeader (${protocolName(nextHeader)})",
                byteRange = (offset + 6)..(offset + 6),
            ),
            Field("Hop limit", hopLimit.toString(), (offset + 7)..(offset + 7)),
            Field(FieldNames.SOURCE, src, (offset + 8)..(offset + 23)),
            Field(FieldNames.DESTINATION, dst, (offset + 24)..(offset + 39)),
        )

        val nextDissector = NextLayer.byIpProtocol(nextHeader)

        return DissectResult(
            layer = Layer(
                protocol = Protocols.IPV6,
                byteRange = offset..(offset + HEADER_SIZE - 1),
                fields = fields,
                summary = "$src → $dst",
                truncated = nextDissector == null && nextHeader != 59,  // 59 = No Next Header
            ),
            next = nextDissector?.let { NextStep.Continue(offset + HEADER_SIZE, it) }
                ?: NextStep.Done,
        )
    }

    private fun protocolName(value: Int): String = when (value) {
        0 -> "Hop-by-hop options"
        6 -> "TCP"
        17 -> "UDP"
        43 -> "Routing"
        44 -> "Fragment"
        58 -> "ICMPv6"
        59 -> "No next header"
        60 -> "Destination options"
        else -> "Unknown"
    }
}
