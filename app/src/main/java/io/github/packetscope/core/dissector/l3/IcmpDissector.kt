package io.github.packetscope.core.dissector.l3

import io.github.packetscope.core.dissector.Dissector
import io.github.packetscope.core.dissector.DissectResult
import io.github.packetscope.core.pcap.ByteReader
import io.github.packetscope.core.pcap.Field
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols

/**
 * ICMP（v4）。v0.2 只解析公共头（type/code/checksum）；具体消息体留给后续。
 */
object IcmpDissector : Dissector {

    override fun dissect(data: ByteArray, offset: Int): DissectResult? {
        if (offset + 4 > data.size) {
            return DissectResult(
                layer = Layer(
                    protocol = Protocols.ICMP,
                    byteRange = offset..(data.size - 1).coerceAtLeast(offset),
                    fields = emptyList(),
                    truncated = true,
                ),
            )
        }

        val type = ByteReader.u8(data, offset)
        val code = ByteReader.u8(data, offset + 1)
        val checksum = ByteReader.u16Be(data, offset + 2)

        return DissectResult(
            layer = Layer(
                protocol = Protocols.ICMP,
                byteRange = offset..(data.size - 1),
                fields = listOf(
                    Field("Type", "$type (${typeName(type)})", offset..offset),
                    Field("Code", code.toString(), (offset + 1)..(offset + 1)),
                    Field("Checksum", "0x%04x".format(checksum), (offset + 2)..(offset + 3)),
                ),
                summary = typeName(type),
            ),
        )
    }

    private fun typeName(value: Int): String = when (value) {
        0 -> "Echo Reply"
        3 -> "Destination Unreachable"
        5 -> "Redirect"
        8 -> "Echo Request"
        11 -> "Time Exceeded"
        else -> "Type $value"
    }
}

/**
 * ICMPv6。结构与 ICMP 类似但 type 编号不同。
 */
object Icmpv6Dissector : Dissector {

    override fun dissect(data: ByteArray, offset: Int): DissectResult? {
        if (offset + 4 > data.size) {
            return DissectResult(
                layer = Layer(
                    protocol = Protocols.ICMPV6,
                    byteRange = offset..(data.size - 1).coerceAtLeast(offset),
                    fields = emptyList(),
                    truncated = true,
                ),
            )
        }

        val type = ByteReader.u8(data, offset)
        val code = ByteReader.u8(data, offset + 1)
        val checksum = ByteReader.u16Be(data, offset + 2)

        return DissectResult(
            layer = Layer(
                protocol = Protocols.ICMPV6,
                byteRange = offset..(data.size - 1),
                fields = listOf(
                    Field("Type", "$type (${typeName(type)})", offset..offset),
                    Field("Code", code.toString(), (offset + 1)..(offset + 1)),
                    Field("Checksum", "0x%04x".format(checksum), (offset + 2)..(offset + 3)),
                ),
                summary = typeName(type),
            ),
        )
    }

    private fun typeName(value: Int): String = when (value) {
        1 -> "Destination Unreachable"
        2 -> "Packet Too Big"
        3 -> "Time Exceeded"
        128 -> "Echo Request"
        129 -> "Echo Reply"
        133 -> "Router Solicitation"
        134 -> "Router Advertisement"
        135 -> "Neighbor Solicitation"
        136 -> "Neighbor Advertisement"
        else -> "Type $value"
    }
}
