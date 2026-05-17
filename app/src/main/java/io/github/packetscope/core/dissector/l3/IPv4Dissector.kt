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
 * IPv4 头（变长 20-60 字节）。
 *
 *   |4 ver|4 IHL|8 DSCP/ECN|16 total len|16 id|3 flags|13 frag off|
 *   |8 TTL|8 protocol|16 hdr checksum|32 src ip|32 dst ip|...options(变长)...|
 */
object IPv4Dissector : Dissector {

    override fun dissect(data: ByteArray, offset: Int): DissectResult? {
        if (offset + 20 > data.size) {
            return truncated(data, offset)
        }

        val verIhl = ByteReader.u8(data, offset)
        val ihl = verIhl and 0x0F
        val headerLen = ihl * 4

        if (headerLen < 20 || offset + headerLen > data.size) {
            return truncated(data, offset)
        }

        val totalLen = ByteReader.u16Be(data, offset + 2)
        val flagsAndFrag = ByteReader.u16Be(data, offset + 6)
        val ttl = ByteReader.u8(data, offset + 8)
        val protocol = ByteReader.u8(data, offset + 9)
        val srcIp = ByteReader.ipv4(data, offset + 12)
        val dstIp = ByteReader.ipv4(data, offset + 16)

        val flagsField = Field(
            name = "Flags",
            value = "0x%x".format(flagsAndFrag ushr 13),
            byteRange = (offset + 6)..(offset + 6),
            children = listOf(
                Field("Don't fragment", ((flagsAndFrag ushr 14) and 1 == 1).toString()),
                Field("More fragments", ((flagsAndFrag ushr 13) and 1 == 1).toString()),
            ),
        )

        val fields = listOf(
            Field("Version", "4", offset..offset),
            Field("Header length", "$headerLen bytes (IHL=$ihl)", offset..offset),
            Field("Total length", totalLen.toString(), (offset + 2)..(offset + 3)),
            Field("Identification", "0x%04x".format(ByteReader.u16Be(data, offset + 4)),
                (offset + 4)..(offset + 5)),
            flagsField,
            Field("Fragment offset", (flagsAndFrag and 0x1FFF).toString(),
                (offset + 6)..(offset + 7)),
            Field("TTL", ttl.toString(), (offset + 8)..(offset + 8)),
            Field(
                name = "Protocol",
                value = "$protocol (${protocolName(protocol)})",
                byteRange = (offset + 9)..(offset + 9),
            ),
            Field("Header checksum", "0x%04x".format(ByteReader.u16Be(data, offset + 10)),
                (offset + 10)..(offset + 11)),
            Field(FieldNames.SOURCE, srcIp, (offset + 12)..(offset + 15)),
            Field(FieldNames.DESTINATION, dstIp, (offset + 16)..(offset + 19)),
        )

        return DissectResult(
            layer = Layer(
                protocol = Protocols.IPV4,
                byteRange = offset..(offset + headerLen - 1),
                fields = fields,
                summary = "$srcIp → $dstIp",
            ),
            next = NextLayer.byIpProtocol(protocol)?.let {
                NextStep.Continue(offset + headerLen, it)
            } ?: NextStep.Done,
        )
    }

    private fun truncated(data: ByteArray, offset: Int) = DissectResult(
        layer = Layer(
            protocol = Protocols.IPV4,
            byteRange = offset..(data.size - 1).coerceAtLeast(offset),
            fields = emptyList(),
            truncated = true,
        ),
    )

    private fun protocolName(value: Int): String = when (value) {
        1 -> "ICMP"
        6 -> "TCP"
        17 -> "UDP"
        47 -> "GRE"
        50 -> "ESP"
        58 -> "ICMPv6"
        else -> "Unknown"
    }
}
