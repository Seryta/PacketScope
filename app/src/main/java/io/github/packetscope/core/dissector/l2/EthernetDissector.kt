package io.github.packetscope.core.dissector.l2

import io.github.packetscope.core.dissector.Dissector
import io.github.packetscope.core.dissector.DissectResult
import io.github.packetscope.core.dissector.NextLayer
import io.github.packetscope.core.dissector.NextStep
import io.github.packetscope.core.pcap.ByteReader
import io.github.packetscope.core.pcap.Field
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols

/**
 * 标准 Ethernet II 帧头（不含 802.1Q VLAN 扩展，v0.2 暂略）。
 *
 *   |  6 dst MAC  |  6 src MAC  |  2 EtherType  | ... payload ... |
 */
object EthernetDissector : Dissector {

    private const val HEADER_SIZE = 14

    override fun dissect(data: ByteArray, offset: Int): DissectResult? {
        if (offset + HEADER_SIZE > data.size) {
            return DissectResult(
                layer = Layer(
                    protocol = Protocols.ETHERNET,
                    byteRange = offset..(data.size - 1).coerceAtLeast(offset),
                    fields = emptyList(),
                    truncated = true,
                ),
            )
        }

        val dstMac = ByteReader.mac(data, offset)
        val srcMac = ByteReader.mac(data, offset + 6)
        val etherType = ByteReader.u16Be(data, offset + 12)

        val fields = listOf(
            Field("Destination MAC", dstMac, offset..(offset + 5)),
            Field("Source MAC", srcMac, (offset + 6)..(offset + 11)),
            Field(
                name = "EtherType",
                value = "0x%04x (%s)".format(etherType, etherTypeName(etherType)),
                byteRange = (offset + 12)..(offset + 13),
            ),
        )

        return DissectResult(
            layer = Layer(
                protocol = Protocols.ETHERNET,
                byteRange = offset..(offset + HEADER_SIZE - 1),
                fields = fields,
                summary = "$srcMac → $dstMac",
            ),
            next = NextLayer.byEtherType(etherType)?.let {
                NextStep.Continue(offset + HEADER_SIZE, it)
            } ?: NextStep.Done,
        )
    }

    private fun etherTypeName(value: Int): String = when (value) {
        0x0800 -> "IPv4"
        0x86DD -> "IPv6"
        0x0806 -> "ARP"
        0x8100 -> "802.1Q VLAN"
        else -> "Unknown"
    }
}
