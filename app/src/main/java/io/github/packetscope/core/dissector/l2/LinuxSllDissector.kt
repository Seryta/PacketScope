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
 * Linux cooked capture v1 (DLT_LINUX_SLL = 113)，16 字节定长头。
 * tcpdump 在没有指定具体接口时（如 `-i any`）使用此格式。
 *
 *   | 2 pkt_type | 2 ARPHRD | 2 addr_len | 8 addr | 2 protocol |
 */
object LinuxSllDissector : Dissector {

    private const val HEADER_SIZE = 16

    override fun dissect(data: ByteArray, offset: Int): DissectResult? {
        if (offset + HEADER_SIZE > data.size) {
            return DissectResult(
                layer = Layer(
                    protocol = Protocols.LINUX_SLL_V1,
                    byteRange = offset..(data.size - 1).coerceAtLeast(offset),
                    fields = emptyList(),
                    truncated = true,
                ),
            )
        }

        val pktType = ByteReader.u16Be(data, offset)
        val arphrd = ByteReader.u16Be(data, offset + 2)
        val addrLen = ByteReader.u16Be(data, offset + 4)
        val protocol = ByteReader.u16Be(data, offset + 14)

        val fields = listOf(
            Field("Packet type", pktTypeName(pktType), offset..(offset + 1)),
            Field("Link-layer address type", arphrd.toString(), (offset + 2)..(offset + 3)),
            Field("Link-layer address length", addrLen.toString(), (offset + 4)..(offset + 5)),
            Field(
                name = "Protocol",
                value = "0x%04x".format(protocol),
                byteRange = (offset + 14)..(offset + 15),
            ),
        )

        return DissectResult(
            layer = Layer(
                protocol = Protocols.LINUX_SLL_V1,
                byteRange = offset..(offset + HEADER_SIZE - 1),
                fields = fields,
                summary = pktTypeName(pktType),
            ),
            next = NextLayer.byEtherType(protocol)?.let {
                NextStep.Continue(offset + HEADER_SIZE, it)
            } ?: NextStep.Done,
        )
    }

    private fun pktTypeName(value: Int): String = when (value) {
        0 -> "Unicast (to us)"
        1 -> "Broadcast"
        2 -> "Multicast"
        3 -> "Unicast (to others)"
        4 -> "Outgoing"
        else -> "Unknown ($value)"
    }
}

/**
 * Linux cooked capture v2 (DLT_LINUX_SLL2 = 276)，20 字节定长头，字段顺序与 v1 不同。
 *
 *   | 2 protocol | 2 reserved | 4 ifindex | 2 ARPHRD | 1 pkt_type | 1 addr_len | 8 addr |
 */
object LinuxSll2Dissector : Dissector {

    private const val HEADER_SIZE = 20

    override fun dissect(data: ByteArray, offset: Int): DissectResult? {
        if (offset + HEADER_SIZE > data.size) {
            return DissectResult(
                layer = Layer(
                    protocol = Protocols.LINUX_SLL_V2,
                    byteRange = offset..(data.size - 1).coerceAtLeast(offset),
                    fields = emptyList(),
                    truncated = true,
                ),
            )
        }

        val protocol = ByteReader.u16Be(data, offset)
        val ifIndex = ByteReader.u32Be(data, offset + 4)
        val arphrd = ByteReader.u16Be(data, offset + 8)
        val pktType = ByteReader.u8(data, offset + 10)

        val fields = listOf(
            Field("Protocol", "0x%04x".format(protocol), offset..(offset + 1)),
            Field("Interface index", ifIndex.toString(), (offset + 4)..(offset + 7)),
            Field("Link-layer address type", arphrd.toString(), (offset + 8)..(offset + 9)),
            Field("Packet type", pktType.toString(), (offset + 10)..(offset + 10)),
        )

        return DissectResult(
            layer = Layer(
                protocol = Protocols.LINUX_SLL_V2,
                byteRange = offset..(offset + HEADER_SIZE - 1),
                fields = fields,
            ),
            next = NextLayer.byEtherType(protocol)?.let {
                NextStep.Continue(offset + HEADER_SIZE, it)
            } ?: NextStep.Done,
        )
    }
}
