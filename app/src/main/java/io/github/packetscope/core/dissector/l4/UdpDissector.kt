package io.github.packetscope.core.dissector.l4

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
 * UDP 头（定长 8 字节）。
 *
 *   |16 src port|16 dst port|16 length|16 checksum|
 */
object UdpDissector : Dissector {

    private const val HEADER_SIZE = 8

    override fun dissect(data: ByteArray, offset: Int): DissectResult? {
        if (offset + HEADER_SIZE > data.size) {
            return DissectResult(
                layer = Layer(
                    protocol = Protocols.UDP,
                    byteRange = offset..(data.size - 1).coerceAtLeast(offset),
                    fields = emptyList(),
                    truncated = true,
                ),
            )
        }

        val srcPort = ByteReader.u16Be(data, offset)
        val dstPort = ByteReader.u16Be(data, offset + 2)
        val length = ByteReader.u16Be(data, offset + 4)
        val checksum = ByteReader.u16Be(data, offset + 6)

        val probed = NextLayer.byUdpPort(srcPort, dstPort, data, offset + HEADER_SIZE)
        return DissectResult(
            layer = Layer(
                protocol = Protocols.UDP,
                byteRange = offset..(offset + HEADER_SIZE - 1),
                fields = listOf(
                    Field(FieldNames.SOURCE_PORT, srcPort.toString(), offset..(offset + 1)),
                    Field(FieldNames.DESTINATION_PORT, dstPort.toString(), (offset + 2)..(offset + 3)),
                    Field("Length", length.toString(), (offset + 4)..(offset + 5)),
                    Field("Checksum", "0x%04x".format(checksum), (offset + 6)..(offset + 7)),
                ),
                summary = "$srcPort → $dstPort len=$length",
            ),
            next = probed?.toNextStep(offset + HEADER_SIZE) ?: NextStep.Done,
        )
    }
}
