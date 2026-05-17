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
 * TCP 头（变长 20-60 字节，由 data offset 决定）。
 *
 *   |16 src port|16 dst port|32 seq|32 ack|4 data off|3 reserved|9 flags|16 window|
 *   |16 checksum|16 urgent|...options(变长)...|
 */
object TcpDissector : Dissector {

    override fun dissect(data: ByteArray, offset: Int): DissectResult? {
        if (offset + 20 > data.size) return truncated(data, offset)

        val srcPort = ByteReader.u16Be(data, offset)
        val dstPort = ByteReader.u16Be(data, offset + 2)
        val seq = ByteReader.u32Be(data, offset + 4)
        val ack = ByteReader.u32Be(data, offset + 8)
        val dataOffAndFlags = ByteReader.u16Be(data, offset + 12)
        val dataOff = (dataOffAndFlags ushr 12) and 0x0F
        val headerLen = dataOff * 4
        val flags = dataOffAndFlags and 0x01FF
        val window = ByteReader.u16Be(data, offset + 14)
        val checksum = ByteReader.u16Be(data, offset + 16)

        if (headerLen < 20 || offset + headerLen > data.size) return truncated(data, offset)

        val flagsField = Field(
            name = "Flags",
            value = formatFlags(flags),
            byteRange = (offset + 12)..(offset + 13),
            children = listOf(
                bitField("NS",  flags, 8),
                bitField("CWR", flags, 7),
                bitField("ECE", flags, 6),
                bitField("URG", flags, 5),
                bitField("ACK", flags, 4),
                bitField("PSH", flags, 3),
                bitField("RST", flags, 2),
                bitField("SYN", flags, 1),
                bitField("FIN", flags, 0),
            ),
        )

        val fields = listOf(
            Field(FieldNames.SOURCE_PORT, srcPort.toString(), offset..(offset + 1)),
            Field(FieldNames.DESTINATION_PORT, dstPort.toString(), (offset + 2)..(offset + 3)),
            Field("Sequence number", seq.toString(), (offset + 4)..(offset + 7)),
            Field("Acknowledgement number", ack.toString(), (offset + 8)..(offset + 11)),
            Field("Header length", "$headerLen bytes", (offset + 12)..(offset + 12)),
            flagsField,
            Field("Window size", window.toString(), (offset + 14)..(offset + 15)),
            Field("Checksum", "0x%04x".format(checksum), (offset + 16)..(offset + 17)),
        )

        // Wireshark 风格 info：payload 长度 = 整个 packet 剩余字节
        // 注意：可能包含 Ethernet padding，但抓包多数情况下精确
        val payloadLen = (data.size - (offset + headerLen)).coerceAtLeast(0)
        val hasAck = (flags ushr 4) and 1 == 1
        val summaryText = buildString {
            append("$srcPort → $dstPort  ")
            append(formatFlags(flags))
            append(" Seq=$seq")
            if (hasAck) append(" Ack=$ack")
            append(" Win=$window Len=$payloadLen")
        }

        val probed = NextLayer.byTcpPort(srcPort, dstPort, data, offset + headerLen)
        return DissectResult(
            layer = Layer(
                protocol = Protocols.TCP,
                byteRange = offset..(offset + headerLen - 1),
                fields = fields,
                summary = summaryText,
            ),
            next = probed?.toNextStep(offset + headerLen) ?: NextStep.Done,
        )
    }

    private fun bitField(name: String, flags: Int, bit: Int) =
        Field(name, if ((flags ushr bit) and 1 == 1) "1" else "0")

    private fun formatFlags(flags: Int): String {
        val names = listOf(
            "FIN" to 0, "SYN" to 1, "RST" to 2, "PSH" to 3,
            "ACK" to 4, "URG" to 5, "ECE" to 6, "CWR" to 7, "NS" to 8,
        )
        val set = names.filter { (_, b) -> (flags ushr b) and 1 == 1 }.map { it.first }
        return if (set.isEmpty()) "[none]" else "[${set.joinToString(",")}]"
    }

    private fun truncated(data: ByteArray, offset: Int) = DissectResult(
        layer = Layer(
            protocol = Protocols.TCP,
            byteRange = offset..(data.size - 1).coerceAtLeast(offset),
            fields = emptyList(),
            truncated = true,
        ),
    )
}
