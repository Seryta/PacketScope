package io.github.packetscope.core.dissector.l7

import io.github.packetscope.core.dissector.Dissector
import io.github.packetscope.core.dissector.DissectResult
import io.github.packetscope.core.pcap.ByteReader
import io.github.packetscope.core.pcap.Field
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols

/**
 * QUIC long-header 元信息浅解析（RFC 9000）。
 *
 * v0.4：只看 long header 字段（form/type/version/DCID/SCID/token/length）。
 * Initial 包内的 CRYPTO frame 需要 HKDF 派生 secret 解 header protection +
 * AEAD 解 payload，工程量大放 v0.4.1。
 *
 * Short header 包（1-RTT 数据）需要先看到对应连接的 Initial 才知道 DCID 长度，
 * MVP 暂不识别。
 */
object QuicDissector : Dissector {

    override fun dissect(data: ByteArray, offset: Int): DissectResult? {
        if (offset + 7 > data.size) return null

        val byte0 = ByteReader.u8(data, offset)
        // Long form 要求最高 bit = 1，fixed bit = 1 → byte0 >= 0xC0
        if (byte0 and 0xC0 != 0xC0) return null

        val packetType = (byte0 ushr 4) and 0x03
        val version = ByteReader.u32Be(data, offset + 1)
        // 合理 QUIC version：v1 (0x00000001)、v2 (0x6b3343cf)、draft-2x 等
        if (!isPlausibleVersion(version)) return null

        var cursor = offset + 5
        val dcidLen = ByteReader.u8(data, cursor); cursor += 1
        if (cursor + dcidLen > data.size) return null
        val dcid = data.copyOfRange(cursor, cursor + dcidLen)
        val dcidEnd = cursor + dcidLen - 1
        cursor += dcidLen

        if (cursor >= data.size) return null
        val scidLen = ByteReader.u8(data, cursor); cursor += 1
        if (cursor + scidLen > data.size) return null
        val scid = data.copyOfRange(cursor, cursor + scidLen)
        val scidEnd = cursor + scidLen - 1
        cursor += scidLen

        val typeName = packetTypeName(packetType, version)
        val fields = mutableListOf(
            Field("Header form", "Long (1)", offset..offset),
            Field("Packet type", "$packetType ($typeName)", offset..offset),
            Field("Version", "0x%08x (${versionName(version)})".format(version),
                (offset + 1)..(offset + 4)),
            Field("DCID length", dcidLen.toString(), (offset + 5)..(offset + 5)),
            Field("Destination CID", hex(dcid), (offset + 6)..dcidEnd),
            Field("SCID length", scidLen.toString(), (dcidEnd + 1)..(dcidEnd + 1)),
            Field("Source CID", hex(scid), (dcidEnd + 2)..scidEnd),
        )

        var summary = "QUIC $typeName"

        if (packetType == 0 && cursor < data.size) {
            // Initial: token length (var-int) + token + length (var-int) + ...
            val tokenLenRes = readVarInt(data, cursor) ?: return makeLayer(offset, fields, summary, data.size - 1)
            val tokenLen = tokenLenRes.value.toInt()
            fields += Field(
                name = "Token length",
                value = tokenLen.toString(),
                byteRange = cursor..(cursor + tokenLenRes.bytes - 1),
            )
            cursor += tokenLenRes.bytes
            if (cursor + tokenLen > data.size) return makeLayer(offset, fields, summary, data.size - 1)
            if (tokenLen > 0) {
                fields += Field(
                    name = "Token",
                    value = hex(data.copyOfRange(cursor, cursor + tokenLen)),
                    byteRange = cursor..(cursor + tokenLen - 1),
                )
            }
            cursor += tokenLen

            val pktLenRes = readVarInt(data, cursor) ?: return makeLayer(offset, fields, summary, data.size - 1)
            fields += Field(
                name = "Length",
                value = pktLenRes.value.toString(),
                byteRange = cursor..(cursor + pktLenRes.bytes - 1),
            )
            cursor += pktLenRes.bytes
            // Packet Number + Payload 都被加密，统一作为一个字段标注
            val encEnd = (cursor + pktLenRes.value.toInt() - 1).coerceAtMost(data.size - 1)
            if (cursor <= encEnd) {
                fields += Field(
                    name = "Encrypted payload",
                    value = "${encEnd - cursor + 1} bytes (PN + payload, requires HKDF to decrypt)",
                    byteRange = cursor..encEnd,
                )
            }
            summary = "QUIC Initial v=${versionName(version)} DCID=${hex(dcid).take(16)}…"
        }

        return makeLayer(offset, fields, summary, data.size - 1)
    }

    private fun makeLayer(offset: Int, fields: List<Field>, summary: String, end: Int) = DissectResult(
        layer = Layer(
            protocol = Protocols.QUIC,
            byteRange = offset..end,
            fields = fields,
            summary = summary,
        ),
    )

    private data class VarIntResult(val value: Long, val bytes: Int)

    private fun readVarInt(data: ByteArray, offset: Int): VarIntResult? {
        if (offset >= data.size) return null
        val first = data[offset].toInt() and 0xFF
        val prefix = first ushr 6
        val len = 1 shl prefix  // 1, 2, 4, 8
        if (offset + len > data.size) return null
        var value = (first and 0x3F).toLong()
        for (i in 1 until len) {
            value = (value shl 8) or (data[offset + i].toLong() and 0xFF)
        }
        return VarIntResult(value, len)
    }

    private fun packetTypeName(type: Int, version: Long): String = when (type) {
        0 -> "Initial"
        1 -> "0-RTT"
        2 -> "Handshake"
        3 -> "Retry"
        else -> "Type$type"
    }

    private fun versionName(version: Long): String = when (version) {
        0L -> "Version Negotiation"
        1L -> "v1"
        0x6b3343cfL -> "v2"
        else -> "0x%08x".format(version)
    }

    private fun isPlausibleVersion(version: Long): Boolean {
        // 接受 v1, v2, draft (0xff0000xx)，以及 Version Negotiation (0)
        if (version == 0L || version == 1L) return true
        if (version == 0x6b3343cfL) return true
        if (version ushr 24 == 0xffL) return true  // draft 系列
        return false
    }

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}
