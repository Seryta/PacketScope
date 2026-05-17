package io.github.packetscope.core.dissector.l7

import io.github.packetscope.core.dissector.Dissector
import io.github.packetscope.core.dissector.DissectResult
import io.github.packetscope.core.pcap.ByteReader
import io.github.packetscope.core.pcap.Field
import io.github.packetscope.core.pcap.FieldNames
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols

/**
 * TLS record layer + handshake 层（ClientHello / ServerHello 浅解析）。
 *
 * 不做密钥派生、解密；后续要消费 PCAPdroid 的 SSLKEYLOGFILE 再补。
 */
object TlsDissector : Dissector {

    override fun dissect(data: ByteArray, offset: Int): DissectResult? {
        if (offset + 5 > data.size) return null

        val recordType = ByteReader.u8(data, offset)
        // 防误命中：record type 只可能是 20/21/22/23（v1.0 起）
        if (recordType !in 20..23) return null

        val version = ByteReader.u16Be(data, offset + 1)
        val recordLen = ByteReader.u16Be(data, offset + 3)

        // 防误命中：合理 TLS version 应该在已知集合
        if (version !in setOf(0x0300, 0x0301, 0x0302, 0x0303, 0x0304)) return null

        val recordEnd = offset + 5 + recordLen
        val truncated = recordEnd > data.size

        val recordFields = mutableListOf(
            Field("Content type", "$recordType (${recordTypeName(recordType)})", offset..offset),
            Field("Version", versionName(version), (offset + 1)..(offset + 2)),
            Field("Length", recordLen.toString(), (offset + 3)..(offset + 4)),
        )

        var summary = "TLS ${recordTypeName(recordType)}"

        if (recordType == 22 && offset + 5 + 4 <= data.size) {
            // Handshake
            val hsStart = offset + 5
            val hsType = ByteReader.u8(data, hsStart)
            val hsLen = ((data[hsStart + 1].toInt() and 0xFF) shl 16) or
                ((data[hsStart + 2].toInt() and 0xFF) shl 8) or
                (data[hsStart + 3].toInt() and 0xFF)

            val hsName = handshakeName(hsType)
            val hsChildren = mutableListOf(
                Field("Handshake type", "$hsType ($hsName)", hsStart..hsStart),
                Field("Length", hsLen.toString(), (hsStart + 1)..(hsStart + 3)),
            )

            // ClientHello → 提取 random + 尝试提取 SNI
            if (hsType == 1) {
                val randomStart = hsStart + 4 + 2
                if (randomStart + 32 <= data.size) {
                    val randomHex = data.copyOfRange(randomStart, randomStart + 32).toHex()
                    hsChildren += Field("Client random", randomHex,
                        randomStart..(randomStart + 31))
                }
                val sni = extractSni(data, hsStart + 4, hsLen)
                if (sni != null) {
                    hsChildren += Field(FieldNames.SERVER_NAME_INDICATION, sni)
                    summary = "TLS Client Hello (SNI=$sni)"
                } else {
                    summary = "TLS Client Hello"
                }
            } else if (hsType == 2) {
                // ServerHello — server_random 给 TLS 1.2 PRF 派生 key_block 用
                val randomStart = hsStart + 4 + 2
                if (randomStart + 32 <= data.size) {
                    val randomHex = data.copyOfRange(randomStart, randomStart + 32).toHex()
                    hsChildren += Field("Server random", randomHex,
                        randomStart..(randomStart + 31))
                }
                // cipher_suite 在 random(32) + session_id 之后
                val cipher = extractServerCipherSuite(data, hsStart + 4, hsLen)
                if (cipher != null) {
                    hsChildren += Field("Cipher suite",
                        "0x%04x (${cipherSuiteName(cipher)})".format(cipher))
                }
                summary = "TLS Server Hello"
            } else {
                summary = "TLS Handshake: $hsName"
            }

            recordFields += Field(
                name = FieldNames.HANDSHAKE,
                value = hsName,
                byteRange = hsStart..(hsStart + 3 + hsLen).coerceAtMost(data.size - 1),
                children = hsChildren,
            )
        }

        return DissectResult(
            layer = Layer(
                protocol = Protocols.TLS,
                byteRange = offset..(recordEnd - 1).coerceAtMost(data.size - 1),
                fields = recordFields,
                summary = summary,
                truncated = truncated,
            ),
        )
    }

    /** 在 ClientHello body 里遍历 extensions 找 server_name(0)，返回第一个 hostname */
    private fun extractSni(data: ByteArray, bodyStart: Int, bodyLen: Int): String? {
        val bodyEnd = (bodyStart + bodyLen).coerceAtMost(data.size)
        // 跳过 ClientHello 固定前缀：version(2) + random(32) = 34
        var c = bodyStart + 34
        if (c + 1 > bodyEnd) return null
        val sidLen = ByteReader.u8(data, c); c += 1 + sidLen
        if (c + 2 > bodyEnd) return null
        val csLen = ByteReader.u16Be(data, c); c += 2 + csLen
        if (c + 1 > bodyEnd) return null
        val cmLen = ByteReader.u8(data, c); c += 1 + cmLen
        if (c + 2 > bodyEnd) return null
        val extLen = ByteReader.u16Be(data, c); c += 2
        val extEnd = (c + extLen).coerceAtMost(bodyEnd)

        while (c + 4 <= extEnd) {
            val extType = ByteReader.u16Be(data, c)
            val len = ByteReader.u16Be(data, c + 2)
            val dataStart = c + 4
            if (dataStart + len > extEnd) return null
            if (extType == 0 && len >= 5) {
                // server_name_list: list_len(2) + name_type(1) + name_len(2) + name
                val listLen = ByteReader.u16Be(data, dataStart)
                if (listLen < 3 || dataStart + 2 + listLen > dataStart + len) return null
                val nameType = ByteReader.u8(data, dataStart + 2)
                val nameLen = ByteReader.u16Be(data, dataStart + 3)
                if (nameType == 0 && dataStart + 5 + nameLen <= dataStart + len) {
                    return String(data, dataStart + 5, nameLen, Charsets.US_ASCII)
                }
            }
            c = dataStart + len
        }
        return null
    }

    private fun recordTypeName(type: Int) = when (type) {
        20 -> "Change Cipher Spec"
        21 -> "Alert"
        22 -> "Handshake"
        23 -> "Application Data"
        else -> "Type$type"
    }

    private fun versionName(version: Int) = when (version) {
        0x0300 -> "SSL 3.0 (0x0300)"
        0x0301 -> "TLS 1.0 (0x0301)"
        0x0302 -> "TLS 1.1 (0x0302)"
        0x0303 -> "TLS 1.2 (0x0303)"
        0x0304 -> "TLS 1.3 (0x0304)"
        else -> "0x%04x".format(version)
    }

    /** 在 ServerHello body 里读出 server 选定的 cipher_suite */
    private fun extractServerCipherSuite(data: ByteArray, bodyStart: Int, bodyLen: Int): Int? {
        val bodyEnd = (bodyStart + bodyLen).coerceAtMost(data.size)
        // version(2) + random(32) + session_id_len(1) + session_id
        var c = bodyStart + 34
        if (c >= bodyEnd) return null
        val sidLen = ByteReader.u8(data, c); c += 1 + sidLen
        if (c + 2 > bodyEnd) return null
        return ByteReader.u16Be(data, c)
    }

    private fun cipherSuiteName(value: Int): String = when (value) {
        0x1301 -> "TLS_AES_128_GCM_SHA256"
        0x1302 -> "TLS_AES_256_GCM_SHA384"
        0x1303 -> "TLS_CHACHA20_POLY1305_SHA256"
        0xC02F -> "TLS_ECDHE_RSA_AES_128_GCM_SHA256"
        0xC030 -> "TLS_ECDHE_RSA_AES_256_GCM_SHA384"
        0xC02B -> "TLS_ECDHE_ECDSA_AES_128_GCM_SHA256"
        0xC02C -> "TLS_ECDHE_ECDSA_AES_256_GCM_SHA384"
        else -> "Unknown"
    }

    private fun ByteArray.toHex(): String = buildString(size * 2) {
        for (b in this@toHex) {
            val v = b.toInt() and 0xFF
            append(HEX[v ushr 4]); append(HEX[v and 0x0F])
        }
    }

    private val HEX = "0123456789abcdef".toCharArray()

    private fun handshakeName(t: Int) = when (t) {
        1 -> "Client Hello"
        2 -> "Server Hello"
        4 -> "New Session Ticket"
        8 -> "Encrypted Extensions"
        11 -> "Certificate"
        12 -> "Server Key Exchange"
        13 -> "Certificate Request"
        14 -> "Server Hello Done"
        15 -> "Certificate Verify"
        16 -> "Client Key Exchange"
        20 -> "Finished"
        else -> "Type$t"
    }
}
