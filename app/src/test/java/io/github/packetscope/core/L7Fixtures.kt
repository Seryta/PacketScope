package io.github.packetscope.core

import java.io.ByteArrayOutputStream

/** 构造各类 L7 fixture：原始字节（不含外面的 Ethernet/IP/L4 头）。 */
object L7Fixtures {

    /** "example.com" 标准 DNS A 查询 */
    fun dnsQueryExampleCom(): ByteArray = byteArrayOf(
        // header: id=0x1234 flags=0x0100 qd=1 an=0 ns=0 ar=0
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // qname "example.com"
        0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
        'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
        0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0x00,
        // qtype=1 qclass=1
        0x00, 0x01, 0x00, 0x01,
    )

    /** DNS A 响应：example.com → 93.184.216.34，含 name 压缩指针 */
    fun dnsResponseExampleCom(): ByteArray = byteArrayOf(
        // header: id=0x1234 flags=0x8180 qd=1 an=1
        0x12, 0x34, 0x81.toByte(), 0x80.toByte(), 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        // question: example.com A IN
        0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
        'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
        0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0x00,
        0x00, 0x01, 0x00, 0x01,
        // answer: name=ptr(0x0c) type=A class=IN ttl=300 rdlen=4 rdata=93.184.216.34
        0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C,
        0x00, 0x04, 0x5D, 0xB8.toByte(), 0xD8.toByte(), 0x22,
    )

    /** 简单 HTTP GET 请求 */
    fun httpGetRequest(): ByteArray =
        ("GET /index.html HTTP/1.1\r\n" +
            "Host: example.com\r\n" +
            "User-Agent: PacketScope-test/1.0\r\n" +
            "Accept: */*\r\n" +
            "\r\n").toByteArray(Charsets.ISO_8859_1)

    /**
     * TLS ClientHello with SNI=example.com.
     * 字段长度精心匹配，所有 length 都正确。
     */
    fun tlsClientHelloWithSni(): ByteArray {
        val sni = "example.com".toByteArray(Charsets.US_ASCII)

        // server_name extension data: list_len(2) + name_type(1) + name_len(2) + name
        val sniExtData = ByteArrayOutputStream().apply {
            // server_name_list length = 1 + 2 + name.size = 3 + name.size
            writeU16(3 + sni.size)
            write(0)                        // name_type = host_name
            writeU16(sni.size)
            write(sni)
        }.toByteArray()
        val sniExtBlock = ByteArrayOutputStream().apply {
            writeU16(0)                     // extension_type = server_name
            writeU16(sniExtData.size)
            write(sniExtData)
        }.toByteArray()

        // ClientHello body
        val body = ByteArrayOutputStream().apply {
            writeU16(0x0303)                // legacy_version = TLS 1.2
            write(ByteArray(32))            // random (32B)
            write(0)                        // session_id_length = 0
            writeU16(2)                     // cipher_suites_length
            writeU16(0x002F)                // TLS_RSA_WITH_AES_128_CBC_SHA
            write(1)                        // compression_methods_length
            write(0)                        // null compression
            writeU16(sniExtBlock.size)      // extensions_length
            write(sniExtBlock)
        }.toByteArray()

        // Handshake header
        val handshake = ByteArrayOutputStream().apply {
            write(1)                                                 // ClientHello
            write((body.size ushr 16) and 0xFF)                      // length (3 bytes)
            write((body.size ushr 8) and 0xFF)
            write(body.size and 0xFF)
            write(body)
        }.toByteArray()

        // Record layer
        return ByteArrayOutputStream().apply {
            write(0x16)                     // Handshake
            writeU16(0x0301)                // record version TLS 1.0 (常见占位)
            writeU16(handshake.size)
            write(handshake)
        }.toByteArray()
    }

    /** QUIC v1 Initial long header with empty token */
    fun quicInitialV1(): ByteArray {
        val dcid = byteArrayOf(0x83.toByte(), 0x94.toByte(), 0xc8.toByte(), 0xf0.toByte(),
            0x3e.toByte(), 0x51.toByte(), 0x57.toByte(), 0x08.toByte())
        val scid = ByteArray(0)
        // 加密 payload 占位 16 字节
        val encryptedPayload = ByteArray(16) { 0x00 }
        return ByteArrayOutputStream().apply {
            write(0xC0.toByte().toInt())                 // long header, fixed bit, type=Initial (00), PN len bits=00
            // version = 1
            write(0); write(0); write(0); write(1)
            write(dcid.size); write(dcid)
            write(scid.size); write(scid)
            // token length = 0 (var-int 1-byte = 0x00)
            write(0)
            // length (var-int 2-byte): payload size = 16
            // 2-byte form prefix 01, value 16 → 0x40 0x10
            write(0x40); write(0x10)
            write(encryptedPayload)
        }.toByteArray()
    }

    private fun ByteArrayOutputStream.writeU16(v: Int) {
        write((v ushr 8) and 0xFF)
        write(v and 0xFF)
    }
}
