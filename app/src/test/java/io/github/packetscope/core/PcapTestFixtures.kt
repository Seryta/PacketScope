package io.github.packetscope.core

import java.io.ByteArrayOutputStream

/** 在测试里手工构造 PCAP byte stream，避免引入二进制 fixture 文件。 */
object PcapTestFixtures {

    /**
     * @param linkType PCAP link type value（1 = Ethernet, 113 = Linux SLL, 101 = Raw IP）
     * @param packets 每个 packet 的原始字节（不含 record header）
     * @param littleEndian magic 字节序
     * @param nanoseconds true 使用纳秒时间分辨率 magic
     */
    fun build(
        linkType: Int,
        packets: List<ByteArray>,
        littleEndian: Boolean = true,
        nanoseconds: Boolean = false,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        // PCAP magic 在内存里始终是 0xa1b2c3d4 (micro) 或 0xa1b23c4d (nano)；
        // 文件 endianness 体现在用什么字节序把这个值落盘——reader 用 BE 解码
        // 后看到的可能是原值（文件是 BE）或反转值（文件是 LE）。
        val magic: Long = if (nanoseconds) 0xa1b23c4dL else 0xa1b2c3d4L
        // global header
        out.writeU32(magic, littleEndian)
        out.writeU16(2, littleEndian)        // version major
        out.writeU16(4, littleEndian)        // version minor
        out.writeU32(0, littleEndian)        // thiszone
        out.writeU32(0, littleEndian)        // sigfigs
        out.writeU32(65535, littleEndian)    // snaplen
        out.writeU32(linkType.toLong(), littleEndian)

        // record headers + bodies
        var ts = 1_700_000_000L
        for (pkt in packets) {
            out.writeU32(ts, littleEndian)               // ts_sec
            out.writeU32(0, littleEndian)                // ts_usec / ts_nsec
            out.writeU32(pkt.size.toLong(), littleEndian) // incl_len
            out.writeU32(pkt.size.toLong(), littleEndian) // orig_len
            out.write(pkt)
            ts++
        }
        return out.toByteArray()
    }

    /** 拼出一个最小可用 Ethernet/IPv4/TCP SYN 包用于端到端测试。 */
    fun ethernetIpv4TcpSyn(): ByteArray {
        // Ethernet: dst aa..., src bb..., ethertype 0x0800
        val eth = byteArrayOf(
            0xaa.b, 0xaa.b, 0xaa.b, 0xaa.b, 0xaa.b, 0xaa.b,
            0xbb.b, 0xbb.b, 0xbb.b, 0xbb.b, 0xbb.b, 0xbb.b,
            0x08, 0x00,
        )
        // IPv4: version 4, IHL 5, total len 40, TTL 64, protocol TCP, src 10.0.0.1, dst 8.8.8.8
        val ipv4 = byteArrayOf(
            0x45, 0x00,
            0x00, 0x28,           // total length 40
            0x00, 0x01,           // identification
            0x40, 0x00,           // flags=DF, frag offset 0
            0x40,                 // TTL 64
            0x06,                 // protocol TCP
            0x00, 0x00,           // header checksum (skip)
            10, 0, 0, 1,
            8, 8, 8, 8,
        )
        // TCP: src 51234, dst 80, data offset 5, flags SYN, window 64240
        val tcp = byteArrayOf(
            0xc8.b, 0x22,         // src port 51234
            0x00, 0x50,           // dst port 80
            0x00, 0x00, 0x00, 0x00,   // seq
            0x00, 0x00, 0x00, 0x00,   // ack
            0x50,                 // data offset = 5 << 4
            0x02,                 // flags = SYN
            0xfa.b, 0xf0.b,       // window 64240
            0x00, 0x00,           // checksum
            0x00, 0x00,           // urgent
        )
        return eth + ipv4 + tcp
    }

    private val DEFAULT_SRC_IP = byteArrayOf(10, 0, 0, 1)
    private val DEFAULT_DST_IP = byteArrayOf(8, 8, 8, 8)

    /** Ethernet + IPv4(UDP) + UDP + payload；自动算长度 */
    fun ethIpv4Udp(
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
        srcIp: ByteArray = DEFAULT_SRC_IP,
        dstIp: ByteArray = DEFAULT_DST_IP,
    ): ByteArray {
        val udp = ByteArrayOutputStream().apply {
            writeU16Be(srcPort)
            writeU16Be(dstPort)
            writeU16Be(8 + payload.size)
            writeU16Be(0)
            write(payload)
        }.toByteArray()
        return ethIpv4(protocol = 17, payload = udp, srcIp, dstIp)
    }

    /** Ethernet + IPv4(TCP) + TCP + payload；可指定 seq/ack/flags + IP */
    fun ethIpv4Tcp(
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
        seq: Long = 1,
        ack: Long = 1,
        flags: Int = 0x18,  // PSH+ACK
        srcIp: ByteArray = DEFAULT_SRC_IP,
        dstIp: ByteArray = DEFAULT_DST_IP,
    ): ByteArray {
        val tcpHeader = ByteArrayOutputStream().apply {
            writeU16Be(srcPort)
            writeU16Be(dstPort)
            writeU32Be(seq)
            writeU32Be(ack)
            write(0x50)                 // data offset = 5
            write(flags)
            writeU16Be(64240)
            writeU16Be(0)
            writeU16Be(0)
        }.toByteArray()
        return ethIpv4(protocol = 6, payload = tcpHeader + payload, srcIp, dstIp)
    }

    private fun ByteArrayOutputStream.writeU32Be(v: Long) {
        write(((v ushr 24) and 0xFF).toInt())
        write(((v ushr 16) and 0xFF).toInt())
        write(((v ushr 8) and 0xFF).toInt())
        write((v and 0xFF).toInt())
    }

    private fun ethIpv4(
        protocol: Int,
        payload: ByteArray,
        srcIp: ByteArray = DEFAULT_SRC_IP,
        dstIp: ByteArray = DEFAULT_DST_IP,
    ): ByteArray {
        val eth = byteArrayOf(
            0xaa.b, 0xaa.b, 0xaa.b, 0xaa.b, 0xaa.b, 0xaa.b,
            0xbb.b, 0xbb.b, 0xbb.b, 0xbb.b, 0xbb.b, 0xbb.b,
            0x08, 0x00,
        )
        val totalLen = 20 + payload.size
        val ipv4 = ByteArrayOutputStream().apply {
            write(0x45); write(0x00)
            writeU16Be(totalLen)
            writeU16Be(1)               // identification
            write(0x40); write(0x00)    // flags=DF
            write(0x40)                 // TTL=64
            write(protocol)
            writeU16Be(0)               // checksum
            write(srcIp)
            write(dstIp)
        }.toByteArray()
        return eth + ipv4 + payload
    }

    private fun ByteArrayOutputStream.writeU16Be(v: Int) {
        write((v ushr 8) and 0xFF)
        write(v and 0xFF)
    }

    /**
     * 构造 PCAPdroid dump_extensions trailer (32 字节)。
     * @param uid Android UID
     * @param appName 应用名（≤20 字符，自动 null-pad）
     */
    fun pcapdroidTrailer(uid: Int, appName: String): ByteArray {
        require(appName.length <= 20)
        val out = ByteArray(32)
        // magic 0x01072021 BE
        out[0] = 0x01; out[1] = 0x07; out[2] = 0x20; out[3] = 0x21
        // uid BE
        out[4] = ((uid ushr 24) and 0xFF).toByte()
        out[5] = ((uid ushr 16) and 0xFF).toByte()
        out[6] = ((uid ushr 8) and 0xFF).toByte()
        out[7] = (uid and 0xFF).toByte()
        // appName 20B null-padded
        val nameBytes = appName.toByteArray(Charsets.US_ASCII)
        System.arraycopy(nameBytes, 0, out, 8, nameBytes.size)
        // fcs placeholder (decoder 不验证)
        out[28] = 0xDE.toByte(); out[29] = 0xAD.toByte()
        out[30] = 0xBE.toByte(); out[31] = 0xEF.toByte()
        return out
    }

    private val Int.b: Byte get() = this.toByte()

    private fun ByteArrayOutputStream.writeU16(value: Int, le: Boolean) {
        if (le) {
            write(value and 0xFF)
            write((value ushr 8) and 0xFF)
        } else {
            write((value ushr 8) and 0xFF)
            write(value and 0xFF)
        }
    }

    private fun ByteArrayOutputStream.writeU32(value: Long, le: Boolean) {
        if (le) {
            write((value and 0xFF).toInt())
            write(((value ushr 8) and 0xFF).toInt())
            write(((value ushr 16) and 0xFF).toInt())
            write(((value ushr 24) and 0xFF).toInt())
        } else {
            write(((value ushr 24) and 0xFF).toInt())
            write(((value ushr 16) and 0xFF).toInt())
            write(((value ushr 8) and 0xFF).toInt())
            write((value and 0xFF).toInt())
        }
    }
}
