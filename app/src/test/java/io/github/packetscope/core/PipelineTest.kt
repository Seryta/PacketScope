package io.github.packetscope.core

import io.github.packetscope.core.dissector.Pipeline
import io.github.packetscope.core.pcap.LinkType
import io.github.packetscope.core.pcap.PcapReader
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class PipelineTest {

    @Test
    fun `Ethernet IPv4 TCP SYN 端到端`() {
        val pcap = PcapTestFixtures.build(
            linkType = 1,
            packets = listOf(PcapTestFixtures.ethernetIpv4TcpSyn()),
        )

        val frames = PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).toList()
        }

        assertEquals(1, frames.size)
        val frame = frames[0]
        assertEquals(listOf("Ethernet", "IPv4", "TCP"), frame.layers.map { it.protocol })

        val eth = frame.layers[0]
        assertEquals(0..13, eth.byteRange)
        assertEquals("aa:aa:aa:aa:aa:aa", eth.fields[0].value)
        assertEquals("bb:bb:bb:bb:bb:bb", eth.fields[1].value)

        val ipv4 = frame.layers[1]
        assertEquals(14..33, ipv4.byteRange)
        assertEquals("10.0.0.1 → 8.8.8.8", ipv4.summary)
        val src = ipv4.fields.first { it.name == "Source" }
        assertEquals("10.0.0.1", src.value)
        assertEquals(26..29, src.byteRange)  // 14 + 12 = 26

        val tcp = frame.layers[2]
        assertTrue(tcp.summary!!.contains("[SYN]"))
        val flags = tcp.fields.first { it.name == "Flags" }
        val syn = flags.children.first { it.name == "SYN" }
        assertEquals("1", syn.value)
        val ack = flags.children.first { it.name == "ACK" }
        assertEquals("0", ack.value)

        assertFalse(frame.layers.any { it.truncated })
        assertEquals("TCP", frame.topProtocol)
        assertNotNull(frame.info)
    }

    @Test
    fun `Raw IP link type 自动识别 IPv4`() {
        val ipv4TcpPart = PcapTestFixtures.ethernetIpv4TcpSyn().sliceArray(14 until 54)
        val pcap = PcapTestFixtures.build(
            linkType = 101,
            packets = listOf(ipv4TcpPart),
        )

        val frames = PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            assertEquals(LinkType.RAW_IP, reader.linkType)
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).toList()
        }

        assertEquals(1, frames.size)
        // Raw IP 不产生独立 L2 layer，IPv4 直接作为第一层
        assertEquals("IPv4", frames[0].layers[0].protocol)
        assertEquals("TCP", frames[0].layers[1].protocol)
    }

    @Test
    fun `UDP 包正常解析端口和长度`() {
        // Ethernet + IPv4 (proto=17 UDP) + UDP(src=53, dst=51234, len=8) + 空 payload
        val eth = byteArrayOf(
            0xaa.toByte(), 0xaa.toByte(), 0xaa.toByte(), 0xaa.toByte(), 0xaa.toByte(), 0xaa.toByte(),
            0xbb.toByte(), 0xbb.toByte(), 0xbb.toByte(), 0xbb.toByte(), 0xbb.toByte(), 0xbb.toByte(),
            0x08, 0x00,
        )
        val ipv4 = byteArrayOf(
            0x45, 0x00,
            0x00, 0x1c,
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x11,           // TTL=64 protocol=UDP
            0x00, 0x00,
            8, 8, 8, 8,
            10, 0, 0, 1,
        )
        val udp = byteArrayOf(
            0x00, 0x35,           // src port 53
            0xc8.toByte(), 0x22,  // dst port 51234
            0x00, 0x08,           // length 8
            0x00, 0x00,           // checksum
        )
        val pcap = PcapTestFixtures.build(linkType = 1, packets = listOf(eth + ipv4 + udp))

        val frame = PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).first()
        }
        val udpLayer = frame.layers.first { it.protocol == "UDP" }
        assertTrue(udpLayer.summary!!.contains("53 → 51234"))
    }

    @Test
    fun `非默认端口的 TLS 通过 fallback 探针识别`() {
        // TLS ClientHello 跑在 TCP 9443（非 443/8443）上 —— 端口表查不到，
        // 但 byTcpPort fallback 应该探针 TLS 成功
        val pcap = PcapTestFixtures.build(linkType = 1, packets = listOf(
            PcapTestFixtures.ethIpv4Tcp(51234, 9443, L7Fixtures.tlsClientHelloWithSni())
        ))
        val frame = PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).first()
        }
        assertTrue("TLS 应被 fallback 探针识别",
            frame.layers.any { it.protocol == "TLS" })
    }

    @Test
    fun `非默认端口的 HTTP 通过 fallback 探针识别`() {
        // HTTP 跑在 TCP 12345（非 80/8080）—— 探针 TLS 不像 + HTTP 文本检测命中
        val pcap = PcapTestFixtures.build(linkType = 1, packets = listOf(
            PcapTestFixtures.ethIpv4Tcp(51234, 12345, L7Fixtures.httpGetRequest())
        ))
        val frame = PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).first()
        }
        assertTrue("HTTP 应被 fallback 探针识别",
            frame.layers.any { it.protocol == "HTTP" })
    }

    @Test
    fun `TLS 优先于 HTTP fallback（避免文本检测误抢 TLS）`() {
        // TLS ClientHello 二进制内可能包含 ASCII 字节，但 TLS dissector 守得严，
        // 应该先于 HTTP fallback 命中
        val pcap = PcapTestFixtures.build(linkType = 1, packets = listOf(
            PcapTestFixtures.ethIpv4Tcp(51234, 30000, L7Fixtures.tlsClientHelloWithSni())
        ))
        val frame = PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).first()
        }
        val l7Names = frame.layers.map { it.protocol }
        assertTrue("应识别成 TLS 而不是 HTTP", "TLS" in l7Names)
        assertFalse("不应误识别成 HTTP", "HTTP" in l7Names)
    }

    @Test
    fun `IPv4 截断（包体不足头长）标记 truncated`() {
        // 只给 18 字节的 IPv4 数据，header 至少 20 字节
        val eth = byteArrayOf(
            0xaa.toByte(), 0xaa.toByte(), 0xaa.toByte(), 0xaa.toByte(), 0xaa.toByte(), 0xaa.toByte(),
            0xbb.toByte(), 0xbb.toByte(), 0xbb.toByte(), 0xbb.toByte(), 0xbb.toByte(), 0xbb.toByte(),
            0x08, 0x00,
        )
        val shortIpv4 = ByteArray(18) { 0x45.toByte() }
        val pcap = PcapTestFixtures.build(linkType = 1, packets = listOf(eth + shortIpv4))

        val frame = PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).first()
        }
        val ipv4 = frame.layers.first { it.protocol == "IPv4" }
        assertTrue("IPv4 应被标 truncated", ipv4.truncated)
    }
}
