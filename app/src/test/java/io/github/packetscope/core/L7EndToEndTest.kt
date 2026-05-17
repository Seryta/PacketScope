package io.github.packetscope.core

import io.github.packetscope.core.dissector.Pipeline
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.PcapReader
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

/** 端到端：构造完整 PCAP → Pipeline 路由到对应 L7 dissector，验证协议栈完整 */
class L7EndToEndTest {

    @Test
    fun `UDP_53 路由到 DNS dissector`() {
        val frame = pipe(PcapTestFixtures.ethIpv4Udp(
            srcPort = 51234,
            dstPort = 53,
            payload = L7Fixtures.dnsQueryExampleCom(),
        ))
        assertEquals(listOf("Ethernet", "IPv4", "UDP", "DNS"), frame.layers.map { it.protocol })
        assertTrue(frame.layers.last().summary!!.contains("example.com"))
    }

    @Test
    fun `TCP_80 路由到 HTTP dissector`() {
        val frame = pipe(PcapTestFixtures.ethIpv4Tcp(
            srcPort = 51234,
            dstPort = 80,
            payload = L7Fixtures.httpGetRequest(),
        ))
        assertEquals(listOf("Ethernet", "IPv4", "TCP", "HTTP"), frame.layers.map { it.protocol })
        val http = frame.layers.last()
        assertTrue(http.summary!!.startsWith("HTTP Request:"))
    }

    @Test
    fun `TCP_443 路由到 TLS dissector 并提取 SNI`() {
        val frame = pipe(PcapTestFixtures.ethIpv4Tcp(
            srcPort = 51234,
            dstPort = 443,
            payload = L7Fixtures.tlsClientHelloWithSni(),
        ))
        assertEquals(listOf("Ethernet", "IPv4", "TCP", "TLS"), frame.layers.map { it.protocol })
        assertTrue(frame.layers.last().summary!!.contains("SNI=example.com"))
    }

    @Test
    fun `UDP_443 路由到 QUIC dissector`() {
        val frame = pipe(PcapTestFixtures.ethIpv4Udp(
            srcPort = 51234,
            dstPort = 443,
            payload = L7Fixtures.quicInitialV1(),
        ))
        assertEquals(listOf("Ethernet", "IPv4", "UDP", "QUIC"), frame.layers.map { it.protocol })
        assertTrue(frame.layers.last().summary!!.contains("Initial"))
    }

    @Test
    fun `非常见端口的 TCP 不进入 L7 dissector`() {
        val frame = pipe(PcapTestFixtures.ethIpv4Tcp(
            srcPort = 50000,
            dstPort = 60000,
            payload = "random payload".toByteArray(),
        ))
        // 仅到 TCP 层
        assertEquals(listOf("Ethernet", "IPv4", "TCP"), frame.layers.map { it.protocol })
    }

    private fun pipe(rawPacket: ByteArray): Frame {
        val pcap = PcapTestFixtures.build(linkType = 1, packets = listOf(rawPacket))
        return PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).first()
        }.also { assertNotNull(it) }
    }
}
