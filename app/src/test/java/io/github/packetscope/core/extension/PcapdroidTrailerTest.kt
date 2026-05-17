package io.github.packetscope.core.extension

import io.github.packetscope.core.PcapTestFixtures
import io.github.packetscope.core.dissector.Pipeline
import io.github.packetscope.core.pcap.PcapReader
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class PcapdroidTrailerTest {

    @Test
    fun `magic 不匹配返回 null`() {
        val data = ByteArray(32) { 0 }
        assertNull(PcapdroidTrailerDecoder.tryDecode(data))
    }

    @Test
    fun `data 太短返回 null`() {
        assertNull(PcapdroidTrailerDecoder.tryDecode(ByteArray(20)))
    }

    @Test
    fun `解出 uid 和 appName`() {
        val trailer = PcapTestFixtures.pcapdroidTrailer(uid = 10063, appName = "com.google.chrome")
        val decoded = PcapdroidTrailerDecoder.tryDecode(trailer)
        assertNotNull(decoded)
        assertEquals(10063, decoded!!.uid)
        assertEquals("com.google.chrome", decoded.appName)
    }

    @Test
    fun `trailer 紧跟 IP 包末尾也能识别`() {
        // 模拟 PCAPdroid 真实场景：fake Ethernet + IPv4 + TCP + trailer
        val syn = PcapTestFixtures.ethernetIpv4TcpSyn()
        val withTrailer = syn + PcapTestFixtures.pcapdroidTrailer(uid = 1000, appName = "system")

        val pcap = PcapTestFixtures.build(linkType = 1, packets = listOf(withTrailer))
        val frame = PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).first()
        }

        // 多了 metadata layer
        assertTrue(frame.layers.any { it.protocol == "PCAPdroid metadata" })
        val meta = frame.layers.first { it.protocol == "PCAPdroid metadata" }
        assertEquals("system", meta.fields.first { it.name == "App name" }.value)
        assertEquals("1000", meta.fields.first { it.name == "UID" }.value)
    }

    @Test
    fun `trailer 不污染 TCP Len 计算`() {
        // 没 trailer 的 SYN 帧 Len=0；加 trailer 后仍然应该 Len=0
        // （回归测试：早期实现把 trailer 32B 当 TCP payload 算成 Len=32）
        val syn = PcapTestFixtures.ethernetIpv4TcpSyn()
        val withTrailer = syn + PcapTestFixtures.pcapdroidTrailer(uid = 1, appName = "x")
        val pcap = PcapTestFixtures.build(linkType = 1, packets = listOf(withTrailer))
        val frame = PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).first()
        }
        val tcp = frame.layers.first { it.protocol == "TCP" }
        assertTrue("expected Len=0 in summary, got: ${tcp.summary}",
            tcp.summary!!.contains("Len=0"))
    }

    @Test
    fun `无 trailer 的包不挂 metadata layer`() {
        val plain = PcapTestFixtures.ethernetIpv4TcpSyn()
        val pcap = PcapTestFixtures.build(linkType = 1, packets = listOf(plain))
        val frame = PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).first()
        }
        assertTrue(frame.layers.none { it.protocol == "PCAPdroid metadata" })
    }
}
