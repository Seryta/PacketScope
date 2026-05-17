package io.github.packetscope.core.filter

import io.github.packetscope.core.L7Fixtures
import io.github.packetscope.core.PcapTestFixtures
import io.github.packetscope.core.dissector.Pipeline
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.PcapReader
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

/**
 * 验证 [FilterIndex.build] 提取的字段与旧 layer 遍历路径一致，且对应 atom 的
 * 索引分支跟无索引分支返回相同结果。
 */
class FilterIndexTest {

    private val dnsFrame: Frame by lazy { buildFrame(
        PcapTestFixtures.ethIpv4Udp(51234, 53, L7Fixtures.dnsQueryExampleCom())
    ) }
    private val tlsFrame: Frame by lazy { buildFrame(
        PcapTestFixtures.ethIpv4Tcp(51234, 443, L7Fixtures.tlsClientHelloWithSni())
    ) }
    private val httpFrame: Frame by lazy { buildFrame(
        PcapTestFixtures.ethIpv4Tcp(51234, 80, L7Fixtures.httpGetRequest())
    ) }

    @Test
    fun `5-tuple 索引正确`() {
        val idx = FilterIndex.build(httpFrame)
        assertEquals(51234, idx.srcPort)
        assertEquals(80, idx.dstPort)
        assertNotNull(idx.srcIp)
        assertNotNull(idx.dstIp)
        assertTrue("TCP" in idx.protocols)
        assertTrue("IPv4" in idx.protocols)
    }

    @Test
    fun `tls 帧索引到 SNI 全小写`() {
        val idx = FilterIndex.build(tlsFrame)
        assertEquals("example.com", idx.sniLower)
        // HTTP 字段在 TLS 帧上应该是 null
        assertNull(idx.httpHostLower)
        assertNull(idx.httpPathLower)
    }

    @Test
    fun `http 帧索引到 host method path`() {
        val idx = FilterIndex.build(httpFrame)
        assertEquals("example.com", idx.httpHostLower)
        assertEquals("GET", idx.httpMethodUpper)
        assertEquals("/index.html", idx.httpPathLower)
    }

    @Test
    fun `dns 帧索引到 question name`() {
        val idx = FilterIndex.build(dnsFrame)
        assertTrue(idx.dnsNamesLower.any { it.contains("example") })
    }

    @Test
    fun `Protocol atom 索引分支与遍历分支结果一致`() {
        val idx = FilterIndex.build(httpFrame)
        val f = FrameFilter.Protocol("TCP")
        assertEquals(f.matches(httpFrame), f.matches(httpFrame, idx))
        assertEquals(f.matches(dnsFrame), f.matches(dnsFrame, FilterIndex.build(dnsFrame)))
    }

    @Test
    fun `HttpHost 索引分支与遍历分支结果一致`() {
        val idx = FilterIndex.build(httpFrame)
        val f = FrameFilter.HttpHost("example")
        assertTrue(f.matches(httpFrame, idx))
        assertEquals(f.matches(httpFrame), f.matches(httpFrame, idx))
    }

    @Test
    fun `Sni 索引分支与遍历分支结果一致`() {
        val idx = FilterIndex.build(tlsFrame)
        val f = FrameFilter.Sni("EXAMPLE")  // 测大小写无关
        assertTrue(f.matches(tlsFrame, idx))
        assertEquals(f.matches(tlsFrame), f.matches(tlsFrame, idx))
    }

    @Test
    fun `DnsName 索引分支命中`() {
        val idx = FilterIndex.build(dnsFrame)
        assertTrue(FrameFilter.DnsName("example").matches(dnsFrame, idx))
        assertFalse(FrameFilter.DnsName("nonexistent").matches(dnsFrame, idx))
    }

    @Test
    fun `Url 索引分支拼 host+path`() {
        val idx = FilterIndex.build(httpFrame)
        // index 路径：拼 example.com + /index.html
        assertTrue(FrameFilter.Url("example.com/index").matches(httpFrame, idx))
        // index 路径下 TLS 帧的 SNI 也能命中 url
        val tlsIdx = FilterIndex.build(tlsFrame)
        assertTrue(FrameFilter.Url("example").matches(tlsFrame, tlsIdx))
    }

    @Test
    fun `Url 索引与非索引路径都不命中 method 或 HTTP version`() {
        // review v0.6-round2 F-005：原非索引分支扫整条 Request line，命中
        // "GET" / "HTTP" / "HTTP/1.1" —— 跟 index 分支不一致。修复后两边都
        // 只在 Host+path 上匹配。
        val idx = FilterIndex.build(httpFrame)
        // 不带 index（非索引分支）
        assertFalse("non-indexed url GET 不应命中纯 method",
            FrameFilter.Url("GET").matches(httpFrame))
        assertFalse("non-indexed url HTTP/1.1 不应命中纯 version",
            FrameFilter.Url("HTTP/1.1").matches(httpFrame))
        // 带 index
        assertFalse("indexed url GET 不应命中",
            FrameFilter.Url("GET").matches(httpFrame, idx))
        assertFalse("indexed url HTTP/1.1 不应命中",
            FrameFilter.Url("HTTP/1.1").matches(httpFrame, idx))
        // 双路径都应该正常命中 Host+path
        assertTrue(FrameFilter.Url("example.com").matches(httpFrame))
        assertTrue(FrameFilter.Url("example.com").matches(httpFrame, idx))
    }

    // ─── F-012 review v0.6-round2：扩展边界 case 覆盖 build 内部分支 ───────

    @Test
    fun `非 IP 帧 srcIp dstIp 全为 null`() {
        // 构造 ARP 之类 EtherType 不在 IPv4/IPv6 集合里的帧 —— pipeline 之后
        // layers 里只有 Ethernet
        val ethOnly = byteArrayOf(
            0xaa.toByte(), 0xaa.toByte(), 0xaa.toByte(), 0xaa.toByte(), 0xaa.toByte(), 0xaa.toByte(),
            0xbb.toByte(), 0xbb.toByte(), 0xbb.toByte(), 0xbb.toByte(), 0xbb.toByte(), 0xbb.toByte(),
            0x08, 0x06,  // EtherType 0x0806 = ARP（无 IP 子层）
            // 一些随机字节
            0, 0, 0, 0, 0, 0, 0, 0,
        )
        val frame = buildFrame(ethOnly)
        val idx = FilterIndex.build(frame)
        assertNull(idx.srcIp)
        assertNull(idx.dstIp)
        assertNull(idx.srcPort)
        assertNull(idx.dstPort)
    }

    @Test
    fun `DNS 帧多个 Name 都被收集`() {
        // DnsQueryExampleCom fixture 至少 1 个 Question Name；这里复用断言
        // collectByName 遍历到 Question + 可能的 Answer
        val idx = FilterIndex.build(dnsFrame)
        assertTrue("至少有 1 条 Question name",
            idx.dnsNamesLower.isNotEmpty())
        assertTrue("Question Name 应有 'example' 子串",
            idx.dnsNamesLower.any { it.contains("example") })
    }

    @Test
    fun `SNI 一律小写化（大小写折叠）`() {
        val idx = FilterIndex.build(tlsFrame)
        val sni = idx.sniLower!!
        assertEquals("sniLower 必须全小写", sni, sni.lowercase())
    }

    @Test
    fun `HttpHost 索引版 大小写无关`() {
        // index 路径上 pattern 已 lowercase，httpHostLower 也是 lowercase
        val idx = FilterIndex.build(httpFrame)
        assertTrue(FrameFilter.HttpHost("EXAMPLE").matches(httpFrame, idx))
        assertTrue(FrameFilter.HttpHost("Example.Com").matches(httpFrame, idx))
    }

    private fun buildFrame(rawPacket: ByteArray): Frame {
        val pcap = PcapTestFixtures.build(linkType = 1, packets = listOf(rawPacket))
        return PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).first()
        }
    }
}
