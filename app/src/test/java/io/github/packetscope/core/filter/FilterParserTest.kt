package io.github.packetscope.core.filter

import io.github.packetscope.core.L7Fixtures
import io.github.packetscope.core.PcapTestFixtures
import io.github.packetscope.core.dissector.Pipeline
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.PcapReader
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class FilterParserTest {

    @Test
    fun `空字符串返回 MatchAll`() {
        assertEquals(FrameFilter.MatchAll, FilterParser.parse(""))
        assertEquals(FrameFilter.MatchAll, FilterParser.parse("   "))
    }

    @Test
    fun `单协议名`() {
        assertEquals(FrameFilter.Protocol("TCP"), FilterParser.parse("tcp"))
        assertEquals(FrameFilter.Protocol("DNS"), FilterParser.parse("DNS"))
        assertEquals(FrameFilter.Protocol("TLS"), FilterParser.parse("Tls"))
    }

    @Test
    fun `host 和 port atom`() {
        assertEquals(FrameFilter.Host("1.1.1.1"), FilterParser.parse("host 1.1.1.1"))
        assertEquals(FrameFilter.Port(53), FilterParser.parse("port 53"))
    }

    @Test
    fun `sni 子串匹配`() {
        assertEquals(FrameFilter.Sni("google"), FilterParser.parse("sni google"))
    }

    @Test
    fun `and 优先级高于 or 且左结合`() {
        val parsed = FilterParser.parse("tcp or udp and port 53")
        // 期望：Or(tcp, And(udp, port 53))
        val or = parsed as FrameFilter.Or
        assertEquals(FrameFilter.Protocol("TCP"), or.left)
        val and = or.right as FrameFilter.And
        assertEquals(FrameFilter.Protocol("UDP"), and.left)
        assertEquals(FrameFilter.Port(53), and.right)
    }

    @Test
    fun `not 取反`() {
        val parsed = FilterParser.parse("not tls")
        assertEquals(FrameFilter.Not(FrameFilter.Protocol("TLS")), parsed)
    }

    @Test
    fun `非法 token 抛异常`() {
        assertThrows(FilterParseException::class.java) { FilterParser.parse("garbage") }
        assertThrows(FilterParseException::class.java) { FilterParser.parse("port abc") }
        assertThrows(FilterParseException::class.java) { FilterParser.parse("port 99999") }
        assertThrows(FilterParseException::class.java) { FilterParser.parse("host") }
        assertThrows(FilterParseException::class.java) { FilterParser.parse("tcp and") }
    }

    // ─── error 类型断言（替代脆的 e.message 字符串断言） ─────────────────

    @Test
    fun `FilterParseError 携带结构化错误类型`() {
        // UnknownToken
        assertEquals(
            FilterParseError.UnknownToken("garbage"),
            catchFilterError("garbage"),
        )
        // PortOutOfRange
        assertEquals(
            FilterParseError.PortOutOfRange(99999),
            catchFilterError("port 99999"),
        )
        // ExpectedDigit
        assertEquals(
            FilterParseError.ExpectedDigit("abc"),
            catchFilterError("port abc"),
        )
        // MissingArg（host 没参数）
        assertEquals(
            FilterParseError.MissingArg("host"),
            catchFilterError("host"),
        )
        // ExtraToken
        assertEquals(
            FilterParseError.ExtraToken("foobar"),
            catchFilterError("tcp foobar"),
        )
        // MissingRightParen
        assertEquals(
            FilterParseError.MissingRightParen,
            catchFilterError("(tcp"),
        )
        // UnexpectedEndOfExpr（and 后什么都没有 → parseFactor 末尾 consume = null）
        assertEquals(
            FilterParseError.UnexpectedEndOfExpr,
            catchFilterError("tcp and"),
        )
    }

    private fun catchFilterError(input: String): FilterParseError {
        var caught: FilterParseError? = null
        try {
            FilterParser.parse(input)
        } catch (e: FilterParseException) {
            caught = e.error
        }
        return caught ?: error("expected FilterParseException for input \"$input\"")
    }

    // ─── 语义测试：在真实 Frame 上验证匹配 ─────────────────────────────────

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
    fun `tcp 匹配 HTTP TLS 但不匹配 DNS`() {
        val f = FilterParser.parse("tcp")
        assertTrue(f.matches(httpFrame))
        assertTrue(f.matches(tlsFrame))
        assertFalse(f.matches(dnsFrame))
    }

    @Test
    fun `port 53 只匹配 DNS`() {
        val f = FilterParser.parse("port 53")
        assertTrue(f.matches(dnsFrame))
        assertFalse(f.matches(httpFrame))
        assertFalse(f.matches(tlsFrame))
    }

    @Test
    fun `host 8_8_8_8 匹配所有目标 8_8_8_8 的包`() {
        val f = FilterParser.parse("host 8.8.8.8")
        assertTrue(f.matches(dnsFrame))
        assertTrue(f.matches(tlsFrame))
        assertTrue(f.matches(httpFrame))
    }

    @Test
    fun `sni google 不匹配 example_com 的 ClientHello`() {
        val f = FilterParser.parse("sni google")
        assertFalse(f.matches(tlsFrame))
    }

    @Test
    fun `sni example 子串匹配 example_com SNI`() {
        val f = FilterParser.parse("sni example")
        assertTrue(f.matches(tlsFrame))
    }

    @Test
    fun `udp and port 53 同时匹配`() {
        val f = FilterParser.parse("udp and port 53")
        assertTrue(f.matches(dnsFrame))
        assertFalse(f.matches(httpFrame))
    }

    @Test
    fun `tcp or udp 任一匹配`() {
        val f = FilterParser.parse("tcp or udp")
        assertTrue(f.matches(dnsFrame))
        assertTrue(f.matches(httpFrame))
        assertTrue(f.matches(tlsFrame))
    }

    @Test
    fun `not tls 取反`() {
        val f = FilterParser.parse("not tls")
        assertFalse(f.matches(tlsFrame))
        assertTrue(f.matches(httpFrame))
        assertTrue(f.matches(dnsFrame))
    }

    @Test
    fun `括号改变优先级`() {
        // 不带括号：tcp or udp and port 53 → tcp 都匹配
        val noParens = FilterParser.parse("tcp or udp and port 53")
        assertTrue(noParens.matches(httpFrame))  // tcp 命中
        // 带括号：(tcp or udp) and port 53 → 必须同时是 tcp/udp 且 port 53
        val withParens = FilterParser.parse("(tcp or udp) and port 53")
        assertTrue(withParens.matches(dnsFrame))    // udp + 53
        assertFalse(withParens.matches(httpFrame))  // tcp 但不 53
        assertFalse(withParens.matches(tlsFrame))   // tcp 但不 53
    }

    @Test
    fun `括号嵌套与 not`() {
        val f = FilterParser.parse("not (tcp and port 80)")
        assertFalse(f.matches(httpFrame))  // tcp:80 命中 inner → not 取反
        assertTrue(f.matches(tlsFrame))    // tcp:443 不命中 inner
        assertTrue(f.matches(dnsFrame))    // udp 不命中 inner
    }

    @Test
    fun `括号缺失抛异常`() {
        assertThrows(FilterParseException::class.java) { FilterParser.parse("(tcp or udp") }
        assertThrows(FilterParseException::class.java) { FilterParser.parse("tcp or udp)") }
    }

    @Test
    fun `http_host 匹配 HTTP Host header`() {
        val f = FilterParser.parse("http.host example.com")
        assertTrue(f.matches(httpFrame))
        assertFalse(f.matches(tlsFrame))
        // 子串匹配
        assertTrue(FilterParser.parse("http.host example").matches(httpFrame))
        assertFalse(FilterParser.parse("http.host google").matches(httpFrame))
    }

    @Test
    fun `http_path 匹配 Request line 路径`() {
        assertTrue(FilterParser.parse("http.path /index").matches(httpFrame))
        assertTrue(FilterParser.parse("http.path index.html").matches(httpFrame))
        assertFalse(FilterParser.parse("http.path /api").matches(httpFrame))
        // 不该把 method 误判为 path
        assertFalse(FilterParser.parse("http.path GET").matches(httpFrame))
    }

    @Test
    fun `http_method 等值匹配`() {
        assertTrue(FilterParser.parse("http.method GET").matches(httpFrame))
        assertTrue(FilterParser.parse("http.method get").matches(httpFrame))  // 大小写无关
        assertFalse(FilterParser.parse("http.method POST").matches(httpFrame))
    }

    @Test
    fun `url 拼 Host+path 子串匹配`() {
        assertTrue(FilterParser.parse("url example.com/index").matches(httpFrame))
        assertTrue(FilterParser.parse("url example.com").matches(httpFrame))
        assertFalse(FilterParser.parse("url google.com").matches(httpFrame))
        // url 也能命中 TLS SNI（提供"https URL"语义）
        assertTrue(FilterParser.parse("url example").matches(tlsFrame))
    }

    @Test
    fun `dns_name 匹配 Question Name`() {
        assertTrue(FilterParser.parse("dns.name example.com").matches(dnsFrame))
        assertTrue(FilterParser.parse("dns.name example").matches(dnsFrame))
        assertFalse(FilterParser.parse("dns.name mozilla").matches(dnsFrame))
        // dns.name 只在 DNS 帧生效
        assertFalse(FilterParser.parse("dns.name example").matches(tlsFrame))
    }

    @Test
    fun `text 扫整帧 raw bytes`() {
        // User-Agent 里有 "PacketScope-test"
        assertTrue(FilterParser.parse("text PacketScope-test").matches(httpFrame))
        // 大小写无关
        assertTrue(FilterParser.parse("text packetscope").matches(httpFrame))
        assertFalse(FilterParser.parse("text NotInTheData").matches(httpFrame))
    }

    private fun buildFrame(rawPacket: ByteArray): Frame {
        val pcap = PcapTestFixtures.build(linkType = 1, packets = listOf(rawPacket))
        return PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).first()
        }
    }
}
