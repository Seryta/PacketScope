package io.github.packetscope.core

import io.github.packetscope.core.dissector.l7.DnsDissector
import io.github.packetscope.core.dissector.l7.HttpDissector
import io.github.packetscope.core.dissector.l7.QuicDissector
import io.github.packetscope.core.dissector.l7.TlsDissector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class L7DissectorTest {

    @Test
    fun `DNS query example_com 解析 question`() {
        val data = L7Fixtures.dnsQueryExampleCom()
        val result = DnsDissector.dissect(data, 0) ?: error("null result")
        val layer = result.layer
        assertEquals("DNS", layer.protocol)
        assertTrue(layer.summary!!.contains("example.com"))
        assertTrue(layer.summary!!.startsWith("Q:"))
        val query = layer.fields.first { it.name == "Query" }
        val name = query.children.first { it.name == "Name" }
        assertEquals("example.com", name.value)
    }

    @Test
    fun `DNS response 解析 answer A 记录含 name 压缩指针`() {
        val data = L7Fixtures.dnsResponseExampleCom()
        val result = DnsDissector.dissect(data, 0) ?: error("null result")
        val layer = result.layer
        assertTrue(layer.summary!!.startsWith("A:"))
        assertTrue(layer.summary!!.contains("93.184.216.34"))
        val answer = layer.fields.first { it.name == "Answer" }
        val name = answer.children.first { it.name == "Name" }
        // name 通过压缩指针应该被还原为 example.com
        assertEquals("example.com", name.value)
        val rdata = answer.children.first { it.name == "Data" }
        assertEquals("93.184.216.34", rdata.value)
    }

    @Test
    fun `HTTP GET 解析 request line 和 host header`() {
        val data = L7Fixtures.httpGetRequest()
        val result = HttpDissector.dissect(data, 0) ?: error("null result")
        val layer = result.layer
        assertEquals("HTTP", layer.protocol)
        assertTrue(layer.summary!!.startsWith("HTTP Request:"))
        val reqLine = layer.fields.first { it.name == "Request line" }
        assertEquals("GET /index.html HTTP/1.1", reqLine.value)
        val host = layer.fields.first { it.name == "Host" }
        assertEquals("example.com", host.value)
    }

    @Test
    fun `HTTP 数据不像 HTTP 时返回 null`() {
        val random = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x42, 0x77, 0x88.toByte())
        assertNull(HttpDissector.dissect(random, 0))
    }

    @Test
    fun `TLS ClientHello 提取 SNI=example_com`() {
        val data = L7Fixtures.tlsClientHelloWithSni()
        val result = TlsDissector.dissect(data, 0) ?: error("null result")
        val layer = result.layer
        assertEquals("TLS", layer.protocol)
        assertTrue(layer.summary!!.contains("SNI=example.com"))
        val handshake = layer.fields.first { it.name == "Handshake" }
        val sni = handshake.children.first { it.name == "Server Name Indication" }
        assertEquals("example.com", sni.value)
    }

    @Test
    fun `TLS 误命中防御 ApplicationData type 仍可识别`() {
        val data = byteArrayOf(0x17, 0x03, 0x03, 0x00, 0x10) + ByteArray(16)
        val result = TlsDissector.dissect(data, 0)
        assertNotNull(result)
        assertEquals("TLS Application Data", result!!.layer.summary)
    }

    @Test
    fun `TLS 非 TLS 数据返回 null`() {
        val notTls = byteArrayOf(0x45, 0x00, 0x00, 0x28)  // 像 IPv4 header
        assertNull(TlsDissector.dissect(notTls, 0))
    }

    @Test
    fun `QUIC v1 Initial 解析 long header 字段`() {
        val data = L7Fixtures.quicInitialV1()
        val result = QuicDissector.dissect(data, 0) ?: error("null result")
        val layer = result.layer
        assertEquals("QUIC", layer.protocol)
        assertTrue(layer.summary!!.contains("Initial"))
        assertTrue(layer.summary!!.contains("v=v1"))
        val version = layer.fields.first { it.name == "Version" }
        assertTrue(version.value.contains("v1"))
        val dcidLen = layer.fields.first { it.name == "DCID length" }
        assertEquals("8", dcidLen.value)
        val encrypted = layer.fields.first { it.name == "Encrypted payload" }
        assertTrue(encrypted.value.contains("HKDF"))
    }

    @Test
    fun `QUIC short header 不识别返回 null`() {
        // byte 0 高 bit = 0 表示 short header
        val data = byteArrayOf(0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        assertNull(QuicDissector.dissect(data, 0))
    }
}
