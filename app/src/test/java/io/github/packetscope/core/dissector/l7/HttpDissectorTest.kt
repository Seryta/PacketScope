package io.github.packetscope.core.dissector.l7

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * HttpDissector 单测重点：headers 不完整 / 跨 TCP segment 时仍返回 truncated
 * Layer 而非 null，且 summary 明确告知"headers 跨包，未重组"。
 * 完整请求 + 起手不像 HTTP 的负面用例也覆盖。
 */
class HttpDissectorTest {

    @Test
    fun `完整 GET 请求 truncated 为 false`() {
        val payload = ("GET /index.html HTTP/1.1\r\n" +
            "Host: example.com\r\n" +
            "\r\n").toByteArray(Charsets.ISO_8859_1)
        val r = HttpDissector.dissect(payload, 0)
        assertNotNull(r)
        assertFalse("完整 headers 不应 truncated", r!!.layer.truncated)
        assertEquals("HTTP", r.layer.protocol)
        assertEquals("Request line", r.layer.fields[0].name)
    }

    @Test
    fun `headers 跨包未结束 返回 truncated Layer`() {
        // 没有 \r\n\r\n 结束符 —— headers 还在路上
        val payload = ("GET /api/v1/users HTTP/1.1\r\n" +
            "Host: api.example.com\r\n" +
            "Accept: ").toByteArray(Charsets.ISO_8859_1)
        val r = HttpDissector.dissect(payload, 0)
        assertNotNull("跨包不应返回 null，要给 truncated Layer 提示用户", r)
        assertTrue("应被标 truncated", r!!.layer.truncated)
        assertTrue("summary 应含跨包提示",
            r.layer.summary!!.contains("跨包"))
    }

    @Test
    fun `Response 跨包 也返回 truncated Layer`() {
        val payload = ("HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/html").toByteArray(Charsets.ISO_8859_1)
        val r = HttpDissector.dissect(payload, 0)
        assertNotNull(r)
        assertTrue(r!!.layer.truncated)
        assertEquals("Status line", r.layer.fields[0].name)
    }

    @Test
    fun `payload 起手不像 HTTP 返回 null（不 over-dissect）`() {
        val binary = byteArrayOf(0x16, 0x03, 0x01, 0x02, 0x00)  // 类似 TLS header
        assertNull(HttpDissector.dissect(binary, 0))
        // 全二进制
        val random = byteArrayOf(0xde.toByte(), 0xad.toByte(), 0xbe.toByte(), 0xef.toByte())
        assertNull(HttpDissector.dissect(random, 0))
    }
}
