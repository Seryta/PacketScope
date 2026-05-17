package io.github.packetscope.core.reassemble

import io.github.packetscope.core.PcapTestFixtures
import io.github.packetscope.core.dissector.Pipeline
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.PcapReader
import io.github.packetscope.core.pcap.Protocols
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPOutputStream

/**
 * HttpStreamPass 端到端测试：构造 PCAP 含多 segment 的 HTTP 流量，验 pass
 * 能从重组后 byte stream 解出 Body 元信息 + chunked / gzip decode。
 */
class HttpStreamPassTest {

    @Test
    fun `Content-Length body 跨多 segment 拼接`() {
        // GET / HTTP/1.1 + headers + 200 OK + Content-Length: 26 + 跨 2 segment 的 body
        val req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n".toByteArray()
        val respHeaders = "HTTP/1.1 200 OK\r\nContent-Length: 26\r\n\r\n".toByteArray()
        // body 共 26 bytes，故意切成两段验证跨 segment 拼接
        val combined = "Hello world from PacketScope".toByteArray().copyOfRange(0, 26)
        val frames = loadFrames(
            // client → server: req
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 51234, dstPort = 80,
                seq = 1, payload = req,
            ),
            // server → client: response headers
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 80, dstPort = 51234,
                seq = 1, payload = respHeaders,
                srcIp = byteArrayOf(8, 8, 8, 8), dstIp = byteArrayOf(10, 0, 0, 1),
            ),
            // server → client: body part 1
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 80, dstPort = 51234,
                seq = 1 + respHeaders.size.toLong(),
                payload = combined.copyOfRange(0, 17),
                srcIp = byteArrayOf(8, 8, 8, 8), dstIp = byteArrayOf(10, 0, 0, 1),
            ),
            // server → client: body part 2
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 80, dstPort = 51234,
                seq = 1 + respHeaders.size.toLong() + 17,
                payload = combined.copyOfRange(17, 26),
                srcIp = byteArrayOf(8, 8, 8, 8), dstIp = byteArrayOf(10, 0, 0, 1),
            ),
        )
        val out = HttpStreamPass.process(frames)
        val bodyField = findHttpField(out, "Body")
        assertNotNull(bodyField)
        assertTrue("expected '26B' size info, got '${bodyField!!.value}'",
            bodyField.value.contains("26B"))
        assertTrue("expected 'across' frame count",
            bodyField.value.contains("across"))
        val preview = findHttpField(out, "Body (preview)")
        assertNotNull(preview)
        assertEquals(String(combined), preview!!.value)
    }

    @Test
    fun `gzip Content-Encoding 自动解压`() {
        val resp = "Decompressed payload by PacketScope".toByteArray()
        val gz = ByteArrayOutputStream().also {
            GZIPOutputStream(it).use { gzo -> gzo.write(resp) }
        }.toByteArray()
        val respHeaders = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n" +
            "Content-Length: ${gz.size}\r\n\r\n"
        val frames = loadFrames(
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 80, dstPort = 51234,
                seq = 1, payload = respHeaders.toByteArray() + gz,
                srcIp = byteArrayOf(8, 8, 8, 8), dstIp = byteArrayOf(10, 0, 0, 1),
            ),
        )
        val out = HttpStreamPass.process(frames)
        val bodyField = findHttpField(out, "Body")
        assertNotNull(bodyField)
        assertTrue("expected gzip decoded info, got '${bodyField!!.value}'",
            bodyField.value.contains("gzip"))
        assertTrue(bodyField.value.contains("${resp.size}B decoded"))
        val preview = findHttpField(out, "Body (preview)")
        assertEquals(String(resp), preview?.value)
    }

    @Test
    fun `chunked Transfer-Encoding 解码`() {
        // chunked body: "Mozilla" (7 bytes) + "Developer" (9 bytes) + "Network" (7 bytes) → "MozillaDeveloperNetwork"
        val chunked = "7\r\nMozilla\r\n9\r\nDeveloper\r\n7\r\nNetwork\r\n0\r\n\r\n"
        val respHeaders = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        val frames = loadFrames(
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 80, dstPort = 51234,
                seq = 1, payload = (respHeaders + chunked).toByteArray(),
                srcIp = byteArrayOf(8, 8, 8, 8), dstIp = byteArrayOf(10, 0, 0, 1),
            ),
        )
        val out = HttpStreamPass.process(frames)
        val bodyField = findHttpField(out, "Body")
        assertNotNull(bodyField)
        assertTrue("expected chunked info, got '${bodyField!!.value}'",
            bodyField.value.contains("chunked"))
        val preview = findHttpField(out, "Body (preview)")
        assertEquals("MozillaDeveloperNetwork", preview?.value)
    }

    @Test
    fun `keep-alive 流 204 No Content 后续 message 不被吞`() {
        // 单 segment 内 keep-alive 两条响应：第一条 204 No Content (body=0)，
        // 第二条 200 OK body=Hello。修复前 scanFlow 安全网逻辑反转，遇 body=0
        // 直接 return，第二条被吞（review v0.6-round7 F-003）。修复后两条
        // message 都该被描述出 Body field。
        val resp = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n" +
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello"
        val frames = loadFrames(
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 80, dstPort = 51234,
                seq = 1, payload = resp.toByteArray(),
                srcIp = byteArrayOf(8, 8, 8, 8), dstIp = byteArrayOf(10, 0, 0, 1),
            ),
        )
        val out = HttpStreamPass.process(frames)
        val bodyFields = allHttpFields(out, "Body")
        assertEquals("两条 message 都该被描述", 2, bodyFields.size)
        // 第二条带 "Hello" preview，验证它确实被解出来
        val previews = allHttpFields(out, "Body (preview)")
        assertTrue("第二条 200 OK 的 body preview Hello 应在",
            previews.any { it.value == "Hello" })
    }

    /** 收集所有 HTTP response frame 的指定 Field（含跨 message 的 keep-alive） */
    private fun allHttpFields(
        frames: List<Frame>, fieldName: String,
    ): List<io.github.packetscope.core.pcap.Field> = frames.flatMap { f ->
        val http = f.layers.firstOrNull { it.protocol == Protocols.HTTP } ?: return@flatMap emptyList()
        val isResponse = http.fields.any {
            it.name == "Status line" && it.value.startsWith("HTTP/")
        }
        if (!isResponse) emptyList() else http.fields.filter { it.name == fieldName }
    }

    /** 找含 "HTTP/1.1 200" 状态行的 response frame 内的指定 Field（区分 request 与
     *  response — 两个方向都会被 HttpStreamPass 扫到挂 Body field） */
    private fun findHttpField(
        frames: List<Frame>, fieldName: String,
    ): io.github.packetscope.core.pcap.Field? = frames.firstNotNullOfOrNull { f ->
        val http = f.layers.firstOrNull { it.protocol == Protocols.HTTP }
            ?: return@firstNotNullOfOrNull null
        val isResponse = http.fields.any {
            it.name == "Status line" && it.value.startsWith("HTTP/")
        }
        if (!isResponse) null else http.fields.firstOrNull { it.name == fieldName }
    }

    private fun loadFrames(vararg packets: ByteArray): List<Frame> {
        val pcap = PcapTestFixtures.build(linkType = 1, packets = packets.toList())
        return PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).toList()
        }
    }
}
