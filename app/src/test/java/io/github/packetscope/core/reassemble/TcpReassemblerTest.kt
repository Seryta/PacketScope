package io.github.packetscope.core.reassemble

import io.github.packetscope.core.PcapTestFixtures
import io.github.packetscope.core.dissector.Pipeline
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.PcapReader
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

/** TCP 重组单元测试：构造手工 PCAP 让 TcpReassembler 走顺序 / 重传 / 乱序 路径 */
class TcpReassemblerTest {

    @Test
    fun `顺序拼接 SYN 后 3 个 payload`() {
        val frames = loadFrames(
            PcapTestFixtures.ethernetIpv4TcpSyn(),  // SYN，client 51234 → server 80, seq=0
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 51234, dstPort = 80,
                seq = 1, payload = "GET ".toByteArray(),
            ),
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 51234, dstPort = 80,
                seq = 5, payload = "/index.html".toByteArray(),
            ),
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 51234, dstPort = 80,
                seq = 16, payload = " HTTP/1.1\r\n".toByteArray(),
            ),
        )
        val stream = TcpReassembler.assemble(frames).values.single()
        assertEquals(
            "GET /index.html HTTP/1.1\r\n",
            stream.clientToServer.data.toString(Charsets.UTF_8),
        )
        assertEquals(3, stream.clientToServer.chunks.size)
        // 各 chunk 起始 offset：0, 4, 15
        assertEquals(listOf(0, 4, 15), stream.clientToServer.chunks.map { it.dataOffset })
    }

    @Test
    fun `重传 packet 被去重`() {
        val frames = loadFrames(
            PcapTestFixtures.ethernetIpv4TcpSyn(),
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 51234, dstPort = 80,
                seq = 1, payload = "AAAA".toByteArray(),
            ),
            // 完全重传同 seq 同 payload
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 51234, dstPort = 80,
                seq = 1, payload = "AAAA".toByteArray(),
            ),
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 51234, dstPort = 80,
                seq = 5, payload = "BBBB".toByteArray(),
            ),
        )
        val stream = TcpReassembler.assemble(frames).values.single()
        assertEquals("AAAABBBB", stream.clientToServer.data.toString(Charsets.UTF_8))
        // 重传不应该贡献 chunk
        assertEquals(2, stream.clientToServer.chunks.size)
    }

    @Test
    fun `overlap 重传只追加新增部分`() {
        val frames = loadFrames(
            PcapTestFixtures.ethernetIpv4TcpSyn(),
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 51234, dstPort = 80,
                seq = 1, payload = "AAAA".toByteArray(),
            ),
            // 部分 overlap：seq=3 表示从 "AA" 开始的 "AABB" — 前两个 "AA" 已见
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 51234, dstPort = 80,
                seq = 3, payload = "AABB".toByteArray(),
            ),
        )
        val stream = TcpReassembler.assemble(frames).values.single()
        assertEquals("AAAABB", stream.clientToServer.data.toString(Charsets.UTF_8))
    }

    @Test
    fun `双向 client server 独立 flow`() {
        val frames = loadFrames(
            PcapTestFixtures.ethernetIpv4TcpSyn(),
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 51234, dstPort = 80,
                seq = 1, payload = "ping".toByteArray(),
            ),
            // server → client（src/dst 反过来）
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 80, dstPort = 51234,
                seq = 100, payload = "pong".toByteArray(),
                srcIp = byteArrayOf(8, 8, 8, 8), dstIp = byteArrayOf(10, 0, 0, 1),
            ),
        )
        val stream = TcpReassembler.assemble(frames).values.single()
        assertEquals("ping", stream.clientToServer.data.toString(Charsets.UTF_8))
        assertEquals("pong", stream.serverToClient.data.toString(Charsets.UTF_8))
    }

    @Test
    fun `无 SYN 时以首个 payload seq 起始`() {
        val frames = loadFrames(
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 51234, dstPort = 80,
                seq = 1000, payload = "hello".toByteArray(),
            ),
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 51234, dstPort = 80,
                seq = 1005, payload = "world".toByteArray(),
            ),
        )
        val stream = TcpReassembler.assemble(frames).values.single()
        assertEquals("helloworld", stream.clientToServer.data.toString(Charsets.UTF_8))
        assertNull(stream.clientToServer.isn)  // 没 SYN，ISN 仍是 null
    }

    @Test
    fun `SYN+data 包的数据首字节不被丢弃`() {
        // RFC 793 允许 SYN 同时带 data（TFO / TCP Fast Open 常用，Chrome/Safari
        // 默认启用）。SYN 占 1 个 sequence number，data 起始 seq = ISN + 1。
        // 重组器要识别这点，否则 payload 首字节会被当作"已见 SYN-byte"截掉
        // （review v0.6-round7 F-002）。
        val frames = loadFrames(
            PcapTestFixtures.ethIpv4Tcp(
                srcPort = 51234, dstPort = 80,
                seq = 100, payload = "GET /".toByteArray(),
                flags = 0x02,  // SYN only
            ),
        )
        val stream = TcpReassembler.assemble(frames).values.single()
        assertEquals("GET /", String(stream.clientToServer.data, Charsets.US_ASCII))
    }

    @Test
    fun `非 TCP frame 不入流`() {
        val frames = loadFrames(
            PcapTestFixtures.ethIpv4Udp(srcPort = 1000, dstPort = 53, payload = "x".toByteArray()),
        )
        assertTrue(TcpReassembler.assemble(frames).isEmpty())
    }

    private fun loadFrames(vararg packets: ByteArray): List<Frame> {
        val pcap = PcapTestFixtures.build(linkType = 1, packets = packets.toList())
        return PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).toList()
        }
    }
}
