package io.github.packetscope.core.analysis

import io.github.packetscope.core.PcapTestFixtures
import io.github.packetscope.core.dissector.Pipeline
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.PcapReader
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class TcpSessionAnalyzerTest {

    @Test
    fun `relative seq 从 SYN 包 ISN 派生`() {
        val syn = PcapTestFixtures.ethIpv4Tcp(
            51234, 80, ByteArray(0),
            seq = 1000, ack = 0, flags = 0x02,  // SYN only
        )
        val data = PcapTestFixtures.ethIpv4Tcp(
            51234, 80, "x".toByteArray(),
            seq = 1001, ack = 1, flags = 0x18,
        )
        val frames = pipe(listOf(syn, data))

        val tcp1 = frames[0].layers.first { it.protocol == "TCP" }
        assertEquals("0", tcp1.fields.first { it.name == "Relative Seq" }.value)
        val tcp2 = frames[1].layers.first { it.protocol == "TCP" }
        assertEquals("1", tcp2.fields.first { it.name == "Relative Seq" }.value)
    }

    @Test
    fun `重传同方向同 seq+len 触发 TCP Retransmission`() {
        val data1 = PcapTestFixtures.ethIpv4Tcp(
            51234, 80, "hello".toByteArray(),
            seq = 100, ack = 1, flags = 0x18,
        )
        val data2 = PcapTestFixtures.ethIpv4Tcp(
            51234, 80, "hello".toByteArray(),
            seq = 100, ack = 1, flags = 0x18,
        )
        val frames = pipe(listOf(data1, data2))

        val tcp1 = frames[0].layers.first { it.protocol == "TCP" }
        val tcp2 = frames[1].layers.first { it.protocol == "TCP" }

        assertFalse("第一次出现不应是重传",
            tcp1.fields.any { it.name == "TCP Analysis" })
        assertEquals("TCP Retransmission",
            tcp2.fields.first { it.name == "TCP Analysis" }.value)
        assertTrue("summary 末尾应有重传标签：${tcp2.summary}",
            tcp2.summary!!.contains("[TCP Retransmission]"))
    }

    @Test
    fun `不同 seq 不算重传`() {
        val data1 = PcapTestFixtures.ethIpv4Tcp(
            51234, 80, "first".toByteArray(),
            seq = 100, ack = 1, flags = 0x18,
        )
        val data2 = PcapTestFixtures.ethIpv4Tcp(
            51234, 80, "secnd".toByteArray(),
            seq = 105, ack = 1, flags = 0x18,
        )
        val frames = pipe(listOf(data1, data2))
        assertFalse(frames.any { f ->
            f.layers.any { it.protocol == "TCP" } &&
                f.layers.first { it.protocol == "TCP" }
                    .fields.any { it.name == "TCP Analysis" }
        })
    }

    @Test
    fun `无 SYN 时退化为第一包 seq 作 ISN`() {
        // mid-stream PCAP，没看到 SYN
        val data1 = PcapTestFixtures.ethIpv4Tcp(
            51234, 80, "x".toByteArray(),
            seq = 5000, ack = 100, flags = 0x18,
        )
        val data2 = PcapTestFixtures.ethIpv4Tcp(
            51234, 80, "y".toByteArray(),
            seq = 5001, ack = 100, flags = 0x18,
        )
        val frames = pipe(listOf(data1, data2))
        val tcp1 = frames[0].layers.first { it.protocol == "TCP" }
        val tcp2 = frames[1].layers.first { it.protocol == "TCP" }
        assertEquals("0", tcp1.fields.first { it.name == "Relative Seq" }.value)
        assertEquals("1", tcp2.fields.first { it.name == "Relative Seq" }.value)
    }

    private fun pipe(packets: List<ByteArray>): List<Frame> {
        val pcap = PcapTestFixtures.build(linkType = 1, packets = packets)
        return PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            val raw = reader.frames().map(pipeline::process).toList()
            TcpSessionAnalyzer.process(raw)
        }
    }
}
