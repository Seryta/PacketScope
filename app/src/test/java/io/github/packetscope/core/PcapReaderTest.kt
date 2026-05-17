package io.github.packetscope.core

import io.github.packetscope.core.pcap.LinkType
import io.github.packetscope.core.pcap.PcapReader
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.IOException

class PcapReaderTest {

    @Test
    fun `读取 little-endian 微秒 PCAP 的全局头`() {
        val bytes = PcapTestFixtures.build(
            linkType = 1,
            packets = emptyList(),
            littleEndian = true,
            nanoseconds = false,
        )
        PcapReader(ByteArrayInputStream(bytes)).use { reader ->
            assertEquals(LinkType.ETHERNET, reader.linkType)
            assertEquals(65535, reader.snaplen)
            assertEquals(0, reader.frames().toList().size)
        }
    }

    @Test
    fun `读取 big-endian 纳秒 PCAP 的全局头`() {
        val bytes = PcapTestFixtures.build(
            linkType = 113,
            packets = emptyList(),
            littleEndian = false,
            nanoseconds = true,
        )
        PcapReader(ByteArrayInputStream(bytes)).use { reader ->
            assertEquals(LinkType.LINUX_SLL, reader.linkType)
        }
    }

    @Test
    fun `无法识别的 magic 抛 IOException`() {
        val bytes = ByteArray(24) { 0x00 }
        assertThrows(IOException::class.java) {
            PcapReader(ByteArrayInputStream(bytes))
        }
    }

    @Test
    fun `逐 packet 输出 RawFrame 含完整字节`() {
        val pkt1 = ByteArray(64) { it.toByte() }
        val pkt2 = ByteArray(80) { (it + 100).toByte() }
        val bytes = PcapTestFixtures.build(
            linkType = 1,
            packets = listOf(pkt1, pkt2),
        )
        PcapReader(ByteArrayInputStream(bytes)).use { reader ->
            val frames = reader.frames().toList()
            assertEquals(2, frames.size)
            assertEquals(1, frames[0].index)
            assertEquals(64, frames[0].capturedLength)
            assertEquals(64, frames[0].data.size)
            assertEquals(2, frames[1].index)
            assertEquals(80, frames[1].capturedLength)
        }
    }

    @Test
    fun `截断的尾部 record header 安全终止而不抛错`() {
        // 一个正常 packet + 半个 record header
        val normal = PcapTestFixtures.build(
            linkType = 1,
            packets = listOf(ByteArray(40) { 0x42 }),
        )
        val truncated = normal + byteArrayOf(0x00, 0x00, 0x00)  // 只 3 字节，凑不齐 record header
        PcapReader(ByteArrayInputStream(truncated)).use { reader ->
            val frames = reader.frames().toList()
            assertEquals(1, frames.size)
            assertNotNull(frames[0])
        }
    }
}
