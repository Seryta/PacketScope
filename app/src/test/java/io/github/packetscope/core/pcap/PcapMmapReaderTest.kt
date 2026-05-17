package io.github.packetscope.core.pcap

import io.github.packetscope.core.PcapTestFixtures
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.RandomAccessFile

/**
 * PcapMmapReader 与 PcapReader 必须解出完全一致的 RawFrame 序列——只是 IO 路径
 * 不同。
 */
class PcapMmapReaderTest {

    @get:Rule val tmp = TemporaryFolder()

    @Test
    fun `mmap path 解析与 InputStream path 一致`() {
        val pcap = PcapTestFixtures.build(
            linkType = 1,
            packets = listOf(
                PcapTestFixtures.ethernetIpv4TcpSyn(),
                PcapTestFixtures.ethIpv4Tcp(
                    srcPort = 51234, dstPort = 80,
                    seq = 1, payload = "GET / HTTP/1.1\r\n\r\n".toByteArray(),
                ),
                PcapTestFixtures.ethIpv4Udp(
                    srcPort = 1000, dstPort = 53, payload = "x".toByteArray(),
                ),
            ),
        )
        val file = tmp.newFile("test.pcap")
        file.writeBytes(pcap)

        val streamFrames = PcapReader(file.inputStream()).use { r ->
            r.linkType to r.frames().toList()
        }
        val mmapFrames = RandomAccessFile(file, "r").use { raf ->
            PcapMmapReader(raf.channel).use { r ->
                r.linkType to r.frames().toList()
            }
        }

        assertEquals(streamFrames.first, mmapFrames.first)  // linkType 一致
        assertEquals(streamFrames.second.size, mmapFrames.second.size)
        streamFrames.second.zip(mmapFrames.second).forEachIndexed { i, (s, m) ->
            assertEquals("frame $i index", s.index, m.index)
            assertEquals("frame $i caplen", s.capturedLength, m.capturedLength)
            assertEquals("frame $i origlen", s.originalLength, m.originalLength)
            assertEquals("frame $i ts", s.timestampNanos, m.timestampNanos)
            assertTrue("frame $i data", s.data.contentEquals(m.data))
        }
    }

    @Test
    fun `mmap path 识别 big-endian magic`() {
        val pcap = PcapTestFixtures.build(
            linkType = 1,
            packets = listOf(PcapTestFixtures.ethernetIpv4TcpSyn()),
            littleEndian = false,
        )
        val file = tmp.newFile("be.pcap")
        file.writeBytes(pcap)
        RandomAccessFile(file, "r").use { raf ->
            PcapMmapReader(raf.channel).use { r ->
                assertEquals(LinkType.ETHERNET, r.linkType)
                val frames = r.frames().toList()
                assertEquals(1, frames.size)
            }
        }
    }

    @Test
    fun `mmap path 识别 nano magic`() {
        val pcap = PcapTestFixtures.build(
            linkType = 1,
            packets = listOf(PcapTestFixtures.ethernetIpv4TcpSyn()),
            nanoseconds = true,
        )
        val file = tmp.newFile("nano.pcap")
        file.writeBytes(pcap)
        RandomAccessFile(file, "r").use { raf ->
            PcapMmapReader(raf.channel).use { r ->
                val frame = r.frames().toList().first()
                assertNotNull(frame)
            }
        }
    }
}
