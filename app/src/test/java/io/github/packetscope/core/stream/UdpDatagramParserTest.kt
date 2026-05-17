package io.github.packetscope.core.stream

import io.github.packetscope.core.PcapTestFixtures
import io.github.packetscope.core.pcap.LinkType
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class UdpDatagramParserTest {

    @Test
    fun `LE global header 推断 endian + linkType`() {
        // 复用 PcapTestFixtures.build 的 global header 部分（前 24 字节）
        val pcap = PcapTestFixtures.build(linkType = 101, packets = emptyList(), littleEndian = true)
        val header = pcap.copyOfRange(0, 24)

        val parser = UdpDatagramParser()
        assertFalse(parser.isReady)
        val lt = parser.consumeGlobalHeader(header)
        assertEquals(LinkType.RAW_IP, lt)
        assertEquals(LinkType.RAW_IP, parser.linkType)
        assertTrue(parser.isReady)
    }

    @Test
    fun `BE 纳秒 global header 也能识别`() {
        val pcap = PcapTestFixtures.build(linkType = 1, packets = emptyList(),
            littleEndian = false, nanoseconds = true)
        val parser = UdpDatagramParser()
        assertEquals(LinkType.ETHERNET, parser.consumeGlobalHeader(pcap.copyOfRange(0, 24)))
    }

    @Test
    fun `无法识别的 magic 抛 IOException`() {
        val parser = UdpDatagramParser()
        val bad = ByteArray(24) { 0x00 }
        assertThrows(IOException::class.java) { parser.consumeGlobalHeader(bad) }
    }

    @Test
    fun `global header datagram 太短抛 IOException`() {
        val parser = UdpDatagramParser()
        assertThrows(IOException::class.java) {
            parser.consumeGlobalHeader(ByteArray(20))
        }
    }

    @Test
    fun `LE 微秒 record 解析正确`() {
        val pcap = PcapTestFixtures.build(
            linkType = 101,
            packets = listOf(byteArrayOf(0x45, 0x00, 0x00, 0x14, 0x42, 0x42)),
            littleEndian = true, nanoseconds = false,
        )
        val parser = UdpDatagramParser()
        parser.consumeGlobalHeader(pcap.copyOfRange(0, 24))

        // PCAP 文件里 record 紧跟 global header
        val recordSize = 16 + 6
        val recordBytes = pcap.copyOfRange(24, 24 + recordSize)
        val raw = parser.parseRecord(recordBytes)

        assertEquals(1, raw.index)
        assertEquals(6, raw.capturedLength)
        assertEquals(6, raw.originalLength)
        assertArrayEquals(byteArrayOf(0x45, 0x00, 0x00, 0x14, 0x42, 0x42), raw.data.asByteArray())
    }

    @Test
    fun `index 自增`() {
        val pcap = PcapTestFixtures.build(
            linkType = 101,
            packets = listOf(byteArrayOf(0x01), byteArrayOf(0x02), byteArrayOf(0x03)),
        )
        val parser = UdpDatagramParser()
        parser.consumeGlobalHeader(pcap.copyOfRange(0, 24))

        val recordSize = 17  // 16 + 1 body
        val r1 = parser.parseRecord(pcap.copyOfRange(24, 24 + recordSize))
        val r2 = parser.parseRecord(pcap.copyOfRange(24 + recordSize, 24 + 2 * recordSize))
        val r3 = parser.parseRecord(pcap.copyOfRange(24 + 2 * recordSize, 24 + 3 * recordSize))
        assertEquals(1, r1.index)
        assertEquals(2, r2.index)
        assertEquals(3, r3.index)
    }

    @Test
    fun `先 parseRecord 没读 global header 抛 IllegalStateException`() {
        val parser = UdpDatagramParser()
        assertThrows(IllegalStateException::class.java) {
            parser.parseRecord(ByteArray(16))
        }
    }

    @Test
    fun `record body 超出 datagram 抛 IOException`() {
        val pcap = PcapTestFixtures.build(linkType = 101, packets = emptyList())
        val parser = UdpDatagramParser()
        parser.consumeGlobalHeader(pcap.copyOfRange(0, 24))

        // 构造一个 record header 声称 100 字节 body 但实际 datagram 只有 16+5 字节
        val record = ByteArray(21)
        // ts_sec/ts_usec = 0
        // incl_len = 100 (LE: 64 00 00 00)
        record[8] = 0x64
        // orig_len = 100
        record[12] = 0x64
        assertThrows(IOException::class.java) { parser.parseRecord(record) }
    }
}
