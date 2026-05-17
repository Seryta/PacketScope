package io.github.packetscope.core.decrypt

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class SslKeyLogParserTest {

    @Test
    fun `解析 NSS Key Log 三行`() {
        val log = (
            "# this is a comment\n" +
            "\n" +
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET " +
            "0".repeat(64) + " " + "a".repeat(64) + "\n" +
            "SERVER_HANDSHAKE_TRAFFIC_SECRET " +
            "0".repeat(64) + " " + "b".repeat(64) + "\n" +
            "CLIENT_TRAFFIC_SECRET_0 " +
            "0".repeat(64) + " " + "c".repeat(64) + "\n"
        )
        val entries = SslKeyLogParser.parse(ByteArrayInputStream(log.toByteArray()))
        assertEquals(3, entries.size)
        assertEquals("CLIENT_HANDSHAKE_TRAFFIC_SECRET", entries[0].label)
        assertEquals(32, entries[0].clientRandom.size)
        assertEquals(32, entries[0].secret.size)
    }

    @Test
    fun `忽略坏行 不抛异常`() {
        val log = (
            "GARBAGE\n" +
            "TOO_FEW_FIELDS abc\n" +
            "NOT_HEX zzz xxx\n" +
            "ODD_LENGTH " + "0".repeat(63) + " " + "a".repeat(64) + "\n" +
            "WRONG_RANDOM_LEN " + "0".repeat(60) + " " + "a".repeat(64) + "\n" +
            "GOOD CLIENT_TRAFFIC_SECRET_0\n"  // 列数不对，会被跳过
        )
        val entries = SslKeyLogParser.parse(ByteArrayInputStream(log.toByteArray()))
        assertTrue("不应解析出任何 entry", entries.isEmpty())
    }

    @Test
    fun `KeyLogStore 按 random 索引`() {
        val random = ByteArray(32) { 0x42 }
        val entry = KeyLogEntry("CLIENT_TRAFFIC_SECRET_0", random, ByteArray(32) { 0x77 })
        KeyLogStore.load(listOf(entry), "test.txt")
        assertEquals(1, KeyLogStore.sessionCount.intValue)
        assertEquals("test.txt", KeyLogStore.fileName.value)

        val secrets = KeyLogStore.lookup(random)
        assertEquals(1, secrets!!.size)
        assertEquals(32, secrets["CLIENT_TRAFFIC_SECRET_0"]!!.size)

        KeyLogStore.clear()
        assertEquals(0, KeyLogStore.sessionCount.intValue)
    }
}
