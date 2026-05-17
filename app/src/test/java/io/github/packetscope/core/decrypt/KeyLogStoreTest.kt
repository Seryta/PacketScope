package io.github.packetscope.core.decrypt

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * review v0.6-round3 F-002：load 替换 keylog 时也必须 fill(0) 旧 secret。
 * round2 F-008 只测了 clear() 路径，本轮覆盖 load 路径。
 */
class KeyLogStoreTest {

    @After
    fun cleanup() = KeyLogStore.clear()

    @Test
    fun `load 替换旧 keylog 后旧 secret 被 fill(0)`() {
        val secretA = ByteArray(32) { 0xAA.toByte() }
        val entryA = KeyLogEntry(
            label = "CLIENT_TRAFFIC_SECRET_0",
            clientRandom = ByteArray(32) { 0x11.toByte() },
            secret = secretA,
        )
        KeyLogStore.load(listOf(entryA), "a.log")
        // secretA 持有的引用进了 byRandom
        assertEquals(1, KeyLogStore.sessionCount.intValue)

        // 第二次 load 完全不同的 keylog
        val entryB = KeyLogEntry(
            label = "CLIENT_TRAFFIC_SECRET_0",
            clientRandom = ByteArray(32) { 0x22.toByte() },
            secret = ByteArray(32) { 0xBB.toByte() },
        )
        KeyLogStore.load(listOf(entryB), "b.log")

        // 关键断言：load 重复用 clear()，secretA 应已被擦零
        assertTrue("旧 secret 必须 fill(0) 而非仅 drop reference",
            secretA.all { it == 0.toByte() })

        // 新 keylog 已就位
        assertEquals(1, KeyLogStore.sessionCount.intValue)
        assertEquals("b.log", KeyLogStore.fileName.value)
    }

    @Test
    fun `clear 重置 sessionCount 与 fileName`() {
        val entry = KeyLogEntry(
            label = "L",
            clientRandom = ByteArray(32),
            secret = ByteArray(32) { 0xCC.toByte() },
        )
        KeyLogStore.load(listOf(entry), "x.log")
        assertEquals(1, KeyLogStore.sessionCount.intValue)
        assertNotNull(KeyLogStore.fileName.value)

        KeyLogStore.clear()
        assertEquals(0, KeyLogStore.sessionCount.intValue)
        assertNull(KeyLogStore.fileName.value)
        assertFalse(KeyLogStore.isLoaded)
    }
}
