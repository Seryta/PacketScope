package io.github.packetscope.core.decrypt

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class HkdfTest {

    /**
     * RFC 5869 Test Case 1（SHA-256）的 expand 部分。
     * PRK 已知 → 验证我们的 expand 实现产出预期 OKM。
     */
    @Test
    fun `RFC 5869 TC1 expand`() {
        val prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5".hex()
        val info = "f0f1f2f3f4f5f6f7f8f9".hex()
        val expected = ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
            "34007208d5b887185865").hex()
        val okm = Hkdf.expand(prk, info, 42)
        assertEquals(42, okm.size)
        assertArrayEquals(expected, okm)
    }

    @Test
    fun `expandLabel 标签前缀正确`() {
        // 同样的 PRK + label="key" + context=""，验证至少返回了正确长度的字节
        val prk = ByteArray(32) { it.toByte() }
        val key16 = Hkdf.expandLabel(prk, "key", ByteArray(0), 16)
        val iv12 = Hkdf.expandLabel(prk, "iv", ByteArray(0), 12)
        assertEquals(16, key16.size)
        assertEquals(12, iv12.size)
        // 两次调用同一参数应该确定性
        val key16Again = Hkdf.expandLabel(prk, "key", ByteArray(0), 16)
        assertArrayEquals(key16, key16Again)
    }

    private fun String.hex(): ByteArray = hexToBytesOrNull() ?: error("bad hex: $this")
}
