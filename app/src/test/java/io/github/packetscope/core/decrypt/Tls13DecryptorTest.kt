package io.github.packetscope.core.decrypt

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 自洽性测试：用 javax.crypto AES-GCM 按 TLS 1.3 规则加密一段已知明文，
 * 验证 Tls13Decryptor 用相同 secret 能正确解出来。
 */
class Tls13DecryptorTest {

    @Test
    fun `roundtrip 第一条 record`() {
        val secret = ByteArray(32) { (it * 7).toByte() }
        val dec = Tls13Decryptor.forDirection(secret)

        // 模拟一条 ApplicationData：inner plaintext = "GET / HTTP/1.1\r\n" + ContentType(23)
        val realData = "GET / HTTP/1.1\r\n".toByteArray()
        val inner = realData + byteArrayOf(23)  // ContentType = ApplicationData

        // 用同一 secret 派生 key/iv（重复 Tls13Decryptor 内部逻辑）
        val key = Hkdf.expandLabel(secret, "key", ByteArray(0), 16)
        val iv = Hkdf.expandLabel(secret, "iv", ByteArray(0), 12)

        // seq = 0 → nonce = iv
        val record = encrypt(key, iv, seq = 0, plaintext = inner)
        val header = record.copyOfRange(0, 5)
        val ciphertext = record.copyOfRange(5, record.size)

        val outerPlain = dec.decryptNext(header, ciphertext)
        assertNotNull(outerPlain)
        val unwrapped = dec.unwrapInnerPlaintext(outerPlain!!)
        assertNotNull(unwrapped)
        assertEquals(23, unwrapped!!.contentType)
        assertArrayEquals(realData, unwrapped.data)
    }

    @Test
    fun `连续两条 record seq 自增`() {
        val secret = ByteArray(32) { (it + 1).toByte() }
        val dec = Tls13Decryptor.forDirection(secret)
        val key = Hkdf.expandLabel(secret, "key", ByteArray(0), 16)
        val iv = Hkdf.expandLabel(secret, "iv", ByteArray(0), 12)

        val r0 = encrypt(key, iv, 0, "first".toByteArray() + byteArrayOf(23))
        val r1 = encrypt(key, iv, 1, "second".toByteArray() + byteArrayOf(23))

        val p0 = dec.decryptNext(r0.copyOfRange(0, 5), r0.copyOfRange(5, r0.size))
        val p1 = dec.decryptNext(r1.copyOfRange(0, 5), r1.copyOfRange(5, r1.size))

        assertArrayEquals("first".toByteArray(), dec.unwrapInnerPlaintext(p0!!)!!.data)
        assertArrayEquals("second".toByteArray(), dec.unwrapInnerPlaintext(p1!!)!!.data)
    }

    @Test
    fun `key 不匹配返回 null`() {
        val secret = ByteArray(32) { it.toByte() }
        val wrongSecret = ByteArray(32) { (it + 100).toByte() }
        val dec = Tls13Decryptor.forDirection(wrongSecret)

        val key = Hkdf.expandLabel(secret, "key", ByteArray(0), 16)
        val iv = Hkdf.expandLabel(secret, "iv", ByteArray(0), 12)
        val record = encrypt(key, iv, 0, "x".toByteArray() + byteArrayOf(23))

        val plaintext = dec.decryptNext(record.copyOfRange(0, 5),
            record.copyOfRange(5, record.size))
        assertNull(plaintext)
    }

    @Test
    fun `AES_256_GCM SHA384 cipher roundtrip`() {
        // 0x1302 TLS_AES_256_GCM_SHA384 — secret 长度 48 (SHA-384)
        val secret = ByteArray(48) { (it * 3 + 5).toByte() }
        val dec = Tls13Decryptor.forDirection(secret, cipherSuite = 0x1302)
        val key = Hkdf.expandLabel(secret, "key", ByteArray(0), 32, Hkdf.Hash.SHA384)
        val iv = Hkdf.expandLabel(secret, "iv", ByteArray(0), 12, Hkdf.Hash.SHA384)

        val inner = "AES256".toByteArray() + byteArrayOf(23)
        val record = encryptAesGcm(key, iv, 0, inner)
        val out = dec.decryptNext(record.copyOfRange(0, 5), record.copyOfRange(5, record.size))
        assertNotNull(out)
        assertArrayEquals("AES256".toByteArray(), dec.unwrapInnerPlaintext(out!!)!!.data)
    }

    @Test
    fun `ChaCha20_Poly1305 cipher roundtrip`() {
        // 0x1303 TLS_CHACHA20_POLY1305_SHA256 — secret 长度 32 (SHA-256)
        val secret = ByteArray(32) { (it + 17).toByte() }
        val dec = Tls13Decryptor.forDirection(secret, cipherSuite = 0x1303)
        val key = Hkdf.expandLabel(secret, "key", ByteArray(0), 32, Hkdf.Hash.SHA256)
        val iv = Hkdf.expandLabel(secret, "iv", ByteArray(0), 12, Hkdf.Hash.SHA256)

        val inner = "Hello TLS 1.3 ChaCha".toByteArray() + byteArrayOf(23)
        val record = encryptChaCha(key, iv, 0, inner)
        val out = dec.decryptNext(record.copyOfRange(0, 5), record.copyOfRange(5, record.size))
        assertNotNull(out)
        assertArrayEquals(
            "Hello TLS 1.3 ChaCha".toByteArray(),
            dec.unwrapInnerPlaintext(out!!)!!.data,
        )
    }

    private fun encryptAesGcm(
        key: ByteArray, iv: ByteArray, seq: Long, plaintext: ByteArray,
    ): ByteArray {
        val nonce = iv.copyOf()
        for (i in 0 until 8) {
            val b = ((seq ushr ((7 - i) * 8)) and 0xFF).toInt()
            nonce[4 + i] = (nonce[4 + i].toInt() xor b).toByte()
        }
        val ctLen = plaintext.size + 16
        val header = byteArrayOf(
            23, 3, 3,
            ((ctLen ushr 8) and 0xFF).toByte(), (ctLen and 0xFF).toByte(),
        )
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(header)
        return header + cipher.doFinal(plaintext)
    }

    private fun encryptChaCha(
        key: ByteArray, iv: ByteArray, seq: Long, plaintext: ByteArray,
    ): ByteArray {
        val nonce = iv.copyOf()
        for (i in 0 until 8) {
            val b = ((seq ushr ((7 - i) * 8)) and 0xFF).toInt()
            nonce[4 + i] = (nonce[4 + i].toInt() xor b).toByte()
        }
        val ctLen = plaintext.size + 16
        val header = byteArrayOf(
            23, 3, 3,
            ((ctLen ushr 8) and 0xFF).toByte(), (ctLen and 0xFF).toByte(),
        )
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        cipher.updateAAD(header)
        return header + cipher.doFinal(plaintext)
    }

    /**
     * 复制 TLS 1.3 AEAD 加密逻辑用于构造 fixture。
     * 返回完整 record（5 字节 header + ciphertext + 16 字节 tag）。
     */
    private fun encrypt(key: ByteArray, iv: ByteArray, seq: Long, plaintext: ByteArray): ByteArray {
        val nonce = iv.copyOf()
        for (i in 0 until 8) {
            val b = ((seq ushr ((7 - i) * 8)) and 0xFF).toInt()
            nonce[4 + i] = (nonce[4 + i].toInt() xor b).toByte()
        }
        val ctLen = plaintext.size + 16  // + tag
        val header = byteArrayOf(
            23, 3, 3,  // ApplicationData / TLS 1.2 legacy version
            ((ctLen ushr 8) and 0xFF).toByte(), (ctLen and 0xFF).toByte(),
        )
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(header)
        val ct = cipher.doFinal(plaintext)
        return header + ct
    }
}
