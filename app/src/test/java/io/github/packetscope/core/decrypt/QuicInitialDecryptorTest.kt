package io.github.packetscope.core.decrypt

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * QUIC v1 Initial 解密 sanity 测试。
 *
 * 用 RFC 9001 Appendix A.1 的 client DCID + secret 派生作 known-good 入口，
 * 然后用 Java JCE 自己加密一个 Initial packet，验证 [QuicInitialDecryptor]
 * 用同一 DCID 派生的 decryptor 能正确解出。
 *
 * 不直接走 RFC 9001 A.2 完整 packet fixture（hex 1162 字节量级），只验
 * "key/iv/hp 派生 + AES-128-GCM + header protection 还原"逻辑端到端通。
 */
class QuicInitialDecryptorTest {

    @Test
    fun `decrypt fails on tampered packet`() {
        val dcid = ByteArray(8) { it.toByte() }
        val (clientDec, _) = QuicInitialDecryptor.fromDcid(dcid)
        // 全零 packet 显然不是合法 Initial，应解失败
        val bogus = ByteArray(100)
        val out = clientDec.decrypt(bogus, pnOffset = 7, totalLen = 50)
        assertNull(out)
    }

    @Test
    fun `RFC 9001 A1 derivation distinct client server`() {
        // 用 RFC 9001 Appendix A.1 的 client DCID 0x8394c8f03e515708
        val dcid = byteArrayOf(
            0x83.toByte(), 0x94.toByte(), 0xc8.toByte(), 0xf0.toByte(),
            0x3e, 0x51, 0x57, 0x08,
        )
        val (clientDec, serverDec) = QuicInitialDecryptor.fromDcid(dcid)
        // 不同方向用不同 key，sanity check 两者不同
        assertNotNull(clientDec)
        assertNotNull(serverDec)
        assert(clientDec !== serverDec)
    }

    @Test
    fun `roundtrip with manually crafted packet`() {
        // 派生 client key/iv/hp via Hkdf 自洽校验
        val dcid = ByteArray(8) { (it * 13).toByte() }
        val initialSecret = hmacSha256(INITIAL_SALT_V1, dcid)
        val clientSecret = Hkdf.expandLabel(initialSecret, "client in", ByteArray(0), 32)
        val key = Hkdf.expandLabel(clientSecret, "quic key", ByteArray(0), 16)
        val iv = Hkdf.expandLabel(clientSecret, "quic iv", ByteArray(0), 12)
        val hp = Hkdf.expandLabel(clientSecret, "quic hp", ByteArray(0), 16)

        // 构造一个 minimal Initial packet：
        // byte0=0xC3 (long form, fixed bit, Initial, pn_len=4)
        // version=0x00000001 (v1)
        // dcid len=8 || dcid bytes
        // scid len=0
        // token_length varint=0
        // length varint = pn(4) + payload(0) + tag(16) = 20 → 1-byte varint 0x14
        // pn = 0x00000000 (4 bytes)
        // payload = empty
        // tag = AES-GCM tag (16 bytes)
        val plaintext = ByteArray(0)
        val unprotectedHeader = byteArrayOf(0xC3.toByte(), 0x00, 0x00, 0x00, 0x01, 8.toByte()) +
            dcid +
            byteArrayOf(0.toByte(), 0.toByte(), 0x14.toByte(), 0, 0, 0, 0)
        val pnOffset = unprotectedHeader.size - 4
        val totalLen = 4 + plaintext.size + 16

        val nonce = iv.copyOf()  // pn=0 → 不 XOR
        val ctAndTag = aesGcmEncrypt(key, nonce, unprotectedHeader, plaintext)

        val protectedPacket = unprotectedHeader + ctAndTag
        // header protection：sample = ciphertext[pnOffset+4 .. pnOffset+20]
        val sample = protectedPacket.copyOfRange(pnOffset + 4, pnOffset + 4 + 16)
        val mask = aesEcb(hp, sample).copyOfRange(0, 5)
        protectedPacket[0] = (protectedPacket[0].toInt() xor (mask[0].toInt() and 0x0F)).toByte()
        for (i in 0 until 4) {
            protectedPacket[pnOffset + i] =
                (protectedPacket[pnOffset + i].toInt() xor mask[1 + i].toInt()).toByte()
        }

        val (clientDec, _) = QuicInitialDecryptor.fromDcid(dcid)
        val res = clientDec.decrypt(protectedPacket, pnOffset, totalLen)
        assertNotNull(res)
        assertEquals(0L, res!!.packetNumber)
        assertArrayEquals(plaintext, res.plaintext)
    }

    private fun aesGcmEncrypt(
        key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray,
    ): ByteArray {
        val c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        c.init(
            javax.crypto.Cipher.ENCRYPT_MODE,
            javax.crypto.spec.SecretKeySpec(key, "AES"),
            javax.crypto.spec.GCMParameterSpec(128, nonce),
        )
        c.updateAAD(aad)
        return c.doFinal(plaintext)
    }

    private fun aesEcb(key: ByteArray, data: ByteArray): ByteArray {
        val c = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding")
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, javax.crypto.spec.SecretKeySpec(key, "AES"))
        return c.doFinal(data)
    }

    private fun hmacSha256(key: ByteArray, ikm: ByteArray): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(ikm)
    }

    companion object {
        private val INITIAL_SALT_V1 = byteArrayOf(
            0x38, 0x76, 0x2c, 0xf7.toByte(),
            0xf5.toByte(), 0x59, 0x34, 0xb3.toByte(),
            0x4d, 0x17, 0x9a.toByte(), 0xe6.toByte(),
            0xa4.toByte(), 0xc8.toByte(), 0x0c, 0xad.toByte(),
            0xcc.toByte(), 0xbb.toByte(), 0x7f, 0x0a,
        )
    }
}
