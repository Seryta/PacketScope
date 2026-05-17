package io.github.packetscope.core.decrypt

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * TLS 1.2 AES-GCM 自洽性测试：用 javax.crypto 按 RFC 5288 规则加密一段已知明文，
 * 验证 [Tls12Decryptor] 用同一 master_secret + randoms + cipher suite 派生的
 * key/iv 能正确解出。
 *
 * AEAD record layout: explicit_nonce(8) || encrypted || tag(16)
 * nonce = implicit_iv(4) || explicit_nonce(8)
 * AAD   = seq(8) || content_type(1) || version(2) || plaintext_length(2)
 */
class Tls12DecryptorTest {

    private val masterSecret = ByteArray(48) { (it * 5 + 7).toByte() }
    private val clientRandom = ByteArray(32) { (it * 3).toByte() }
    private val serverRandom = ByteArray(32) { (it * 11 + 1).toByte() }

    @Test
    fun `AES_128_GCM roundtrip first record`() {
        val cipher = 0xC02F  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        roundtripOnce(cipher, "GET / HTTP/1.1\r\n\r\n".toByteArray())
    }

    @Test
    fun `AES_256_GCM SHA384 roundtrip`() {
        val cipher = 0xC030  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        roundtripOnce(cipher, "Hello TLS 1.2".toByteArray())
    }

    @Test
    fun `连续多条 record seq 自增`() {
        val cipher = 0xC02F
        val dec = Tls12Decryptor.forDirection(
            masterSecret, clientRandom, serverRandom, cipher, isClient = true,
        )!!
        val (key, iv) = deriveKeyIv(cipher, isClient = true)

        val p0 = "first".toByteArray()
        val p1 = "second message".toByteArray()
        val r0 = encrypt(key, iv, 0, p0, contentType = 23, version = 0x0303)
        val r1 = encrypt(key, iv, 1, p1, contentType = 23, version = 0x0303)
        val out0 = dec.decryptNext(23, 0x0303, r0)
        val out1 = dec.decryptNext(23, 0x0303, r1)
        assertArrayEquals(p0, out0)
        assertArrayEquals(p1, out1)
    }

    @Test
    fun `wrong cipher returns null decryptor`() {
        val cipher = 0xDEAD  // 未知 cipher suite
        val dec = Tls12Decryptor.forDirection(
            masterSecret, clientRandom, serverRandom, cipher, isClient = true,
        )
        assertNull(dec)
    }

    @Test
    fun `auth failure returns null`() {
        val cipher = 0xC02F
        val dec = Tls12Decryptor.forDirection(
            masterSecret, clientRandom, serverRandom, cipher, isClient = true,
        )!!
        val (key, iv) = deriveKeyIv(cipher, isClient = true)
        val plaintext = "tamper me".toByteArray()
        val record = encrypt(key, iv, 0, plaintext, contentType = 23, version = 0x0303)
        // 翻转一字节让 GCM tag 失败
        record[record.size - 1] = (record[record.size - 1].toInt() xor 0x01).toByte()
        assertNull(dec.decryptNext(23, 0x0303, record))
    }

    /** 复制 [Tls12Decryptor.forDirection] 的派生逻辑用于构造 fixture */
    private fun deriveKeyIv(cipherSuite: Int, isClient: Boolean): Pair<ByteArray, ByteArray> {
        val params = Tls12CipherParams.of(cipherSuite)!!
        val seed = serverRandom + clientRandom
        val keyBlockLen = 2 * params.keyLen + 2 * params.fixedIvLen
        val keyBlock = when (params.hashAlg) {
            "SHA256" -> Tls12Prf.prfSha256(masterSecret, "key expansion", seed, keyBlockLen)
            "SHA384" -> Tls12Prf.prfSha384(masterSecret, "key expansion", seed, keyBlockLen)
            else -> error("hash $params")
        }
        var pos = 0
        val clientKey = keyBlock.copyOfRange(pos, pos + params.keyLen); pos += params.keyLen
        val serverKey = keyBlock.copyOfRange(pos, pos + params.keyLen); pos += params.keyLen
        val clientIv = keyBlock.copyOfRange(pos, pos + params.fixedIvLen); pos += params.fixedIvLen
        val serverIv = keyBlock.copyOfRange(pos, pos + params.fixedIvLen)
        return if (isClient) clientKey to clientIv else serverKey to serverIv
    }

    /**
     * AES-GCM 加密构造 TLS 1.2 record body（不含 5 字节 record header）。
     *
     * @return explicit_nonce(8) || encrypted_data || tag(16)
     */
    private fun encrypt(
        key: ByteArray, implicitIv: ByteArray, seq: Long, plaintext: ByteArray,
        contentType: Int, version: Int,
    ): ByteArray {
        // explicit_nonce 通常 = seq num，但只要双方约定即可；这里直接用 seq
        val explicitNonce = ByteArray(8)
        for (i in 0 until 8) {
            explicitNonce[i] = ((seq ushr ((7 - i) * 8)) and 0xFF).toByte()
        }
        val nonce = implicitIv + explicitNonce
        val aad = ByteArray(13)
        for (i in 0 until 8) aad[i] = explicitNonce[i]
        aad[8] = contentType.toByte()
        aad[9] = (version ushr 8).toByte()
        aad[10] = (version and 0xFF).toByte()
        aad[11] = (plaintext.size ushr 8).toByte()
        aad[12] = (plaintext.size and 0xFF).toByte()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        val ct = cipher.doFinal(plaintext)
        return explicitNonce + ct
    }

    private fun roundtripOnce(cipher: Int, plaintext: ByteArray) {
        val dec = Tls12Decryptor.forDirection(
            masterSecret, clientRandom, serverRandom, cipher, isClient = true,
        )
        assertNotNull(dec)
        val (key, iv) = deriveKeyIv(cipher, isClient = true)
        val body = encrypt(key, iv, 0, plaintext, contentType = 23, version = 0x0303)
        val out = dec!!.decryptNext(23, 0x0303, body)
        assertArrayEquals(plaintext, out)
    }

    @Test
    fun `ChaCha20_Poly1305 roundtrip`() {
        // 0xCCA8 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        val cipher = 0xCCA8
        val dec = Tls12Decryptor.forDirection(
            masterSecret, clientRandom, serverRandom, cipher, isClient = true,
        )
        assertNotNull(dec)
        val (key, iv) = deriveKeyIv(cipher, isClient = true)
        val plaintext = "Hello over ChaCha20-Poly1305".toByteArray()
        val body = encryptChaCha(key, iv, seq = 0, plaintext, contentType = 23, version = 0x0303)
        val out = dec!!.decryptNext(23, 0x0303, body)
        assertArrayEquals(plaintext, out)
    }

    /** ChaCha20-Poly1305 加密构造 record body（无 explicit_nonce） */
    private fun encryptChaCha(
        key: ByteArray, fixedIv: ByteArray, seq: Long, plaintext: ByteArray,
        contentType: Int, version: Int,
    ): ByteArray {
        val nonce = fixedIv.copyOf()
        for (i in 0 until 8) {
            val b = ((seq ushr ((7 - i) * 8)) and 0xFF).toInt()
            nonce[4 + i] = (nonce[4 + i].toInt() xor b).toByte()
        }
        val aad = ByteArray(13)
        for (i in 0 until 8) aad[i] = ((seq ushr ((7 - i) * 8)) and 0xFF).toByte()
        aad[8] = contentType.toByte()
        aad[9] = (version ushr 8).toByte()
        aad[10] = (version and 0xFF).toByte()
        aad[11] = (plaintext.size ushr 8).toByte()
        aad[12] = (plaintext.size and 0xFF).toByte()
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "ChaCha20"),
            javax.crypto.spec.IvParameterSpec(nonce),
        )
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    @Test
    fun `client and server derive different keys`() {
        val cipher = 0xC02F
        val (cKey, cIv) = deriveKeyIv(cipher, isClient = true)
        val (sKey, sIv) = deriveKeyIv(cipher, isClient = false)
        assertEquals(16, cKey.size)
        assertEquals(4, cIv.size)
        // sanity：client/server 派生不同
        assertNotNull(cKey)
        assertNotNull(sKey)
        assert(!cKey.contentEquals(sKey))
        assert(!cIv.contentEquals(sIv))
    }
}
