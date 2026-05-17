package io.github.packetscope.core.decrypt

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * TLS 1.2 ApplicationData 解密。支持 cipher suites:
 *   AES-GCM (RFC 5288):
 *     0xC02F TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 *     0xC02B TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 *     0x009C TLS_RSA_WITH_AES_128_GCM_SHA256
 *     0xC030 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 *     0xC02C TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 *     0x009D TLS_RSA_WITH_AES_256_GCM_SHA384
 *   ChaCha20-Poly1305 (RFC 7905):
 *     0xCCA8 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
 *     0xCCA9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
 *     0xCCAA TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
 *
 * AEAD 不同 cipher 的 nonce 派生 + record layout 不同：
 *
 *   AES-GCM:
 *     record_body = explicit_nonce(8) || encrypted || tag(16)
 *     nonce       = implicit_iv(4) || explicit_nonce(8)
 *
 *   ChaCha20-Poly1305:
 *     record_body = encrypted || tag(16)   (无 explicit_nonce)
 *     nonce       = implicit_iv(12) XOR (seq padded 到 8 bytes on the right)
 *
 * 两种 cipher 的 AAD 相同（RFC 5246 / RFC 7905 一致）:
 *     AAD = seq(8) || content_type(1) || version(2) || plaintext_len(2)
 *
 * 用法：每个方向用 [forDirection] 派生一个 [Tls12Decryptor]，按时间顺序对每条
 * ApplicationData 调 [decryptNext]。内部维护 sequence number。
 */
class Tls12Decryptor private constructor(
    private val key: ByteArray,
    // 4 字节（AES-GCM 走 implicit_iv + record explicit_nonce）
    // 或 12 字节（ChaCha20-Poly1305 直接当 fixed_iv）—— decryptAead 用
    // fixedIv.size 分派，不再需要单独的 cipherSuite 标识。
    private val fixedIv: ByteArray,
) {
    private var seq: Long = 0L

    fun decryptNext(contentType: Int, version: Int, recordBody: ByteArray): ByteArray? {
        val plaintext = try {
            decryptAead(contentType, version, recordBody) ?: return null
        } catch (_: AEADBadTagException) {
            return null
        } catch (_: Exception) {
            return null
        }
        seq++
        return plaintext
    }

    private fun decryptAead(
        contentType: Int, version: Int, recordBody: ByteArray,
    ): ByteArray? = when (fixedIv.size) {
        4 -> decryptAesGcm(contentType, version, recordBody)
        12 -> decryptChaChaPoly(contentType, version, recordBody)
        else -> null
    }

    private fun decryptAesGcm(contentType: Int, version: Int, recordBody: ByteArray): ByteArray? {
        if (recordBody.size < 8 + 16) return null
        val nonce = ByteArray(12)
        System.arraycopy(fixedIv, 0, nonce, 0, 4)
        System.arraycopy(recordBody, 0, nonce, 4, 8)
        val ciphertext = recordBody.copyOfRange(8, recordBody.size)
        val aad = buildAad(contentType, version, ciphertext.size - 16)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(aad)
        return c.doFinal(ciphertext)
    }

    private fun decryptChaChaPoly(
        contentType: Int, version: Int, recordBody: ByteArray,
    ): ByteArray? {
        if (recordBody.size < 16) return null
        // nonce = fixedIv(12) XOR (seq padded 到 8 bytes on the right)
        val nonce = fixedIv.copyOf()
        for (i in 0 until 8) {
            val b = ((seq ushr ((7 - i) * 8)) and 0xFF).toInt()
            nonce[4 + i] = (nonce[4 + i].toInt() xor b).toByte()
        }
        val aad = buildAad(contentType, version, recordBody.size - 16)
        val c = Cipher.getInstance("ChaCha20-Poly1305")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        c.updateAAD(aad)
        return c.doFinal(recordBody)
    }

    private fun buildAad(contentType: Int, version: Int, plaintextLen: Int): ByteArray {
        val aad = ByteArray(13)
        for (i in 0 until 8) {
            aad[i] = ((seq ushr ((7 - i) * 8)) and 0xFF).toByte()
        }
        aad[8] = contentType.toByte()
        aad[9] = (version ushr 8).toByte()
        aad[10] = (version and 0xFF).toByte()
        aad[11] = (plaintextLen ushr 8).toByte()
        aad[12] = (plaintextLen and 0xFF).toByte()
        return aad
    }

    companion object {
        /**
         * 从 master_secret + client/server random 派生 key_block，按方向取 write_key
         * 与 implicit_iv 构造 decryptor。
         *
         * key_block = PRF(master_secret, "key expansion", server_random || client_random)
         * layout    = client_write_key || server_write_key || client_write_IV || server_write_IV
         *
         * @param masterSecret 48 字节
         * @param clientRandom 32 字节
         * @param serverRandom 32 字节
         * @param cipherSuite TLS cipher suite ID
         * @param isClient true → 解 client→server 方向; false → server→client
         */
        fun forDirection(
            masterSecret: ByteArray,
            clientRandom: ByteArray,
            serverRandom: ByteArray,
            cipherSuite: Int,
            isClient: Boolean,
        ): Tls12Decryptor? {
            require(masterSecret.size == 48) { "TLS 1.2 master_secret must be 48 bytes" }
            require(clientRandom.size == 32) { "client_random must be 32 bytes" }
            require(serverRandom.size == 32) { "server_random must be 32 bytes" }

            val params = Tls12CipherParams.of(cipherSuite) ?: return null
            val seed = serverRandom + clientRandom
            val keyBlockLen = 2 * params.keyLen + 2 * params.fixedIvLen
            val keyBlock = when (params.hashAlg) {
                "SHA256" -> Tls12Prf.prfSha256(masterSecret, "key expansion", seed, keyBlockLen)
                "SHA384" -> Tls12Prf.prfSha384(masterSecret, "key expansion", seed, keyBlockLen)
                else -> return null
            }
            var pos = 0
            val clientKey = keyBlock.copyOfRange(pos, pos + params.keyLen); pos += params.keyLen
            val serverKey = keyBlock.copyOfRange(pos, pos + params.keyLen); pos += params.keyLen
            val clientIv = keyBlock.copyOfRange(pos, pos + params.fixedIvLen)
            pos += params.fixedIvLen
            val serverIv = keyBlock.copyOfRange(pos, pos + params.fixedIvLen)
            return Tls12Decryptor(
                key = if (isClient) clientKey else serverKey,
                fixedIv = if (isClient) clientIv else serverIv,
            )
        }
    }
}

/** TLS 1.2 cipher suite 关键参数 */
internal class Tls12CipherParams(
    val keyLen: Int,      // AES-128=16, AES-256=32, ChaCha20=32
    val fixedIvLen: Int,  // AES-GCM=4, ChaCha20=12
    val hashAlg: String,  // PRF hash: SHA256 / SHA384
) {
    companion object {
        fun of(cipherSuite: Int): Tls12CipherParams? = when (cipherSuite) {
            0xC02F, 0xC02B, 0x009C -> Tls12CipherParams(16, 4, "SHA256")
            0xC030, 0xC02C, 0x009D -> Tls12CipherParams(32, 4, "SHA384")
            0xCCA8, 0xCCA9, 0xCCAA -> Tls12CipherParams(32, 12, "SHA256")
            else -> null
        }
    }
}
