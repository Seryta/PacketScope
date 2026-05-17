package io.github.packetscope.core.decrypt

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * TLS 1.3 ApplicationData 解密。支持 cipher suites:
 *   0x1301 TLS_AES_128_GCM_SHA256
 *   0x1302 TLS_AES_256_GCM_SHA384
 *   0x1303 TLS_CHACHA20_POLY1305_SHA256
 *
 * 不论哪个 cipher，TLS 1.3 record 的 nonce 派生都一样：
 *   nonce = iv(12) XOR (seq padded 到 8 bytes on the right)
 * AAD 都是 5 字节 record header。
 *
 * 用法：每个方向用 [forDirection] 派生一个 [Tls13Decryptor]，按时间顺序对每条
 * ApplicationData 调 [decryptNext]。内部维护 sequence number。
 */
class Tls13Decryptor private constructor(
    private val key: ByteArray,
    private val iv: ByteArray,   // 12 字节
    private val cipherSuite: Int,
) {
    private var seq: Long = 0L

    /**
     * 解密一条 record。
     *
     * @param recordHeader 5 字节 record header（作为 AAD）
     * @param ciphertext  record body（含末尾 16 字节 auth tag）
     * @return 解密后明文，最后一字节是 TLS 1.3 inner ContentType；调用方需要剥掉。
     *         返回 null 表示 auth 失败（key 不对 / 包乱序）。
     */
    fun decryptNext(recordHeader: ByteArray, ciphertext: ByteArray): ByteArray? {
        val nonce = ByteArray(12)
        System.arraycopy(iv, 0, nonce, 0, 12)
        // RFC 8446: nonce = iv XOR (seq padded to 8 bytes on the right)
        for (i in 0 until 8) {
            val b = ((seq ushr ((7 - i) * 8)) and 0xFF).toInt()
            nonce[4 + i] = (nonce[4 + i].toInt() xor b).toByte()
        }
        val plaintext = try {
            decryptAead(nonce, recordHeader, ciphertext)
        } catch (_: AEADBadTagException) {
            return null
        } catch (_: Exception) {
            return null
        }
        seq++
        return plaintext
    }

    private fun decryptAead(nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        return when (cipherSuite) {
            0x1301, 0x1302 -> {
                val c = Cipher.getInstance("AES/GCM/NoPadding")
                c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
                c.updateAAD(aad)
                c.doFinal(ciphertext)
            }
            0x1303 -> {
                // ChaCha20-Poly1305 (RFC 7539). JCE 算法名 "ChaCha20-Poly1305"，
                // Conscrypt 自 API 28 起原生支持
                val c = Cipher.getInstance("ChaCha20-Poly1305")
                c.init(
                    Cipher.DECRYPT_MODE,
                    SecretKeySpec(key, "ChaCha20"),
                    IvParameterSpec(nonce),
                )
                c.updateAAD(aad)
                c.doFinal(ciphertext)
            }
            else -> error("unsupported TLS 1.3 cipher 0x%04x".format(cipherSuite))
        }
    }

    /** 内部明文末尾是 ContentType + 可能的 0-padding。剥掉得到真实数据。 */
    fun unwrapInnerPlaintext(plaintext: ByteArray): InnerPlaintext? {
        var i = plaintext.size - 1
        while (i >= 0 && plaintext[i].toInt() == 0) i--
        if (i < 0) return null
        val contentType = plaintext[i].toInt() and 0xFF
        val data = plaintext.copyOfRange(0, i)
        return InnerPlaintext(contentType, data)
    }

    companion object {
        /**
         * 从 traffic secret 派生 key/iv。
         *
         * @param secret CLIENT_TRAFFIC_SECRET_0 或 SERVER_TRAFFIC_SECRET_0；
         *   长度跟 cipher suite 的 hash 一致（SHA256=32, SHA384=48）
         * @param cipherSuite TLS 1.3 cipher suite ID
         */
        fun forDirection(secret: ByteArray, cipherSuite: Int = 0x1301): Tls13Decryptor {
            val params = Tls13CipherParams.of(cipherSuite)
                ?: error("unsupported TLS 1.3 cipher 0x%04x".format(cipherSuite))
            require(secret.size == params.hash.len) {
                "Expected ${params.hash.len}-byte traffic secret for cipher 0x%04x".format(cipherSuite)
            }
            val key = Hkdf.expandLabel(secret, "key", ByteArray(0), params.keyLen, params.hash)
            val iv = Hkdf.expandLabel(secret, "iv", ByteArray(0), 12, params.hash)
            return Tls13Decryptor(key, iv, cipherSuite)
        }
    }
}

/** TLS 1.3 cipher suite 关键参数 */
internal class Tls13CipherParams(
    val keyLen: Int,
    val hash: Hkdf.Hash,
) {
    companion object {
        fun of(cipherSuite: Int): Tls13CipherParams? = when (cipherSuite) {
            0x1301 -> Tls13CipherParams(16, Hkdf.Hash.SHA256)
            0x1302 -> Tls13CipherParams(32, Hkdf.Hash.SHA384)
            0x1303 -> Tls13CipherParams(32, Hkdf.Hash.SHA256)
            else -> null
        }
    }
}

/**
 * 普通 class（无 `data` 修饰）：没有 copy() 用户，避免 ByteArray 默认 equals 的逐
 * 字节比较（review v0.6-round1 F-007）。
 */
class InnerPlaintext(val contentType: Int, val data: ByteArray) {
    val contentTypeName: String get() = when (contentType) {
        20 -> "ChangeCipherSpec"
        21 -> "Alert"
        22 -> "Handshake"
        23 -> "ApplicationData"
        else -> "Type$contentType"
    }
}
