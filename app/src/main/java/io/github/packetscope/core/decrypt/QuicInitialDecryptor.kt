package io.github.packetscope.core.decrypt

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * QUIC v1 Initial 包解密（RFC 9001 §5）。
 *
 * Initial keys 完全由 client 第一个 Initial 包的 Destination Connection ID 派生，
 * 不需要 SSLKEYLOGFILE。
 *
 *   salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a            (QUIC v1)
 *   initial_secret        = HKDF-Extract(salt, dcid)
 *   client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
 *   server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
 *
 *   key = HKDF-Expand-Label(secret, "quic key", "", 16)   // AES-128
 *   iv  = HKDF-Expand-Label(secret, "quic iv", "", 12)
 *   hp  = HKDF-Expand-Label(secret, "quic hp", "", 16)   // AES-128-ECB header protection
 *
 * Header protection (RFC 9001 §5.4):
 *   sample      = packet[pnOffset + 4 .. pnOffset + 19]
 *   mask        = AES-ECB(hp, sample)[0..5]
 *   byte0      ^= mask[0] & 0x0F            (Long header low 4 bits)
 *   pn_len      = (byte0 & 0x03) + 1
 *   pn_bytes   ^= mask[1..pn_len+1]
 *
 * Payload (AES-128-GCM):
 *   nonce       = iv XOR (pn left-padded to 12 bytes)
 *   AAD         = unprotected_header (byte0 .. last pn byte)
 *   plaintext   = AES-GCM-Decrypt(key, nonce, AAD, ciphertext)
 */
class QuicInitialDecryptor private constructor(
    private val key: ByteArray,
    private val iv: ByteArray,
    private val hp: ByteArray,
) {

    /**
     * 解密一个 QUIC Initial 包。
     *
     * @param packetBytes 完整 QUIC packet 字节（从 byte0 开始，含 tag）
     * @param pnOffset    packet number 的起始 offset（在 [packetBytes] 内）
     * @param totalLen    QUIC "Length" 字段值 = pn 长度 + payload + 16 字节 tag
     * @return [DecryptedInitial] 或 null（auth 失败 / 长度异常）
     */
    fun decrypt(packetBytes: ByteArray, pnOffset: Int, totalLen: Int): DecryptedInitial? =
        runCatching { decryptInternal(packetBytes, pnOffset, totalLen) }.getOrNull()

    private fun decryptInternal(
        packetBytes: ByteArray, pnOffset: Int, totalLen: Int,
    ): DecryptedInitial? {
        require(pnOffset + totalLen <= packetBytes.size)
        require(pnOffset + 4 + 16 <= packetBytes.size)

        // 1. Header protection 还原
        val sample = packetBytes.copyOfRange(pnOffset + 4, pnOffset + 4 + 16)
        val mask = aesEcb(hp, sample).copyOfRange(0, 5)
        val byte0Orig = packetBytes[0].toInt() and 0xFF
        val byte0 = byte0Orig xor (mask[0].toInt() and 0x0F)
        val pnLen = (byte0 and 0x03) + 1
        require(pnOffset + pnLen <= packetBytes.size)

        val unprotectedHeader = packetBytes.copyOf(pnOffset + pnLen)
        unprotectedHeader[0] = byte0.toByte()
        var packetNumber = 0L
        for (i in 0 until pnLen) {
            val unprot = (packetBytes[pnOffset + i].toInt() xor mask[1 + i].toInt()) and 0xFF
            unprotectedHeader[pnOffset + i] = unprot.toByte()
            packetNumber = (packetNumber shl 8) or unprot.toLong()
        }

        // 2. AES-GCM payload 解密
        val ctStart = pnOffset + pnLen
        val ctEnd = pnOffset + totalLen
        require(ctStart < ctEnd && ctStart + 16 <= ctEnd)
        val ciphertext = packetBytes.copyOfRange(ctStart, ctEnd)
        val nonce = iv.copyOf()
        for (i in 0 until 8) {
            val b = ((packetNumber ushr ((7 - i) * 8)) and 0xFF).toInt()
            nonce[4 + i] = (nonce[4 + i].toInt() xor b).toByte()
        }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(unprotectedHeader)
        val plaintext = c.doFinal(ciphertext)
        return DecryptedInitial(unprotectedHeader, packetNumber, plaintext)
    }

    private fun aesEcb(key: ByteArray, data: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/ECB/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return c.doFinal(data)
    }

    companion object {
        /** RFC 9001 §5.2 — QUIC v1 initial salt. */
        private val INITIAL_SALT_V1 = byteArrayOf(
            0x38, 0x76, 0x2c, 0xf7.toByte(),
            0xf5.toByte(), 0x59, 0x34, 0xb3.toByte(),
            0x4d, 0x17, 0x9a.toByte(), 0xe6.toByte(),
            0xa4.toByte(), 0xc8.toByte(), 0x0c, 0xad.toByte(),
            0xcc.toByte(), 0xbb.toByte(), 0x7f, 0x0a,
        )

        /**
         * 从 client 第一个 Initial 包的 Destination CID 派生整个连接 Initial
         * 双向 decryptor。
         *
         * RFC 9001 §5.2 复用 TLS 1.3 HKDF-Expand-Label（前缀 "tls13 "），所以
         * label "client in" 实际全 label = "tls13 client in"。Initial 解 key/iv/hp
         * 用 QUIC 独有的 "quic key" / "quic iv" / "quic hp"（RFC 9001 §5.1）。
         */
        fun fromDcid(dcid: ByteArray): Pair<QuicInitialDecryptor, QuicInitialDecryptor> {
            val initialSecret = hkdfExtract(INITIAL_SALT_V1, dcid)
            val clientSecret = Hkdf.expandLabel(initialSecret, "client in", ByteArray(0), 32)
            val serverSecret = Hkdf.expandLabel(initialSecret, "server in", ByteArray(0), 32)
            return forSecret(clientSecret) to forSecret(serverSecret)
        }

        private fun forSecret(secret: ByteArray): QuicInitialDecryptor {
            val key = Hkdf.expandLabel(secret, "quic key", ByteArray(0), 16)
            val iv = Hkdf.expandLabel(secret, "quic iv", ByteArray(0), 12)
            val hp = Hkdf.expandLabel(secret, "quic hp", ByteArray(0), 16)
            return QuicInitialDecryptor(key, iv, hp)
        }

        /** HKDF-Extract (RFC 5869 §2.2) = HMAC-SHA256(salt, IKM). */
        private fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(salt, "HmacSHA256"))
            return mac.doFinal(ikm)
        }
    }
}

/** 解密成功后返回：unprotected header 字节 + 包号 + 明文 payload（含 frames） */
class DecryptedInitial(
    val unprotectedHeader: ByteArray,
    val packetNumber: Long,
    val plaintext: ByteArray,
)
