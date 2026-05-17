package io.github.packetscope.core.decrypt

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * TLS 1.2 PRF（RFC 5246 §5）：
 *
 *   P_hash(secret, seed) = HMAC(secret, A(1) || seed) || HMAC(secret, A(2) || seed) || ...
 *   其中  A(0) = seed
 *         A(i) = HMAC(secret, A(i-1))
 *
 *   PRF(secret, label, seed) = P_hash(secret, label || seed)
 *
 * TLS 1.2 cipher suite 用各自的 hash：默认 P_SHA256，SHA384 cipher 用 P_SHA384。
 */
object Tls12Prf {

    /** PRF with HMAC-SHA256（TLS_*_SHA256 系列） */
    fun prfSha256(secret: ByteArray, label: String, seed: ByteArray, length: Int): ByteArray =
        pHash("HmacSHA256", secret, label.toByteArray(Charsets.US_ASCII) + seed, length)

    /** PRF with HMAC-SHA384（TLS_*_SHA384 系列） */
    fun prfSha384(secret: ByteArray, label: String, seed: ByteArray, length: Int): ByteArray =
        pHash("HmacSHA384", secret, label.toByteArray(Charsets.US_ASCII) + seed, length)

    /**
     * 通用 P_hash 实现。
     *
     * @param alg JCA HMAC algorithm name（HmacSHA256 / HmacSHA384）
     * @param secret HMAC 密钥（PRF 输入 secret）
     * @param seed   P_hash 输入 seed（PRF 内是 label || seed）
     * @param length 输出字节数
     */
    private fun pHash(
        alg: String,
        secret: ByteArray,
        seed: ByteArray,
        length: Int,
    ): ByteArray {
        val mac = Mac.getInstance(alg).apply { init(SecretKeySpec(secret, alg)) }
        val out = ByteArray(length)
        var a = seed  // A(0) = seed
        var pos = 0
        while (pos < length) {
            // A(i) = HMAC(secret, A(i-1))
            mac.reset()
            mac.update(a)
            a = mac.doFinal()
            // block = HMAC(secret, A(i) || seed)
            mac.reset()
            mac.update(a)
            mac.update(seed)
            val block = mac.doFinal()
            val take = minOf(block.size, length - pos)
            System.arraycopy(block, 0, out, pos, take)
            pos += take
        }
        return out
    }
}
