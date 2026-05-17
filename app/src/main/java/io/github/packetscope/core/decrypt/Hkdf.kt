package io.github.packetscope.core.decrypt

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF（RFC 5869）+ TLS 1.3 HKDF-Expand-Label（RFC 8446 §7.1）。
 *
 * 支持 SHA-256 / SHA-384 两个 hash family，分别对应：
 *   - TLS_AES_128_GCM_SHA256 / TLS_CHACHA20_POLY1305_SHA256 → SHA-256
 *   - TLS_AES_256_GCM_SHA384                                → SHA-384
 *
 * 兼容老 call site：[expand] / [expandLabel] 不指定 hash 时默认 SHA-256。
 */
object Hkdf {

    enum class Hash(val alg: String, val len: Int) {
        SHA256("HmacSHA256", 32),
        SHA384("HmacSHA384", 48),
    }

    /** HKDF-Expand(PRK, info, L) — RFC 5869 §2.3. */
    fun expand(prk: ByteArray, info: ByteArray, length: Int, hash: Hash = Hash.SHA256): ByteArray {
        require(length <= 255 * hash.len) { "HKDF-Expand length too large" }
        val mac = Mac.getInstance(hash.alg).apply { init(SecretKeySpec(prk, hash.alg)) }
        val out = ByteArray(length)
        var prev = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            mac.reset()
            mac.update(prev)
            mac.update(info)
            mac.update(counter.toByte())
            prev = mac.doFinal()
            val take = minOf(prev.size, length - pos)
            System.arraycopy(prev, 0, out, pos, take)
            pos += take
            counter++
        }
        return out
    }

    /**
     * HKDF-Expand-Label(Secret, Label, Context, Length) — RFC 8446 §7.1.
     *
     *   HkdfLabel = struct {
     *     uint16 length;
     *     opaque label<7..255> = "tls13 " + label;
     *     opaque context<0..255> = context;
     *   }
     */
    fun expandLabel(
        secret: ByteArray, label: String, context: ByteArray, length: Int,
        hash: Hash = Hash.SHA256,
    ): ByteArray {
        val fullLabel = ("tls13 $label").toByteArray(Charsets.US_ASCII)
        require(fullLabel.size in 7..255) { "label out of range" }
        require(context.size <= 255) { "context too large" }

        // 2 (length) + 1 (label_len) + fullLabel + 1 (context_len) + context
        val info = ByteArray(2 + 1 + fullLabel.size + 1 + context.size)
        info[0] = ((length ushr 8) and 0xFF).toByte()
        info[1] = (length and 0xFF).toByte()
        info[2] = fullLabel.size.toByte()
        System.arraycopy(fullLabel, 0, info, 3, fullLabel.size)
        info[3 + fullLabel.size] = context.size.toByte()
        System.arraycopy(context, 0, info, 4 + fullLabel.size, context.size)

        return expand(secret, info, length, hash)
    }
}
