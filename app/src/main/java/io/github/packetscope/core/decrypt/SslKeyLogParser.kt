package io.github.packetscope.core.decrypt

import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader

/**
 * 解析 NSS Key Log Format（Firefox / Wireshark / mitmproxy 都用同一格式）。
 *
 * 每行：  <LABEL> <CLIENT_RANDOM_HEX> <SECRET_HEX>
 *
 * 例：
 *   CLIENT_RANDOM 6b3343cf...  9c8e2f1b...
 *   CLIENT_HANDSHAKE_TRAFFIC_SECRET ... ...
 *   CLIENT_TRAFFIC_SECRET_0 ... ...
 *   SERVER_TRAFFIC_SECRET_0 ... ...
 *
 * 第二列 32 字节 client_random 作为 session 标识。
 */
object SslKeyLogParser {

    /** 解析输入流；忽略空行和 `#` 注释 */
    fun parse(input: InputStream): List<KeyLogEntry> {
        val entries = mutableListOf<KeyLogEntry>()
        BufferedReader(InputStreamReader(input, Charsets.US_ASCII)).useLines { lines ->
            for (raw in lines) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#")) continue
                val parts = line.split(Regex("\\s+"))
                if (parts.size != 3) continue
                val label = parts[0]
                val clientRandom = parts[1].hexToBytesOrNull() ?: continue
                val secret = parts[2].hexToBytesOrNull() ?: continue
                if (clientRandom.size != 32) continue
                entries += KeyLogEntry(label, clientRandom, secret)
            }
        }
        return entries
    }
}

/**
 * 普通 class（无 `data` 修饰）：没有 copy() 用户，避免 ByteArray 默认 equals 的逐
 * 字节比较；身份比较够用（review v0.6-round1 F-007）。
 */
class KeyLogEntry(val label: String, val clientRandom: ByteArray, val secret: ByteArray) {
    override fun toString(): String = "KeyLogEntry(label=$label)"
}

internal fun String.hexToBytesOrNull(): ByteArray? {
    if (length % 2 != 0) return null
    val out = ByteArray(length / 2)
    for (i in indices step 2) {
        val hi = this[i].digitToIntOrNull(16) ?: return null
        val lo = this[i + 1].digitToIntOrNull(16) ?: return null
        out[i / 2] = ((hi shl 4) or lo).toByte()
    }
    return out
}

internal fun ByteArray.toHexLower(): String = buildString(size * 2) {
    for (b in this@toHexLower) {
        val v = b.toInt() and 0xFF
        append(HEX[v ushr 4]); append(HEX[v and 0x0F])
    }
}

private val HEX = "0123456789abcdef".toCharArray()
