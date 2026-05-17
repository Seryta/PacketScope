package io.github.packetscope.core.extension

import io.github.packetscope.core.pcap.ByteReader

/**
 * PCAPdroid 的 dump_extensions trailer（PCAP 模式下加在每个 packet 末尾）。
 *
 * 格式（big-endian）：
 *   offset  size  field
 *   0       4     magic = 0x01072021
 *   4       4     uid (Android UID)
 *   8       20    app name (null-padded ASCII)
 *   28      4     CRC32 (over bytes 0..27)
 *
 * 总长 SIZE = 20。等等，重新数：
 *   magic(4) + uid(4) + appname(20) + fcs(4) = 32 字节
 *
 * 参考：PCAPdroid pcap_dump.c trailer 写入逻辑
 */
data class PcapdroidTrailer(
    val uid: Int,
    val appName: String,
    val fcs: Int,
)

object PcapdroidTrailerDecoder {
    private const val MAGIC = 0x01072021L
    const val SIZE = 32

    /** 试探 [data] 末尾 32 字节是否是有效 trailer。magic 不匹配返回 null */
    fun tryDecode(data: ByteArray): PcapdroidTrailer? {
        if (data.size < SIZE) return null
        val start = data.size - SIZE
        val magic = ByteReader.u32Be(data, start)
        if (magic != MAGIC) return null
        val uid = ByteReader.u32Be(data, start + 4).toInt()
        val appName = readNullTerminatedUtf8(data, start + 8, 20)
        val fcs = ByteReader.u32Be(data, start + 28).toInt()
        return PcapdroidTrailer(uid = uid, appName = appName, fcs = fcs)
    }

    /**
     * PCAPdroid 通过 JNI GetStringUTFChars 写入，本质是 modified UTF-8。
     * 中文 app label 是多字节 UTF-8，必须按 UTF-8 解；不能用 ASCII。
     * 末尾可能在多字节中间被截断（20B 字段限制），Kotlin String(bytes, UTF_8)
     * 默认遇到 malformed 用 � 替换，trimEnd 去掉。
     */
    private fun readNullTerminatedUtf8(data: ByteArray, offset: Int, max: Int): String {
        var end = offset
        val limit = (offset + max).coerceAtMost(data.size)
        while (end < limit && data[end].toInt() != 0) end++
        return String(data, offset, end - offset, Charsets.UTF_8)
            .trimEnd('�')
    }
}
