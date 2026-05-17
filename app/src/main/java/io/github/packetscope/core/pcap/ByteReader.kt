package io.github.packetscope.core.pcap

/**
 * 小工具：按指定字节序从 ByteArray 读取多字节整数。
 * dissector 里大量用到，提到顶层避免每个文件重复。
 */
object ByteReader {

    fun u8(data: ByteArray, offset: Int): Int =
        data[offset].toInt() and 0xFF

    fun u16Be(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or
            (data[offset + 1].toInt() and 0xFF)

    fun u16Le(data: ByteArray, offset: Int): Int =
        (data[offset].toInt() and 0xFF) or
            ((data[offset + 1].toInt() and 0xFF) shl 8)

    fun u32Be(data: ByteArray, offset: Int): Long =
        ((data[offset].toLong() and 0xFF) shl 24) or
            ((data[offset + 1].toLong() and 0xFF) shl 16) or
            ((data[offset + 2].toLong() and 0xFF) shl 8) or
            (data[offset + 3].toLong() and 0xFF)

    fun u32Le(data: ByteArray, offset: Int): Long =
        (data[offset].toLong() and 0xFF) or
            ((data[offset + 1].toLong() and 0xFF) shl 8) or
            ((data[offset + 2].toLong() and 0xFF) shl 16) or
            ((data[offset + 3].toLong() and 0xFF) shl 24)

    /** 6 字节 MAC 地址格式化为 "aa:bb:cc:dd:ee:ff" */
    fun mac(data: ByteArray, offset: Int): String =
        (0 until 6).joinToString(":") {
            "%02x".format(data[offset + it].toInt() and 0xFF)
        }

    /** 4 字节 IPv4 地址格式化为 "a.b.c.d" */
    fun ipv4(data: ByteArray, offset: Int): String =
        (0 until 4).joinToString(".") {
            (data[offset + it].toInt() and 0xFF).toString()
        }

    /** 16 字节 IPv6 地址格式化为标准缩写形式 */
    fun ipv6(data: ByteArray, offset: Int): String {
        val groups = (0 until 8).map { i ->
            u16Be(data, offset + i * 2)
        }
        // 找到最长的连续 0 段，缩为 "::"
        var bestStart = -1
        var bestLen = 0
        var curStart = -1
        var curLen = 0
        for (i in groups.indices) {
            if (groups[i] == 0) {
                if (curStart == -1) curStart = i
                curLen++
                if (curLen > bestLen) {
                    bestLen = curLen
                    bestStart = curStart
                }
            } else {
                curStart = -1
                curLen = 0
            }
        }
        if (bestLen < 2) {
            return groups.joinToString(":") { "%x".format(it) }
        }
        val before = groups.subList(0, bestStart).joinToString(":") { "%x".format(it) }
        val after = groups.subList(bestStart + bestLen, 8).joinToString(":") { "%x".format(it) }
        return "$before::$after"
    }
}
