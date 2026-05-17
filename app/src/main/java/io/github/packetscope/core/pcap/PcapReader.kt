package io.github.packetscope.core.pcap

import java.io.IOException
import java.io.InputStream

/**
 * 读取 classic PCAP 文件格式（不是 PCAPng，PCAPng 留给后续版本）。
 *
 * 文件结构：
 *   - 24 字节 global header（magic 决定字节序和时间分辨率）
 *   - 一个或多个 record：16 字节 record header + captured_length 字节包内容
 *
 * 引用：https://wiki.wireshark.org/Development/LibpcapFileFormat
 */
class PcapReader(private val input: InputStream) : AutoCloseable {

    val linkType: LinkType
    val snaplen: Int

    private val littleEndian: Boolean
    private val nanoseconds: Boolean
    private var nextIndex = 1

    init {
        val header = input.readNBytesOrThrow(GLOBAL_HEADER_SIZE, "global header")

        // 推断字节序和时间分辨率
        val magic = ByteReader.u32Be(header, 0)
        val info = MAGIC_TABLE[magic]
            ?: throw IOException("Not a PCAP file or unsupported format (magic=0x%08x)".format(magic))
        littleEndian = info.littleEndian
        nanoseconds = info.nanoseconds

        // 其余字段按推断出的字节序读
        snaplen = readU32(header, 16).toInt()
        linkType = LinkType.fromValue(readU32(header, 20).toInt())
    }

    /**
     * 惰性输出所有 frame 的原始信息（不含 dissector 解析）。
     * 调用方需要再交给 [io.github.packetscope.core.dissector.Pipeline] 处理。
     */
    fun frames(): Sequence<RawFrame> = sequence {
        while (true) {
            val recordHeader = input.readNBytesOrNull(RECORD_HEADER_SIZE) ?: break
            if (recordHeader.size < RECORD_HEADER_SIZE) break  // 截断的 record header，按结束处理

            val tsSec = readU32(recordHeader, 0)
            val tsFrac = readU32(recordHeader, 4)
            val capturedLen = readU32(recordHeader, 8).toInt()
            val originalLen = readU32(recordHeader, 12).toInt()

            if (capturedLen < 0 || capturedLen > MAX_REASONABLE_PACKET) {
                throw IOException("Unreasonable captured length: $capturedLen")
            }

            val data = input.readNBytesOrThrow(capturedLen, "packet body")
            val ts = if (nanoseconds) {
                tsSec * 1_000_000_000L + tsFrac
            } else {
                tsSec * 1_000_000_000L + tsFrac * 1_000L
            }

            yield(
                RawFrame(
                    index = nextIndex++,
                    timestampNanos = ts,
                    capturedLength = capturedLen,
                    originalLength = originalLen,
                    data = data,
                )
            )
        }
    }

    override fun close() {
        input.close()
    }

    private fun readU32(buf: ByteArray, offset: Int): Long =
        if (littleEndian) ByteReader.u32Le(buf, offset) else ByteReader.u32Be(buf, offset)

    companion object {
        private const val GLOBAL_HEADER_SIZE = 24
        private const val RECORD_HEADER_SIZE = 16

        /** 防御性上限：避免文件损坏导致一次性分配几个 GB 的 ByteArray */
        private const val MAX_REASONABLE_PACKET = 16 * 1024 * 1024

        private data class MagicInfo(val littleEndian: Boolean, val nanoseconds: Boolean)

        private val MAGIC_TABLE = mapOf(
            0xa1b2c3d4L to MagicInfo(littleEndian = false, nanoseconds = false),
            0xd4c3b2a1L to MagicInfo(littleEndian = true, nanoseconds = false),
            0xa1b23c4dL to MagicInfo(littleEndian = false, nanoseconds = true),
            0x4d3cb2a1L to MagicInfo(littleEndian = true, nanoseconds = true),
        )
    }
}

/**
 * 未经 dissector 解析的原始 frame。后续交给 Pipeline 产出完整 [Frame]。
 *
 * 普通 class（无 `data` 修饰）：没有任何 copy() 调用方，省去 ByteArray 上的
 * 自动生成 equals/hashCode 开销；身份比较即可（review v0.6-round1 F-007）。
 */
class RawFrame(
    val index: Int,
    val timestampNanos: Long,
    val capturedLength: Int,
    val originalLength: Int,
    val data: ByteArray,
) {
    override fun toString(): String =
        "RawFrame(index=$index, capLen=$capturedLength, origLen=$originalLength)"
}

private fun InputStream.readNBytesOrThrow(n: Int, what: String): ByteArray {
    val buf = ByteArray(n)
    var read = 0
    while (read < n) {
        val r = read(buf, read, n - read)
        if (r < 0) throw IOException("Unexpected EOF while reading $what (wanted $n, got $read)")
        read += r
    }
    return buf
}

private fun InputStream.readNBytesOrNull(n: Int): ByteArray? {
    val buf = ByteArray(n)
    var read = 0
    while (read < n) {
        val r = read(buf, read, n - read)
        if (r < 0) return if (read == 0) null else buf.copyOf(read)
        read += r
    }
    return buf
}
