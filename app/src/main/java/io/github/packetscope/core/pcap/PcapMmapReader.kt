package io.github.packetscope.core.pcap

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel

/**
 * 基于 mmap 的 PCAP 读取器（v0.9）。
 *
 * 跟 [PcapReader] 解析逻辑完全一致，但 IO 路径走 [FileChannel.map] 把整个文件
 * 映射进进程地址空间——OS 按需 paging，免去 InputStream 在 user-space 反复
 * malloc + memcpy 的 read buffer。对几百 MB PCAP 加载快 + 内存压力低。
 *
 * 注意每个 [RawFrame] 仍持有完整 captured bytes 的 ByteArray（解析时一次 bulk
 * copy 出来），堆压力仍随帧数线性增长——真正的 lazy paging（Frame.data 改成
 * 按需 mmap slice）留 v1.0+ 改造。
 *
 * 接口跟 [PcapReader] 对齐 (linkType / snaplen / frames())，让 PcapLoader 内可
 * sealed 选用。
 */
class PcapMmapReader(channel: FileChannel) : AutoCloseable {

    val linkType: LinkType
    val snaplen: Int

    private val channel: FileChannel = channel
    private val mmap: ByteBuffer
    private val recordsStart: Int
    private val nanoseconds: Boolean

    init {
        val fileSize = channel.size()
        if (fileSize < GLOBAL_HEADER_SIZE) {
            throw IOException("Not a PCAP file: too small ($fileSize bytes)")
        }
        if (fileSize > Int.MAX_VALUE) {
            // ByteBuffer 索引上限 ~2GB；超过这个量 v1.0 lazy paging 才能处理
            throw IOException("File too large to mmap as single ByteBuffer: $fileSize")
        }
        mmap = channel.map(FileChannel.MapMode.READ_ONLY, 0, fileSize)
        // 读 magic（默认 BIG_ENDIAN）判断字节序 + 时间分辨率
        mmap.order(ByteOrder.BIG_ENDIAN)
        val magic = mmap.getInt(0).toLong() and 0xFFFFFFFFL
        val info = MAGIC_TABLE[magic]
            ?: throw IOException("Not a PCAP file or unsupported format (magic=0x%08x)".format(magic))
        nanoseconds = info.nanoseconds
        mmap.order(if (info.littleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)
        snaplen = mmap.getInt(16)
        linkType = LinkType.fromValue(mmap.getInt(20))
        recordsStart = GLOBAL_HEADER_SIZE
    }

    /**
     * 顺序 emit 所有 records 的原始信息。跟 [PcapReader.frames] 语义一致：
     * 截断的 record header 视为流结束（不抛异常）；超大 capturedLength 抛 IOException。
     */
    fun frames(): Sequence<RawFrame> = sequence {
        var cursor = recordsStart
        var index = 1
        val limit = mmap.capacity()
        while (cursor + RECORD_HEADER_SIZE <= limit) {
            val tsSec = mmap.getInt(cursor).toLong() and 0xFFFFFFFFL
            val tsFrac = mmap.getInt(cursor + 4).toLong() and 0xFFFFFFFFL
            val capLen = mmap.getInt(cursor + 8)
            val origLen = mmap.getInt(cursor + 12)
            if (capLen < 0 || capLen > MAX_REASONABLE_PACKET) {
                throw IOException("Unreasonable captured length: $capLen")
            }
            val bodyStart = cursor + RECORD_HEADER_SIZE
            if (bodyStart + capLen > limit) break  // 截断的 record body 当流结束
            val data = ByteArray(capLen)
            val slice = mmap.duplicate().apply { position(bodyStart) }
            slice.get(data, 0, capLen)
            val tsNanos = if (nanoseconds) {
                tsSec * 1_000_000_000L + tsFrac
            } else {
                tsSec * 1_000_000_000L + tsFrac * 1_000L
            }
            yield(RawFrame(
                index = index++,
                timestampNanos = tsNanos,
                capturedLength = capLen,
                originalLength = origLen,
                data = HeapBytes(data),
            ))
            cursor = bodyStart + capLen
        }
    }

    override fun close() {
        // MappedByteBuffer 没标准 unmap API（JDK Cleaner 是 sun.misc internal，
        // Android Q+ 还可能撞 hidden API restriction）。这里 reflection 调一次
        // Cleaner.clean() best-effort 释放，失败静默 fallback 到 GC + finalizer
        // 回收 —— v0.6-round7 F-008 deferred 兑现（round1 REFACTOR-002）。
        // 反复加载大 PCAP 时减少 virtual address space 累积，但不可依赖：
        // - API 28 grey list（reflection 可用但有警告）
        // - API 29+ dark list 可能 SecurityException
        // - 不同 JDK / Conscrypt 字段名差异（some 'cleaner' / others 不存在）
        runCatching { explicitUnmap(mmap) }
        channel.close()
    }

    /** 反射触发 [java.nio.MappedByteBuffer] 内的 cleaner。任何失败都吞掉，
     *  让 caller 依赖 GC + finalizer 兜底。 */
    private fun explicitUnmap(buf: java.nio.ByteBuffer) {
        val cleanerField = buf::class.java.getDeclaredField("cleaner")
        cleanerField.isAccessible = true
        val cleaner = cleanerField.get(buf) ?: return
        val cleanMethod = cleaner::class.java.getMethod("clean")
        cleanMethod.invoke(cleaner)
    }

    companion object {
        private const val GLOBAL_HEADER_SIZE = 24
        private const val RECORD_HEADER_SIZE = 16
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
