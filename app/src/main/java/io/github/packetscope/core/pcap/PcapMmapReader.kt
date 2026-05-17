package io.github.packetscope.core.pcap

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel

/**
 * 基于 mmap 的 PCAP 读取器（v0.9 引入；v1.1 LAZY-002 改为 true lazy）。
 *
 * 跟 [PcapReader] 解析逻辑完全一致，但 IO 路径走 [FileChannel.map] 把整个文件
 * 映射进进程地址空间——OS 按需 paging，免去 InputStream 在 user-space 反复
 * malloc + memcpy 的 read buffer。对几百 MB PCAP 加载快 + 内存压力低。
 *
 * **v1.1 lazy 改造**：每个 [RawFrame.data] 不再 ByteArray copy 出 captured bytes，
 * 而是 yield 一个 [MmapBytes] 视图（zero-copy）。Frame.data 仅持 (parent buffer
 * ref, offset, length)，heap 上只有元数据。这把同等 PCAP 的 heap 占用从 ~2×
 * 文件大小降到 ~0.5-1×（只剩 layers + fields）。
 *
 * **生命周期**：[MmapBytes] 持 parent 强引用，GC 不会在视图存活时回收 mmap。
 * [close] 不再主动 unmap（v1.0 round1 的 explicitUnmap 移到 LAZY-003 的
 * PcapHandle）—— 若立即 unmap，外部还在用的 MmapBytes 视图会 SIGSEGV。
 * 短期回到 GC + finalizer 自然回收 mmap；显式 unmap 留 LAZY-003 接管。
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
            // LAZY-002: 不再 ByteArray copy；MmapBytes 持 (mmap, bodyStart, capLen)
            // 视图，访问时通过 ByteBuffer.duplicate() 拿独立 position view，
            // 零拷贝，零额外 heap。父 mmap 由 MmapBytes 强引用守 GC。
            val data: FrameBytes = MmapBytes(mmap, bodyStart, capLen)
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
                data = data,
            ))
            cursor = bodyStart + capLen
        }
    }

    override fun close() {
        // LAZY-002: 移除立即 explicitUnmap(mmap)——MmapBytes 视图仍持父 mmap 强引用
        // 在 PcapLoader 完成后存活到 Frame 列表整体 GC，提前 unmap 会触发 SIGSEGV。
        // 显式 unmap 改由 LAZY-003 的 PcapHandle 接管：state 切换时统一释放。
        // 这里只 close FileChannel（已经 mapped 进地址空间的 buffer 不依赖 channel）；
        // mmap 由 GC + finalizer 兜底回收 —— 回到 v0.9 之前的回收策略。
        channel.close()
    }

    /** 显式 unmap helper：触发 [java.nio.MappedByteBuffer] 内的 Cleaner.clean()。
     *  失败静默 fallback 到 GC + finalizer。
     *  LAZY-003 PcapHandle 在确认所有 Frame 引用都 drop 后调此函数。
     *  - API 28 grey list（reflection 可用但有警告）
     *  - API 29+ dark list 可能 SecurityException
     *  - 不同 JDK / Conscrypt 字段名差异（some 'cleaner' / others 不存在） */
    internal fun tryExplicitUnmap() {
        runCatching {
            val cleanerField = mmap::class.java.getDeclaredField("cleaner")
            cleanerField.isAccessible = true
            val cleaner = cleanerField.get(mmap) ?: return@runCatching
            val cleanMethod = cleaner::class.java.getMethod("clean")
            cleanMethod.invoke(cleaner)
        }
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
