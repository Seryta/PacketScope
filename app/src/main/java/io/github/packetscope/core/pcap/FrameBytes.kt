package io.github.packetscope.core.pcap

import java.nio.ByteBuffer
import java.nio.charset.Charset

/**
 * 帧字节内容的抽象。把 [Frame] 持有的 raw bytes 从具体的 ByteArray
 * 解耦出来，让 mmap 路径可以零拷贝持视图、heap 路径继续直接持 ByteArray。
 *
 * 两种实现：
 *  - [HeapBytes]：直接持 ByteArray（流式 PcapReader / PCAPdroid UDP listener / 旧路径）
 *  - [MmapBytes]：持 `(parent ByteBuffer, offset, length)` 的 zero-copy 视图，
 *    mmap 父 buffer 保持强引用直到所有视图释放
 *
 * **不可变契约**：所有返回的 ByteArray 调用方**不得改写**。HeapBytes.asByteArray
 * 直接返回内部数组（zero-copy），如果调用方修改会污染原帧。
 *
 * **不重写 equals/hashCode**：Frame 自己用身份比较（见 [Frame.equals]），
 * FrameBytes 引用比较即可。
 */
sealed interface FrameBytes {
    val size: Int
    operator fun get(index: Int): Byte
    fun copyOfRange(fromIndex: Int, toIndex: Int): ByteArray
    /**
     * 把帧字节完整材料化为 ByteArray。
     * - HeapBytes：返回内部引用（零拷贝）
     * - MmapBytes：copy 出 ByteArray（必然分配）
     *
     * 调用点应明确意识到这是"放弃 lazy"——只在需要把整帧字节传给 ByteArray-API
     * 的 helper / 旧 dissector 路径时用。
     */
    fun asByteArray(): ByteArray
    /** 把整帧解码为字符串。Latin-1 等单字节编码常用于全字节 substring 扫描。 */
    fun decodeToString(charset: Charset): String
}

/** 直接持 ByteArray 的实现。任何 frame.data 在 v0.9 之前都是这种。 */
class HeapBytes(private val arr: ByteArray) : FrameBytes {
    override val size: Int get() = arr.size
    override fun get(index: Int): Byte = arr[index]
    override fun copyOfRange(fromIndex: Int, toIndex: Int): ByteArray =
        arr.copyOfRange(fromIndex, toIndex)
    override fun asByteArray(): ByteArray = arr
    override fun decodeToString(charset: Charset): String = String(arr, charset)
}

/**
 * mmap 视图实现。LAZY-002 Phase 2 启用，让 PcapMmapReader 不再 copy 出 ByteArray。
 *
 * **生命周期**：必须持 [parent] 强引用，保证 GC 不在视图存活时回收 mmap。
 * 反向 unmap 由 LAZY-003 Phase 3 的 PcapHandle 显式管理。
 *
 * **线程安全**：[parent] 自身是 MappedByteBuffer，可被多线程读；本类每次访问
 * 都 [ByteBuffer.duplicate] 出独立 position view，不共享游标状态。
 */
class MmapBytes(
    private val parent: ByteBuffer,
    private val byteOffset: Int,
    override val size: Int,
) : FrameBytes {
    override fun get(index: Int): Byte {
        if (index < 0 || index >= size) throw IndexOutOfBoundsException("index=$index size=$size")
        return parent.get(byteOffset + index)
    }

    override fun copyOfRange(fromIndex: Int, toIndex: Int): ByteArray {
        if (fromIndex < 0 || toIndex > size || fromIndex > toIndex) {
            throw IndexOutOfBoundsException("range=$fromIndex..$toIndex size=$size")
        }
        val len = toIndex - fromIndex
        val out = ByteArray(len)
        if (len > 0) {
            val slice = parent.duplicate().apply { position(byteOffset + fromIndex) }
            slice.get(out, 0, len)
        }
        return out
    }

    override fun asByteArray(): ByteArray = copyOfRange(0, size)

    override fun decodeToString(charset: Charset): String = String(asByteArray(), charset)
}
