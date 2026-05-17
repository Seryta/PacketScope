package io.github.packetscope.ui

import io.github.packetscope.core.filter.FilterIndex
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.LinkType
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 一次 PCAP 加载的所有产物 + 底层资源。LAZY-003 引入：把 mmap 生命周期从
 * [io.github.packetscope.core.pcap.PcapMmapReader.close] 抽出来，由本类显式
 * 管理，让 MmapBytes 视图在使用期间保持 alive，资源释放跟 UI state 切换时机
 * 对齐。
 *
 * **使用契约**：
 * 1. UI 持 [PcapHandle] 引用期间，可以自由访问 [frames] / [indices]，其中
 *    Frame.data 可能是 MmapBytes 视图——本类的 [onClose] 守住 mmap 不被
 *    提前 unmap。
 * 2. AppScreen 切换到非 Loaded 状态时调 [close]，触发 [onClose]（mmap 路径
 *    下做 reflection unmap，InputStream 路径下 no-op）。
 * 3. [close] 之后所有 Frame.data 访问行为 undefined（SIGSEGV / 异常 / 脏
 *    数据）。调用方必须先 drop 对 frames 的引用再 close。
 *
 * **GC 兜底**：reflection unmap 在 Android API 28+ 可能失败（hidden API
 * restriction），失败时 fallback 到 GC + finalizer 自然回收——跟 v0.9 行为
 * 一致，不会更差，只是大 PCAP 累积时 vmem 释放有延迟。
 */
class PcapHandle(
    val linkType: LinkType,
    val frames: List<Frame>,
    val indices: List<FilterIndex>,
    private val onClose: () -> Unit,
) : AutoCloseable {
    // v1.1-round1 F-002：原 @Volatile + check-then-set 两线程并发能进同一分支
    // 双触发 onClose。AtomicBoolean.compareAndSet 是 atomic test-and-set，
    // onClose 严格 exactly-once。零开销改动。
    private val closed = AtomicBoolean(false)

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        onClose()
    }
}
