package io.github.packetscope.ui

import io.github.packetscope.core.pcap.LinkType
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * [PcapHandle] 是 LAZY-003 引入的 mmap 生命周期管理边界，主要责任是把 onClose
 * 钩子 idempotent 化（DisposableEffect 在不同 Compose 路径上可能多调一次 close）。
 */
class PcapHandleTest {

    @Test
    fun `close 调用 onClose 钩子一次`() {
        val count = AtomicInteger(0)
        val h = PcapHandle(
            linkType = LinkType.ETHERNET,
            frames = emptyList(),
            indices = emptyList(),
            onClose = { count.incrementAndGet() },
        )
        h.close()
        assertEquals(1, count.get())
    }

    @Test
    fun `重复 close idempotent 不会多次释放底层资源`() {
        val count = AtomicInteger(0)
        val h = PcapHandle(
            linkType = LinkType.ETHERNET,
            frames = emptyList(),
            indices = emptyList(),
            onClose = { count.incrementAndGet() },
        )
        h.close()
        h.close()
        h.close()
        assertEquals("onClose 在多次 close 后仍只触发一次", 1, count.get())
    }

    @Test
    fun `未 close 时 onClose 不触发`() {
        val count = AtomicInteger(0)
        @Suppress("UNUSED_VARIABLE")
        val h = PcapHandle(
            linkType = LinkType.ETHERNET,
            frames = emptyList(),
            indices = emptyList(),
            onClose = { count.incrementAndGet() },
        )
        // 不调 close —— 模拟 PcapHandle 还在 active 使用中
        assertEquals(0, count.get())
    }
}
