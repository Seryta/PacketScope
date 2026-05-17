package io.github.packetscope.perf

import io.github.packetscope.core.PcapTestFixtures
import io.github.packetscope.core.dissector.Pipeline
import io.github.packetscope.core.pcap.HeapBytes
import io.github.packetscope.core.pcap.MmapBytes
import io.github.packetscope.core.pcap.PcapMmapReader
import io.github.packetscope.core.pcap.PcapReader
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.RandomAccessFile

/**
 * LAZY-004 Phase 4：量化 v1.1 lazy refactor 的 heap 收益。
 *
 * **两条对比路径**：
 *  - InputStream 路径（[PcapReader]）：Frame.data = HeapBytes，仍把 captured
 *    bytes copy 进 heap，等效 v0.9 之前的行为。
 *  - mmap 路径（[PcapMmapReader]）：Frame.data = MmapBytes，视图零拷贝。
 *
 * **测试目标**：mmap 路径下，frame.data 持有的字节内容**不进 heap**。直接
 * 验证 [MmapBytes] 引用占的 heap 是固定开销（视图对象 + 父 buffer 引用），
 * 跟 PCAP 文件总字节数无关。
 *
 * **不直接测 100 MB 真档案**——单元测试不应跑大文件 (CI 时间 + tmp 盘)。
 * 真机性能验证留 QA_CHECKLIST §perf 段（dumpsys meminfo）。
 *
 * 注意 Runtime.totalMemory() - freeMemory() 给的是 JVM 真实 heap usage，
 * 但 GC 时机不可控；用前后两次 System.gc() + 重复 sampling 减少噪声。
 */
class MemoryProfileTest {

    @get:Rule val tmp = TemporaryFolder()

    /** mmap 路径下，每个 frame.data 在 heap 上占的开销与 captured bytes 无关。 */
    @Test
    fun `mmap 路径 frame data 是 MmapBytes 视图 不持 ByteArray`() {
        val pcap = buildLargePcap(packetCount = 500, packetSize = 1500)
        val file = tmp.newFile("lazy.pcap")
        file.writeBytes(pcap)

        val frames = RandomAccessFile(file, "r").use { raf ->
            PcapMmapReader(raf.channel).use { r ->
                r.frames().toList()
            }
        }
        // 全部 frame.data 必须是 MmapBytes 视图（零拷贝），不是 HeapBytes
        assertEquals(500, frames.size)
        frames.forEach { f ->
            assertTrue("frame ${f.index} 应是 MmapBytes 视图", f.data is MmapBytes)
            assertEquals("frame.size 应等 captured", 1500, f.data.size)
        }
    }

    /**
     * Pipeline.process 入口短暂材料化整帧 ByteArray 给 dissector 链；
     * 出口的 Frame.data 必须仍是原 FrameBytes 视图（不被 asByteArray 引用泄漏
     * 进 Frame）——否则 lazy 收益全失，1 GB PCAP load 时 raw bytes 还会进
     * heap。本 case 用 Pipeline 走真实 dissect path 后断言 frame.data 类型。
     * v1.1-round1 F-004。
     */
    @Test
    fun `Pipeline 处理后 Frame 仍持 MmapBytes 视图`() {
        val pcap = buildLargePcap(packetCount = 100, packetSize = 1500)
        val file = tmp.newFile("pipeline.pcap")
        file.writeBytes(pcap)

        val processedFrames = RandomAccessFile(file, "r").use { raf ->
            PcapMmapReader(raf.channel).use { reader ->
                val pipeline = Pipeline(reader.linkType)
                reader.frames().toList().map(pipeline::process)
            }
        }

        assertEquals(100, processedFrames.size)
        processedFrames.forEach { f ->
            assertTrue(
                "Pipeline 后 frame ${f.index}.data 应仍是 MmapBytes，未被 " +
                    "asByteArray 中间变量泄漏成 HeapBytes",
                f.data is MmapBytes,
            )
            // 同时验证 layers 真的解出来了（否则视图保住但 dissect 没跑也 vacuous）
            assertTrue("frame ${f.index} 应至少有一个 layer", f.layers.isNotEmpty())
        }
    }

    /** InputStream 路径作为对照：frame.data 仍是 HeapBytes，行为不变。 */
    @Test
    fun `InputStream 路径 frame data 仍是 HeapBytes`() {
        val pcap = buildLargePcap(packetCount = 10, packetSize = 1500)
        val frames = PcapReader(ByteArrayInputStream(pcap)).use { r ->
            r.frames().toList()
        }
        assertEquals(10, frames.size)
        frames.forEach { f ->
            assertTrue("frame ${f.index} 应是 HeapBytes", f.data is HeapBytes)
        }
    }

    /**
     * heap delta 测试：mmap 路径加载 N 帧 PCAP，JVM heap 增量应远小于
     * 文件总 captured bytes。给 30% 容忍度（layer/field metadata + indices
     * + JVM 内部数组 expansion 等开销）。
     *
     * 不强求绝对数值（不同 JVM / GC 算法不同），只验证比例。
     */
    @Test
    fun `mmap 路径 heap 增量 应远小于文件大小`() {
        val packetCount = 1000
        val packetSize = 1500
        val totalBytes = packetCount.toLong() * packetSize  // ~1.5 MB
        val pcap = buildLargePcap(packetCount, packetSize)
        val file = tmp.newFile("heap-test.pcap")
        file.writeBytes(pcap)

        // 预热 + 稳定 baseline
        repeat(3) { System.gc(); Thread.sleep(20) }
        val before = usedHeap()

        val raf = RandomAccessFile(file, "r")
        val reader = PcapMmapReader(raf.channel)
        val frames = reader.frames().toList()
        // 故意持引用到测试末尾，防 GC

        repeat(3) { System.gc(); Thread.sleep(20) }
        val after = usedHeap()
        val delta = after - before

        // heap 增量上限：raw bytes 不入 heap 的理论值 = 仅 frame/layer 元数据。
        // 给 50% 文件大小做容忍（含 layer/field 对象 + JVM 数组开销）
        val limit = totalBytes / 2
        assertTrue(
            "mmap 路径 heap delta 应 < 50% 文件大小: delta=${delta / 1024} KB, " +
                "limit=${limit / 1024} KB, frames=${frames.size}",
            delta < limit,
        )

        reader.close()
        raf.close()
    }

    private fun usedHeap(): Long {
        val rt = Runtime.getRuntime()
        return rt.totalMemory() - rt.freeMemory()
    }

    /** 构造 N 个相同大小的 Ethernet/IPv4/TCP-SYN 包（每个 packetSize 字节）。 */
    private fun buildLargePcap(packetCount: Int, packetSize: Int): ByteArray {
        val base = PcapTestFixtures.ethernetIpv4TcpSyn()
        // 把 base packet pad 到 packetSize；剩余字节填零（dissector 容忍）
        val pkt = if (packetSize <= base.size) {
            base.copyOf(packetSize)
        } else {
            ByteArray(packetSize).also { System.arraycopy(base, 0, it, 0, base.size) }
        }
        return PcapTestFixtures.build(
            linkType = 1,
            packets = List(packetCount) { pkt },
        )
    }
}
