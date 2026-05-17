package io.github.packetscope.core.dissector

import io.github.packetscope.core.pcap.Layer

/**
 * 协议解析器。每个 dissector 只负责自己这一层，返回本层 Layer 和下一步动作（如有）。
 *
 * 这种链式设计的目的：
 *   - 解耦：每个协议一个文件，互不依赖
 *   - 易扩展：v0.4 加 DNS/TLS handshake 时只是新增 dissector + 在父层 next 里加分支
 *   - 测试方便：每个 dissector 可独立单测
 */
fun interface Dissector {
    /**
     * @param data 完整 frame 字节
     * @param offset 本层起始字节偏移
     * @return 解析结果；null 表示数据不足/无法解析（调用方决定如何展示）
     */
    fun dissect(data: ByteArray, offset: Int): DissectResult?
}

/**
 * Pipeline 主循环消费的下一步动作。sealed 让"调用者继续 dissect" / "已经预算好下一层
 * 结果" / "链终止" 三种状态互斥，不会出现两个字段同时非空的语义模糊
 * （review v0.6-round3 F-003）。
 */
sealed interface NextStep {
    /** 让 Pipeline 用 [dissector] 在 [offset] 继续 dissect 下一层 */
    data class Continue(val offset: Int, val dissector: Dissector) : NextStep

    /** 下一层已被探针 dissect 完毕，Pipeline 直接 append 这个 [result] 并消费它的
     *  `next`（自然递归）；不要再调 dissect。 */
    data class Prefetched(val result: DissectResult) : NextStep

    /** 链到此结束 */
    data object Done : NextStep
}

data class DissectResult(
    val layer: Layer,
    val next: NextStep = NextStep.Done,
)
