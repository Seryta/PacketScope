package io.github.packetscope.core.dissector

import io.github.packetscope.core.extension.PcapdroidTrailerDecoder
import io.github.packetscope.core.pcap.Field
import io.github.packetscope.core.pcap.FieldNames
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.LinkType
import io.github.packetscope.core.pcap.Protocols
import io.github.packetscope.core.pcap.RawFrame
import io.github.packetscope.core.dissector.l2.EthernetDissector
import io.github.packetscope.core.dissector.l2.LinuxSllDissector
import io.github.packetscope.core.dissector.l2.LinuxSll2Dissector
import io.github.packetscope.core.dissector.l3.IPv4Dissector
import io.github.packetscope.core.dissector.l3.IPv6Dissector

/**
 * 把 [RawFrame] 喂给链式 dissector，产出已解析的 [Frame]。
 *
 * 主循环：根据 link type 选起点 dissector，然后跟着 [NextStep] 一直走，
 * 直到 dissector 返回 null 或 next == Done。
 */
class Pipeline(linkType: LinkType) {

    private val rootDissector: Dissector? = when (linkType) {
        LinkType.ETHERNET -> EthernetDissector
        LinkType.LINUX_SLL -> LinuxSllDissector
        LinkType.LINUX_SLL2 -> LinuxSll2Dissector
        LinkType.RAW_IP -> RawIpDissector
        LinkType.UNKNOWN -> null
    }

    fun process(raw: RawFrame): Frame {
        val layers = mutableListOf<Layer>()
        var dissector = rootDissector
        var offset = 0

        // dissector signature 仍是 (data: ByteArray, offset: Int)（LAZY-006 才动）。
        // Phase 1 在 Pipeline 入口短暂材料化整帧 ByteArray 给 dissector / trailer。
        // HeapBytes 路径下 asByteArray() 零拷贝；MmapBytes（Phase 2 后）会触发一次
        // copy，但 frame.data 持久化仍是 FrameBytes 视图，不留 ByteArray 在 Frame 上。
        val dataBytes: ByteArray = raw.data.asByteArray()

        // PCAPdroid 在 dump_extensions 模式下追加 32 字节 trailer；
        // dissect 时用裁短版避免污染 TCP/UDP payload 长度。byteRange 不需要调整
        // 因为 dissectData[i] 就是 raw.data[i]，只是末尾裁短了。
        val trailer = PcapdroidTrailerDecoder.tryDecode(dataBytes)
        val dissectData = if (trailer != null)
            dataBytes.copyOfRange(0, dataBytes.size - PcapdroidTrailerDecoder.SIZE)
        else dataBytes

        if (dissector != null) {
            var result: DissectResult? = dissector.dissect(dissectData, offset)
            while (result != null) {
                layers += result.layer
                // NextStep 把"继续 dissect" / "已 prefetch" / "结束"三种状态变成
                // 互斥的 sealed 分支（review v0.6-round3 F-003）
                result = when (val step = result.next) {
                    is NextStep.Continue -> {
                        if (step.offset >= dissectData.size) null
                        else step.dissector.dissect(dissectData, step.offset)
                    }
                    // fallback 探针已经 dissect 过了，直接消费——Prefetched.result
                    // 自身的 next 会在下一轮 loop 处理（Prefetched 自然递归）
                    is NextStep.Prefetched -> step.result
                    is NextStep.Done -> null
                }
            }
        }

        // 挂 PCAPdroid metadata layer（放最后，作为「这一帧来自哪个 app」展示）
        if (trailer != null) {
            val trailerStart = dataBytes.size - PcapdroidTrailerDecoder.SIZE
            layers += Layer(
                protocol = Protocols.PCAPDROID_META,
                byteRange = trailerStart..(dataBytes.size - 1),
                fields = listOf(
                    Field("Magic", "0x01072021", trailerStart..(trailerStart + 3)),
                    Field("UID", trailer.uid.toString(),
                        (trailerStart + 4)..(trailerStart + 7)),
                    Field(FieldNames.APP_NAME, trailer.appName,
                        (trailerStart + 8)..(trailerStart + 27)),
                    Field("FCS (CRC32)", "0x%08x".format(trailer.fcs),
                        (trailerStart + 28)..(trailerStart + 31)),
                ),
                summary = "${trailer.appName} (UID ${trailer.uid})",
            )
        }

        return Frame(
            index = raw.index,
            timestampNanos = raw.timestampNanos,
            capturedLength = raw.capturedLength,
            originalLength = raw.originalLength,
            data = raw.data,
            layers = layers,
        )
    }
}

/**
 * Raw IP link type：第一个字节的高 4 位告诉我们是 IPv4 (=4) 还是 IPv6 (=6)。
 * 单独放这里，因为它只是一个分派器，不算 L2 协议。
 */
private object RawIpDissector : Dissector {
    override fun dissect(data: ByteArray, offset: Int): DissectResult? {
        if (offset >= data.size) return null
        val version = (data[offset].toInt() ushr 4) and 0x0F
        val next = when (version) {
            4 -> IPv4Dissector
            6 -> IPv6Dissector
            else -> return null
        }
        // 不产生独立的 Layer，直接把控制权交给 IP dissector
        return next.dissect(data, offset)
    }
}
