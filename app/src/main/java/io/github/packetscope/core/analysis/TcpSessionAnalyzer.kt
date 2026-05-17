package io.github.packetscope.core.analysis

import io.github.packetscope.core.pcap.ByteReader
import io.github.packetscope.core.pcap.Field
import io.github.packetscope.core.pcap.FieldNames
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols

/**
 * 后处理 pass：按五元组聚类 TCP frame，计算相对 Seq/Ack 和重传标记，
 * 把结果作为 Field 挂回 TCP layer，并在 summary 末尾追加 [TCP Retransmission] 等标签。
 *
 * v0.11 只做重传检测；out-of-order / dup-ack 留后续版本。
 */
object TcpSessionAnalyzer {

    private const val PCAPDROID_TRAILER_SIZE = 32

    fun process(frames: List<Frame>): List<Frame> {
        val infos = frames.mapNotNull(::extractTcpInfo)
        if (infos.isEmpty()) return frames

        val sessions = infos.groupBy(::sessionKey)
        val analyses = mutableMapOf<Int, TcpAnalysis>()
        for ((_, list) in sessions) {
            analyzeSession(list.sortedBy { it.frameIndex }, analyses)
        }

        if (analyses.isEmpty()) return frames
        return frames.map { f ->
            val a = analyses[f.index] ?: return@map f
            apply(f, a)
        }
    }

    // ─── 内部数据类 ───────────────────────────────────────────────

    private data class TcpEndpoint(val ip: String, val port: Int)

    private data class TcpInfo(
        val frameIndex: Int,
        val src: TcpEndpoint,
        val dst: TcpEndpoint,
        val seq: Long,
        val ack: Long,
        val flags: Int,
        val payloadLen: Int,
    )

    private data class TcpAnalysis(
        val relativeSeq: Long?,
        val relativeAck: Long?,
        val tags: List<String>,
    )

    // ─── 抽取 ─────────────────────────────────────────────────────

    private fun extractTcpInfo(frame: Frame): TcpInfo? {
        val tcp = frame.layers.firstOrNull { it.protocol == Protocols.TCP } ?: return null
        val ip = frame.layers.firstOrNull { it.protocol == Protocols.IPV4 || it.protocol == Protocols.IPV6 }
            ?: return null
        val srcIp = ip.fields.firstOrNull { it.name == FieldNames.SOURCE }?.value ?: return null
        val dstIp = ip.fields.firstOrNull { it.name == FieldNames.DESTINATION }?.value ?: return null
        val tcpStart = tcp.byteRange.first
        val data = frame.data
        if (tcpStart + 14 > data.size) return null

        val srcPort = ByteReader.u16Be(data, tcpStart)
        val dstPort = ByteReader.u16Be(data, tcpStart + 2)
        val seq = ByteReader.u32Be(data, tcpStart + 4)
        val ack = ByteReader.u32Be(data, tcpStart + 8)
        val flags = data[tcpStart + 13].toInt() and 0xFF
        val payloadLen = payloadLength(frame, tcp)

        return TcpInfo(
            frameIndex = frame.index,
            src = TcpEndpoint(srcIp, srcPort),
            dst = TcpEndpoint(dstIp, dstPort),
            seq = seq, ack = ack, flags = flags,
            payloadLen = payloadLen,
        )
    }

    private fun payloadLength(frame: Frame, tcpLayer: Layer): Int {
        // 排除 PCAPdroid trailer 32B 干扰
        val hasTrailer = frame.layers.any { it.protocol == Protocols.PCAPDROID_META }
        val end = if (hasTrailer) frame.data.size - PCAPDROID_TRAILER_SIZE else frame.data.size
        return (end - (tcpLayer.byteRange.last + 1)).coerceAtLeast(0)
    }

    private fun sessionKey(info: TcpInfo): String {
        val a = "${info.src.ip}:${info.src.port}"
        val b = "${info.dst.ip}:${info.dst.port}"
        return if (a < b) "$a|$b" else "$b|$a"
    }

    // ─── 分析 ─────────────────────────────────────────────────────

    private fun analyzeSession(infos: List<TcpInfo>, out: MutableMap<Int, TcpAnalysis>) {
        // 确定 client side：第一个仅 SYN（无 ACK）的包发起方；没有 SYN 时
        // 退化为第一个 packet 的源
        val firstSyn = infos.firstOrNull {
            (it.flags and 0x02) != 0 && (it.flags and 0x10) == 0
        }
        val client = firstSyn?.src ?: infos.first().src

        var clientIsn: Long? = null
        var serverIsn: Long? = null
        val seenClient = mutableSetOf<Pair<Long, Int>>()
        val seenServer = mutableSetOf<Pair<Long, Int>>()
        // 每方向迄今为止见过的最大 seq+len（期望的下个 seq）
        var nextSeqClient: Long? = null
        var nextSeqServer: Long? = null
        // 每方向 Dup ACK：上次 ack 值 + 连续相同次数
        var lastAckClient: Long? = null
        var dupAckClient = 0
        var lastAckServer: Long? = null
        var dupAckServer = 0

        for (info in infos) {
            val fromClient = info.src == client
            val isSyn = (info.flags and 0x02) != 0
            val isAck = (info.flags and 0x10) != 0

            if (fromClient) {
                if (clientIsn == null || (isSyn && !isAck)) clientIsn = info.seq
            } else {
                if (serverIsn == null || (isSyn && !isAck)) serverIsn = info.seq
                if (isSyn && isAck) serverIsn = info.seq
            }

            val relSeq = (if (fromClient) clientIsn else serverIsn)
                ?.let { (info.seq - it) and 0xFFFFFFFFL }
            val relAck = if (isAck) {
                (if (fromClient) serverIsn else clientIsn)
                    ?.let { (info.ack - it) and 0xFFFFFFFFL }
            } else null

            val tags = mutableListOf<String>()

            if (info.payloadLen > 0) {
                val seen = if (fromClient) seenClient else seenServer
                val nextSeq = if (fromClient) nextSeqClient else nextSeqServer
                val key = info.seq to info.payloadLen
                val isRetrans = key in seen
                if (isRetrans) {
                    tags += "TCP Retransmission"
                } else if (nextSeq != null && info.seq < nextSeq) {
                    tags += "TCP Out-Of-Order"
                }
                seen += key
                val seqEnd = info.seq + info.payloadLen
                if (fromClient) {
                    if (nextSeqClient == null || seqEnd > nextSeqClient!!) nextSeqClient = seqEnd
                } else {
                    if (nextSeqServer == null || seqEnd > nextSeqServer!!) nextSeqServer = seqEnd
                }
            }

            // Dup ACK：纯 ACK 包（len=0）+ ack 值与上次相同
            if (isAck && info.payloadLen == 0 && !isSyn) {
                if (fromClient) {
                    if (info.ack == lastAckClient) {
                        dupAckClient++
                        tags += "TCP Dup ACK #$dupAckClient"
                    } else {
                        lastAckClient = info.ack
                        dupAckClient = 0
                    }
                } else {
                    if (info.ack == lastAckServer) {
                        dupAckServer++
                        tags += "TCP Dup ACK #$dupAckServer"
                    } else {
                        lastAckServer = info.ack
                        dupAckServer = 0
                    }
                }
            }

            out[info.frameIndex] = TcpAnalysis(relSeq, relAck, tags)
        }
    }

    // ─── 应用 ─────────────────────────────────────────────────────

    private fun apply(frame: Frame, a: TcpAnalysis): Frame {
        val tcp = frame.layers.firstOrNull { it.protocol == Protocols.TCP } ?: return frame
        val extras = mutableListOf<Field>()
        a.relativeSeq?.let { extras += Field("Relative Seq", it.toString()) }
        a.relativeAck?.let { extras += Field("Relative Ack", it.toString()) }
        if (a.tags.isNotEmpty()) {
            extras += Field("TCP Analysis", a.tags.joinToString(", "))
        }
        if (extras.isEmpty()) return frame

        val newSummary = if (a.tags.isNotEmpty()) {
            "${tcp.summary}  [${a.tags.joinToString(", ")}]"
        } else tcp.summary

        val newTcp = tcp.copy(fields = tcp.fields + extras, summary = newSummary)
        val newLayers = frame.layers.map { if (it === tcp) newTcp else it }
        return frame.copy(layers = newLayers)
    }
}
