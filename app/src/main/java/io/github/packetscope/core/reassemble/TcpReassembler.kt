package io.github.packetscope.core.reassemble

import io.github.packetscope.core.pcap.ByteReader
import io.github.packetscope.core.pcap.FieldNames
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols

/**
 * TCP 流重组 v1（基础版）。
 *
 * 输入一批 [Frame]，按 4-tuple 聚类成 TCP session，每个 session 维护
 * client→server 与 server→client 两个方向的 ordered byte stream：
 *
 * - SYN 包确定 ISN（initial seq number），下个期望 seq = ISN+1；无 SYN 的
 *   stream 以第一个 payload 的 seq 起始
 * - 后续 payload 按 expected seq 拼接：seq 早于 expected 视为重传 / overlap，
 *   截掉已见部分；seq 晚于 expected 视为乱序 / gap，简化版直接跳到新 seq
 *   （不等补齐——MVP 接受 best-effort，跟 Wireshark 行为一致）
 * - FIN / RST 不打断已收集数据，下游能拿到完整 bytes
 *
 * 不处理 32-bit Seq wrap-around（>4GB 单流才会触发，v0.9 lazy paging 一起做）。
 *
 * 输出 [TcpStream]：含双向 [ReassembledFlow]，flow 提供 ordered bytes +
 * (frameIndex, range in bytes) 反查表，给下游 HTTP body 解析 / Follow Stream
 * "拼接视图" 用。
 */
object TcpReassembler {

    /** 重组所有 TCP frames。key 是 4-tuple canonical key（端点字典序排序）。 */
    fun assemble(frames: List<Frame>): Map<String, TcpStream> {
        val streams = mutableMapOf<String, TcpStream>()
        for (frame in frames) addFrame(frame, streams)
        return streams
    }

    private fun addFrame(frame: Frame, streams: MutableMap<String, TcpStream>) {
        runCatching {
            val info = checkNotNull(extractTcpInfo(frame))
            val key = canonicalKey(info.src, info.dst)
            val stream = streams.getOrPut(key) {
                TcpStream(clientEp = info.src, serverEp = info.dst)
            }
            val isFromClient = info.src == stream.clientEp
            val flow = if (isFromClient) stream.clientToServer else stream.serverToClient
            if (info.isSyn) {
                flow.isn = info.seq
                flow.nextSeq = (info.seq + 1) and 0xFFFFFFFFL
            }
            if (info.payload.isNotEmpty()) {
                // SYN 占 1 个 sequence number，所以 SYN+data 包的 data 真实 seq
                // = info.seq + 1（review v0.6-round7 F-002）；普通 data 包直接用
                // info.seq。不修正会被 appendPayload 当作"已见 SYN-byte 的重传"
                // 截掉首字节
                val dataSeq = if (info.isSyn) (info.seq + 1) and 0xFFFFFFFFL else info.seq
                flow.appendPayload(dataSeq, info.payload, frame.index)
            }
        }
    }

    private fun canonicalKey(a: TcpEndpoint, b: TcpEndpoint): String {
        val sa = "${a.ip}:${a.port}"
        val sb = "${b.ip}:${b.port}"
        return if (sa < sb) "$sa|$sb" else "$sb|$sa"
    }

    /** 从 [Frame] 提取 TCP 关键字段。失败 / 非 TCP 返回 null。 */
    private fun extractTcpInfo(frame: Frame): TcpFrameInfo? = runCatching {
        val tcp = checkNotNull(frame.layers.firstOrNull { it.protocol == Protocols.TCP })
        val ip = checkNotNull(frame.layers.firstOrNull {
            it.protocol == Protocols.IPV4 || it.protocol == Protocols.IPV6
        })
        val srcIp = checkNotNull(ip.fields.firstOrNull { it.name == FieldNames.SOURCE }).value
        val dstIp = checkNotNull(ip.fields.firstOrNull { it.name == FieldNames.DESTINATION }).value
        val tcpStart = tcp.byteRange.first
        val data = frame.data
        require(tcpStart + 14 <= data.size)
        val srcPort = ByteReader.u16Be(data, tcpStart)
        val dstPort = ByteReader.u16Be(data, tcpStart + 2)
        val seq = ByteReader.u32Be(data, tcpStart + 4)
        val flags = data[tcpStart + 13].toInt() and 0xFF
        val payload = extractPayload(frame, tcp)
        TcpFrameInfo(
            src = TcpEndpoint(srcIp, srcPort),
            dst = TcpEndpoint(dstIp, dstPort),
            seq = seq,
            isSyn = flags and 0x02 != 0,
            payload = payload,
        )
    }.getOrNull()

    /** payload = TCP 数据段（剥除 PCAPdroid trailer） */
    private fun extractPayload(frame: Frame, tcp: Layer): ByteArray {
        val hasTrailer = frame.layers.any { it.protocol == Protocols.PCAPDROID_META }
        val end = if (hasTrailer) frame.data.size - PCAPDROID_TRAILER_SIZE else frame.data.size
        val start = tcp.byteRange.last + 1
        if (start >= end) return ByteArray(0)
        return frame.data.copyOfRange(start, end)
    }

    private const val PCAPDROID_TRAILER_SIZE = 32
}

data class TcpEndpoint(val ip: String, val port: Int)

class TcpStream(
    val clientEp: TcpEndpoint,
    val serverEp: TcpEndpoint,
    val clientToServer: ReassembledFlow = ReassembledFlow(),
    val serverToClient: ReassembledFlow = ReassembledFlow(),
)

/**
 * 单方向的 ordered byte stream。
 *
 * [data] 是按 seq 顺序拼接后的去重 bytes；[chunks] 记录每段来自哪一帧
 * （给 UI 反查"这段数据来自第 #N 包"）。
 *
 * 不直接暴露 mutable list / array，写操作走 [appendPayload]。
 */
class ReassembledFlow {
    /** ISN（SYN 包 seq），用来算相对 seq；无 SYN 时为 null */
    var isn: Long? = null
        internal set

    /** 期望下个 segment 的 absolute seq；null 表示流尚未收到数据 */
    var nextSeq: Long? = null
        internal set

    private val buf = java.io.ByteArrayOutputStream()
    private val chunkList = mutableListOf<Chunk>()

    val data: ByteArray get() = buf.toByteArray()
    val chunks: List<Chunk> get() = chunkList

    /**
     * 把一段 payload 按 seq 拼到 flow 末尾。
     *
     * - seq < expected: 重传 / overlap，截掉 expected-seq 字节的已见部分
     * - seq == expected: 顺序到达，直接 append
     * - seq > expected: gap，丢失 seq-expected 字节；为了让 HTTP body 解析仍可
     *   推进，直接 advance expected 到 seq（best-effort，跟 Wireshark 一致）
     *
     * @return true 表示有新数据 appended，false 表示完全重传被吞
     */
    internal fun appendPayload(seq: Long, payload: ByteArray, frameIndex: Int): Boolean {
        val expected = nextSeq
        if (expected == null) {
            // 流上首个 payload — 以它 seq 起始
            nextSeq = seq
            return appendPayload(seq, payload, frameIndex)
        }
        return when {
            seq < expected -> handleRetransmit(seq, payload, frameIndex, expected)
            seq == expected -> appendInOrder(seq, payload, frameIndex)
            else -> {                          // seq > expected (gap)
                nextSeq = seq                  // best-effort 跳过 hole
                appendInOrder(seq, payload, frameIndex)
            }
        }
    }

    private fun handleRetransmit(
        seq: Long, payload: ByteArray, frameIndex: Int, expected: Long,
    ): Boolean {
        val skip = (expected - seq).toInt()
        if (skip >= payload.size) return false
        val fresh = payload.copyOfRange(skip, payload.size)
        return appendInOrder(expected, fresh, frameIndex)
    }

    private fun appendInOrder(seq: Long, payload: ByteArray, frameIndex: Int): Boolean {
        val offset = buf.size()
        buf.write(payload)
        chunkList += Chunk(frameIndex, seq, offset, payload.size)
        nextSeq = seq + payload.size
        return true
    }
}

/** 一条 chunk 在 reassembled byte stream 中的位置 + 来源 frame index */
class Chunk(
    val frameIndex: Int,
    /** 绝对 TCP seq（保留原值，不减 ISN） */
    val seq: Long,
    /** chunk 在 ReassembledFlow.data 内的起始 byte offset */
    val dataOffset: Int,
    val length: Int,
)

private class TcpFrameInfo(
    val src: TcpEndpoint,
    val dst: TcpEndpoint,
    val seq: Long,
    val isSyn: Boolean,
    val payload: ByteArray,
)
