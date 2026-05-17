package io.github.packetscope.core.stream

import io.github.packetscope.core.pcap.ByteReader
import io.github.packetscope.core.pcap.LinkType
import io.github.packetscope.core.pcap.RawFrame
import java.io.IOException

/**
 * 解析 PCAPdroid UDP Exporter 发出的 datagram。
 *
 * 协议（见 PCAPdroid pcap_dump.c）：
 *   1. 首个 datagram = 24B PCAP global header（native byte order，magic 决定 endian）
 *   2. 后续每个 datagram = 16B record header + body，对应一个完整 RawFrame
 *
 * 这个类**不**是线程安全的——调用方应在单个 socket 协程里串行使用。
 */
class UdpDatagramParser {

    private var littleEndian = true
    private var nanoseconds = false
    private var headerSeen = false
    private var nextIndex = 1

    var linkType: LinkType = LinkType.UNKNOWN
        private set

    val isReady: Boolean get() = headerSeen

    /**
     * 把首个 datagram 当作 PCAP global header 消费。
     * @return 推断出的 [LinkType]
     */
    fun consumeGlobalHeader(data: ByteArray): LinkType {
        if (data.size < 24) {
            throw IOException("Global header datagram too short: ${data.size}B (expected ≥ 24)")
        }
        val magic = ByteReader.u32Be(data, 0)
        val info = MAGIC_TABLE[magic]
            ?: throw IOException("Not a PCAP global header (magic=0x%08x)".format(magic))
        littleEndian = info.littleEndian
        nanoseconds = info.nanoseconds
        linkType = LinkType.fromValue(readU32(data, 20).toInt())
        headerSeen = true
        return linkType
    }

    /**
     * 错过 PCAPdroid 启动时的 global header 时（比如 PCAPdroid 抓包已经在跑，
     * PacketScope 才启动监听），用启发式参数初始化 parser，让后续 record 能
     * 解析。
     *
     * @param linkType 推断出的 link type
     * @param littleEndian Android 平台默认 LE
     * @param nanoseconds PCAPdroid 默认 microseconds
     */
    fun bootstrap(linkType: LinkType, littleEndian: Boolean = true, nanoseconds: Boolean = false) {
        this.linkType = linkType
        this.littleEndian = littleEndian
        this.nanoseconds = nanoseconds
        this.headerSeen = true
    }

    /**
     * 解析一个 record datagram。要求 [consumeGlobalHeader] 已经先调用过。
     */
    fun parseRecord(data: ByteArray): RawFrame {
        check(headerSeen) { "Global header must be received first" }
        if (data.size < 16) {
            throw IOException("Record datagram too short: ${data.size}B (expected ≥ 16)")
        }
        val tsSec = readU32(data, 0)
        val tsFrac = readU32(data, 4)
        val incLen = readU32(data, 8).toInt()
        val origLen = readU32(data, 12).toInt()
        if (incLen < 0 || 16 + incLen > data.size) {
            throw IOException("Record body length $incLen exceeds datagram size ${data.size}")
        }
        val body = data.copyOfRange(16, 16 + incLen)
        val ts = if (nanoseconds) tsSec * 1_000_000_000L + tsFrac
        else tsSec * 1_000_000_000L + tsFrac * 1_000L

        return RawFrame(
            index = nextIndex++,
            timestampNanos = ts,
            capturedLength = incLen,
            originalLength = origLen,
            data = body,
        )
    }

    private fun readU32(buf: ByteArray, offset: Int): Long =
        if (littleEndian) ByteReader.u32Le(buf, offset) else ByteReader.u32Be(buf, offset)

    private data class MagicInfo(val littleEndian: Boolean, val nanoseconds: Boolean)

    private companion object {
        private val MAGIC_TABLE = mapOf(
            0xa1b2c3d4L to MagicInfo(littleEndian = false, nanoseconds = false),
            0xd4c3b2a1L to MagicInfo(littleEndian = true, nanoseconds = false),
            0xa1b23c4dL to MagicInfo(littleEndian = false, nanoseconds = true),
            0x4d3cb2a1L to MagicInfo(littleEndian = true, nanoseconds = true),
        )
    }
}
