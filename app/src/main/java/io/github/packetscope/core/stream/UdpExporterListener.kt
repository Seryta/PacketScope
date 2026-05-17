package io.github.packetscope.core.stream

import android.util.Log
import io.github.packetscope.BuildConfig
import io.github.packetscope.core.dissector.Pipeline
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.LinkType
import io.github.packetscope.core.pcap.RawFrame
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.isActive
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketException

/**
 * 监听 PCAPdroid UDP Exporter 模式发出的 datagram，把每个数据包解析成 [Frame]。
 *
 * 用法：
 * ```kotlin
 * LaunchedEffect(port) {
 *     UdpExporterListener.events(port).collect { event -> ... }
 * }
 * ```
 *
 * 不引入 ForegroundService —— 协程 cancel 时 socket 自动关闭，切后台时 listener 停。
 * v0.8 再加 Service 解决 background。
 */
object UdpExporterListener {

    private const val MAX_DATAGRAM = 65535 + 64

    /**
     * 错过 global header 时根据 record body 起始字节推断 link type：
     *   - 第 17 字节高 4 位 == 4 或 6 → IP 包直挂，RAW_IP
     *   - 否则 → 带（假）Ethernet 头，ETHERNET（PCAPdroid dump_extensions 模式）
     */
    private fun inferLinkTypeFromRecord(data: ByteArray): LinkType? {
        if (data.size < 17) return null
        val firstByte = data[16].toInt() and 0xFF
        return when (firstByte ushr 4) {
            4, 6 -> LinkType.RAW_IP
            else -> LinkType.ETHERNET
        }
    }

    /**
     * 返回的 Flow 在 cancel 时关闭 socket。Flow 是冷流，每次 collect 都会绑定一次端口。
     */
    fun events(port: Int): Flow<StreamEvent> = callbackFlow {
        // 用未绑定的 DatagramSocket + reuseAddress = true 再 bind，避免
        // service 快速重启时旧 socket 未完全释放就报 BindException
        val socket = try {
            DatagramSocket(null as java.net.SocketAddress?).apply {
                reuseAddress = true
                bind(InetSocketAddress(port))
            }
        } catch (e: Exception) {
            trySend(StreamEvent.Error("绑定端口 $port 失败: ${e.message}"))
            close()
            return@callbackFlow
        }

        trySend(StreamEvent.Listening)

        val parser = UdpDatagramParser()
        var pipeline: Pipeline? = null
        val buf = ByteArray(MAX_DATAGRAM)
        var parseFailures = 0

        try {
            while (currentCoroutineContext().isActive) {
                val packet = DatagramPacket(buf, buf.size)
                socket.receive(packet)
                val data = buf.copyOfRange(0, packet.length)

                if (!parser.isReady) {
                    // 路径 1：当作 global header（PCAPdroid 抓包刚开始时的第一个 datagram）
                    val globalHeaderLinkType = runCatching {
                        parser.consumeGlobalHeader(data)
                    }.onFailure { logDebug("consumeGlobalHeader 失败（可能是 record，转 path 2）", it) }
                        .getOrNull()

                    if (globalHeaderLinkType != null) {
                        pipeline = Pipeline(globalHeaderLinkType)
                        trySend(StreamEvent.Capturing(globalHeaderLinkType))
                        continue
                    }

                    // 路径 2：错过 global header（PCAPdroid 已经在跑，我们后启动）。
                    // 启发式判断 linkType：record body 第 1 字节高 4 位 == 4/6 时是 RAW_IP，
                    // 否则按 ETHERNET 处理（PCAPdroid dump_extensions 模式）。
                    val inferred = inferLinkTypeFromRecord(data) ?: continue
                    parser.bootstrap(inferred)
                    pipeline = Pipeline(inferred)
                    trySend(StreamEvent.Capturing(inferred))
                    // 本帧也当 record 处理，不丢
                    val raw = runCatching { parser.parseRecord(data) }
                        .onFailure { logDebug("bootstrap 首帧 parseRecord 失败", it); parseFailures++ }
                        .getOrNull() ?: continue
                    val frame = pipeline!!.process(raw)
                    trySend(StreamEvent.FrameReceived(frame))
                } else {
                    try {
                        val raw = parser.parseRecord(data)
                        val frame = pipeline!!.process(raw)
                        trySend(StreamEvent.FrameReceived(frame))
                    } catch (e: Exception) {
                        // 个别 malformed datagram 跳过，但记日志便于线上排查
                        logDebug("parseRecord / dissect 失败 (#$parseFailures)", e)
                        parseFailures++
                    }
                }
            }
        } catch (_: SocketException) {
            // socket.close() 触发的退出，正常情况
        } catch (e: Exception) {
            trySend(StreamEvent.Error(e.message ?: "未知错误"))
        }

        awaitClose { socket.close() }
    }.flowOn(Dispatchers.IO)

    private const val TAG = "UdpExporterListener"

    /** debug build 才打日志，release 静默 —— 不要把 PCAPdroid 协议变化暴露到生产 logcat */
    private fun logDebug(message: String, throwable: Throwable? = null) {
        if (!BuildConfig.DEBUG) return
        if (throwable != null) Log.d(TAG, message, throwable) else Log.d(TAG, message)
    }
}

sealed interface StreamEvent {
    /** Socket 已绑定，等待 PCAPdroid 第一个 datagram */
    data object Listening : StreamEvent

    /** 收到 global header，知道了 link type，正式开始接收 frame */
    data class Capturing(val linkType: LinkType) : StreamEvent

    /** 收到并解析了一个 frame */
    data class FrameReceived(val frame: Frame) : StreamEvent

    /** 不可恢复的错误（socket 绑定失败等） */
    data class Error(val message: String) : StreamEvent
}
