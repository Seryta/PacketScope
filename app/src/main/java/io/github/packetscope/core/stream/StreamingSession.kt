package io.github.packetscope.core.stream

import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.LinkType

/**
 * 进程级别的实时监听状态。
 *
 * 设计取舍：用 Compose runtime 的 mutableStateOf/mutableStateListOf 而不是 StateFlow，
 * 因为 UI 全程在 Compose 里，Compose state 在跨 Activity 重建时也能存活（只要进程在），
 * 且写读端不需要 collectAsState 这层间接。
 *
 * 写入：UdpExporterService 协程串行写。
 * 读取：UI Composable 直接读。Snapshot 系统保证读写一致。
 */
object StreamingSession {
    val frames = mutableStateListOf<Frame>()
    val linkType = mutableStateOf(LinkType.UNKNOWN)
    val port = mutableIntStateOf(0)
    val status = mutableStateOf<String?>(null)
    val isRunning = mutableStateOf(false)

    fun reset() {
        frames.clear()
        linkType.value = LinkType.UNKNOWN
        port.intValue = 0
        status.value = null
        isRunning.value = false
    }
}
