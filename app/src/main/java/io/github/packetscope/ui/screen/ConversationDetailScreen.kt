package io.github.packetscope.ui.screen

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.packetscope.R
import io.github.packetscope.core.analysis.Conversation
import io.github.packetscope.core.pcap.FieldNames
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols

private val MonoFont = FontFamily.Monospace

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationDetailScreen(
    conversation: Conversation,
    allFrames: List<Frame>,
    onBack: () -> Unit,
    onFollowStream: (Frame) -> Unit = {},
) {
    BackHandler(onBack = onBack)

    val sessionFrames = remember(allFrames.size, conversation) {
        findSessionFrames(allFrames, conversation)
    }
    val stats = remember(sessionFrames.size, conversation) {
        computeStats(sessionFrames, conversation)
    }
    val tcpAnchor = sessionFrames.firstOrNull { f ->
        f.layers.any { it.protocol == Protocols.TCP }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(stringResource(R.string.conv_detail_title))
                        val packetsText = pluralStringResource(
                            R.plurals.count_packets, conversation.packets, conversation.packets)
                        Text("${conversation.protocol} · $packetsText",
                            style = MaterialTheme.typography.bodySmall)
                    }
                },
                navigationIcon = {
                    TextButton(onClick = onBack) {
                        Text(stringResource(R.string.action_back))
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
        ) {
            // Endpoints 卡片
            Card {
                Column(modifier = Modifier.padding(12.dp)) {
                    SectionLabel(stringResource(R.string.conv_section_endpoints))
                    Text(conversation.endpointA,
                        fontFamily = MonoFont, fontSize = 13.sp,
                        modifier = Modifier.padding(top = 4.dp))
                    Text("↕", fontSize = 14.sp, color = Color(0xFF888888),
                        modifier = Modifier.padding(start = 4.dp))
                    Text(conversation.endpointB,
                        fontFamily = MonoFont, fontSize = 13.sp)

                    conversation.appName?.let { name ->
                        Spacer(modifier = Modifier.height(8.dp))
                        Row {
                            Text(stringResource(R.string.conv_app_label),
                                style = MaterialTheme.typography.labelSmall,
                                color = Color(0xFF666666))
                            // 资源里不带尾随空格，间距用 Spacer 补
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(name, fontFamily = MonoFont, fontSize = 12.sp)
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // 统计卡片
            Card {
                Column(modifier = Modifier.padding(12.dp)) {
                    SectionLabel(stringResource(R.string.conv_section_stats))
                    StatRow(stringResource(R.string.conv_stat_total_packets),
                        conversation.packets.toString())
                    StatRow(stringResource(R.string.conv_stat_total_bytes),
                        formatBytes(conversation.bytes))
                    StatRow(stringResource(R.string.conv_stat_duration),
                        formatDuration(stats.durationNanos))
                    HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))
                    StatRow(stringResource(R.string.conv_stat_a_to_b_packets),
                        stats.aToB.toString())
                    StatRow(stringResource(R.string.conv_stat_a_to_b_bytes),
                        formatBytes(stats.aToBBytes))
                    StatRow(stringResource(R.string.conv_stat_b_to_a_packets),
                        stats.bToA.toString())
                    StatRow(stringResource(R.string.conv_stat_b_to_a_bytes),
                        formatBytes(stats.bToABytes))
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // 操作按钮
            if (conversation.protocol == Protocols.TCP && tcpAnchor != null) {
                OutlinedButton(
                    onClick = { onFollowStream(tcpAnchor) },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.action_follow_tcp_stream))
                }
            }
        }
    }
}

@Composable
private fun Card(content: @Composable () -> Unit) {
    Box(modifier = Modifier
        .fillMaxWidth()
        .clip(RoundedCornerShape(8.dp))
        .background(Color(0x08000000))) {
        content()
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(text, style = MaterialTheme.typography.labelMedium,
        color = Color(0xFF555555))
}

@Composable
private fun StatRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, fontSize = 12.sp, color = Color(0xFF666666))
        Text(value, fontFamily = MonoFont, fontSize = 12.sp)
    }
}

// ─── 数据计算 ──────────────────────────────────────────────────

private data class ConvStats(
    val durationNanos: Long,
    val aToB: Int,
    val bToA: Int,
    val aToBBytes: Long,
    val bToABytes: Long,
)

private fun findSessionFrames(allFrames: List<Frame>, conv: Conversation): List<Frame> =
    allFrames.filter { f ->
        val src = endpointOf(f, source = true) ?: return@filter false
        val dst = endpointOf(f, source = false) ?: return@filter false
        val (low, high) = if (src < dst) src to dst else dst to src
        low == conv.endpointA && high == conv.endpointB
    }.sortedBy { it.index }

private fun computeStats(frames: List<Frame>, conv: Conversation): ConvStats {
    var aToB = 0; var bToA = 0
    var aToBBytes = 0L; var bToABytes = 0L
    var firstTs = Long.MAX_VALUE
    var lastTs = Long.MIN_VALUE
    for (f in frames) {
        val src = endpointOf(f, source = true) ?: continue
        if (f.timestampNanos < firstTs) firstTs = f.timestampNanos
        if (f.timestampNanos > lastTs) lastTs = f.timestampNanos
        if (src == conv.endpointA) {
            aToB++; aToBBytes += f.originalLength.toLong()
        } else {
            bToA++; bToABytes += f.originalLength.toLong()
        }
    }
    val duration = if (frames.size >= 2) lastTs - firstTs else 0L
    return ConvStats(duration, aToB, bToA, aToBBytes, bToABytes)
}

private fun endpointOf(f: Frame, source: Boolean): String? {
    val ip = f.layers.firstOrNull { it.protocol == Protocols.IPV4 || it.protocol == Protocols.IPV6 }
        ?: return null
    val l4 = f.layers.firstOrNull { it.protocol == Protocols.TCP || it.protocol == Protocols.UDP }
        ?: return null
    val addrField = if (source) FieldNames.SOURCE else FieldNames.DESTINATION
    val portField = if (source) FieldNames.SOURCE_PORT else FieldNames.DESTINATION_PORT
    val ipAddr = ip.fields.firstOrNull { it.name == addrField }?.value ?: return null
    val port = l4.fields.firstOrNull { it.name == portField }?.value ?: return null
    return "$ipAddr:$port"
}

private fun formatDuration(nanos: Long): String {
    if (nanos <= 0) return "—"
    val secs = nanos / 1_000_000_000.0
    return when {
        secs < 1 -> "%.0fms".format(secs * 1000)
        secs < 60 -> "%.2fs".format(secs)
        secs < 3600 -> "%.0fs".format(secs)
        else -> "%.1fh".format(secs / 3600)
    }
}
