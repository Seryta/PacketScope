package io.github.packetscope.ui.screen

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
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
import io.github.packetscope.core.analysis.ConversationBuilder
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.Protocols

private val MonoFont = FontFamily.Monospace

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationsScreen(
    frames: List<Frame>,
    onBack: () -> Unit,
    onSelect: (Conversation) -> Unit = {},
) {
    BackHandler(onBack = onBack)
    val convs = remember(frames.size) { ConversationBuilder.build(frames) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(stringResource(R.string.nav_conversations))
                        // 两个 plurals 拼接：sessions · packets
                        val sessionsText = pluralStringResource(
                            R.plurals.count_sessions, convs.size, convs.size)
                        val packetsText = pluralStringResource(
                            R.plurals.count_packets, frames.size, frames.size)
                        Text("$sessionsText · $packetsText",
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
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding).padding(horizontal = 8.dp),
        ) {
            items(convs, key = { "${it.protocol}|${it.endpointA}|${it.endpointB}" }) { c ->
                ConvCard(c, onClick = { onSelect(c) })
            }
        }
    }
}

@Composable
private fun ConvCard(c: Conversation, onClick: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .clip(RoundedCornerShape(6.dp))
            .background(Color(0x08000000))
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 8.dp),
    ) {
        // 第 1 行：协议徽章 + app 名
        Row(modifier = Modifier.fillMaxWidth()) {
            ProtocolBadge(c.protocol)
            Box(modifier = Modifier.weight(1f))
            c.appName?.let {
                Text(
                    text = it,
                    fontFamily = MonoFont,
                    fontSize = 11.sp,
                    color = Color(0xFF555555),
                    maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                )
            }
        }
        // 第 2 行：endpoints，必要时折两行
        Text(
            text = "${c.endpointA}  ↔  ${c.endpointB}",
            fontFamily = MonoFont,
            fontSize = 12.sp,
            maxLines = 2,
            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            modifier = Modifier.padding(top = 4.dp),
        )
        // 第 3 行：统计
        Text(
            text = "${pluralStringResource(R.plurals.count_packets, c.packets, c.packets)} · ${formatBytes(c.bytes)}",
            fontFamily = MonoFont,
            fontSize = 11.sp,
            color = Color(0xFF666666),
            modifier = Modifier.padding(top = 2.dp),
        )
    }
}

@Composable
private fun ProtocolBadge(protocol: String) {
    val (bg, fg) = protocolColors(protocol)
    Box(modifier = Modifier
        .clip(RoundedCornerShape(4.dp))
        .background(bg)
        .padding(horizontal = 6.dp, vertical = 2.dp)) {
        Text(protocol,
            fontFamily = MonoFont, fontSize = 11.sp, color = fg)
    }
}

private fun protocolColors(p: String): Pair<Color, Color> = when (p) {
    Protocols.TCP -> Color(0xFF1565C0) to Color.White
    Protocols.UDP -> Color(0xFFE65100) to Color.White
    else -> Color(0xFF616161) to Color.White
}

internal fun formatBytes(n: Long): String = when {
    n < 1024 -> "${n}B"
    n < 1024 * 1024 -> "%.1fKB".format(n / 1024.0)
    n < 1024 * 1024 * 1024 -> "%.1fMB".format(n / 1024.0 / 1024.0)
    else -> "%.2fGB".format(n / 1024.0 / 1024.0 / 1024.0)
}

