package io.github.packetscope.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import io.github.packetscope.R
import io.github.packetscope.core.analysis.Conversation
import io.github.packetscope.core.decrypt.KeyLogStore
import io.github.packetscope.core.decrypt.SslKeyLogParser
import io.github.packetscope.core.filter.FilterIndex
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.LinkType
import io.github.packetscope.core.stream.StreamingSession
import io.github.packetscope.service.UdpExporterService
import io.github.packetscope.ui.screen.AboutScreen
import io.github.packetscope.ui.screen.ConversationDetailScreen
import io.github.packetscope.ui.screen.ConversationsScreen
import io.github.packetscope.ui.screen.FollowStreamScreen
import io.github.packetscope.ui.screen.FrameDetailScreen
import io.github.packetscope.ui.screen.FrameListScreen
import io.github.packetscope.ui.screen.OpenFileCallbacks
import io.github.packetscope.ui.screen.OpenFileScreen

/**
 * 顶层 UI 状态机。MVP 用 sealed class + mutableStateOf 切换；
 * 还不到引入 Navigation 库的复杂度。
 */
sealed interface AppState {
    data object Empty : AppState
    /** 「关于」屏；从 OpenFileScreen overflow → "About" 进入，返回 Empty */
    data object About : AppState
    data class Loading(val uri: Uri) : AppState
    data class Error(val message: String) : AppState
    data class Loaded(
        val sourceName: String,
        val linkType: LinkType,
        val frames: List<Frame>,
        val indices: List<FilterIndex>,
        val selectedFrame: Frame? = null,
        val showConversations: Boolean = false,
        val followStream: Frame? = null,
        val selectedConversation: Conversation? = null,
    ) : AppState
    /** UDP Exporter 实时模式 */
    data class Streaming(
        val port: Int,
        val selectedFrame: Frame? = null,
        val showConversations: Boolean = false,
        val followStream: Frame? = null,
        val selectedConversation: Conversation? = null,
    ) : AppState
}

@Composable
fun AppScreen(
    initialUri: Uri? = null,
    onInitialUriConsumed: () -> Unit = {},
) {
    var state: AppState by remember { mutableStateOf(AppState.Empty) }
    val context = LocalContext.current

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION,
                )
            }
            state = AppState.Loading(uri)
        }
    }

    val keyLogPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.openInputStream(uri)?.use { input ->
                    val entries = SslKeyLogParser.parse(input)
                    val name = uri.lastPathSegment ?: "keylog"
                    KeyLogStore.load(entries, name)
                }
            }
        }
    }

    val keyLogName = KeyLogStore.fileName.value
    val keyLogSessionCount = KeyLogStore.sessionCount.intValue
    val keyLogStatus: String? =
        if (keyLogName != null && keyLogSessionCount > 0)
            pluralStringResource(
                R.plurals.count_session_keys_loaded,
                keyLogSessionCount, keyLogSessionCount,
            )
        else null

    // 外部 Intent 传入的 Uri（PCAPdroid 分享 / 文件管理器打开）
    LaunchedEffect(initialUri) {
        val uri = initialUri ?: return@LaunchedEffect
        state = AppState.Loading(uri)
        onInitialUriConsumed()
    }

    // 触发文件加载
    val current = state
    if (current is AppState.Loading) {
        LaunchedEffect(current.uri) {
            val name = current.uri.lastPathSegment ?: current.uri.toString()
            when (val result = PcapLoader.load(context, current.uri)) {
                is PcapLoader.Result.Success -> {
                    state = AppState.Loaded(
                        sourceName = name,
                        linkType = result.linkType,
                        frames = result.frames,
                        indices = result.indices,
                    )
                }
                is PcapLoader.Result.Failure -> {
                    state = AppState.Error(result.message)
                }
            }
        }
    }

    val openFileCallbacks = OpenFileCallbacks(
        onPickFile = { picker.launch(arrayOf("*/*")) },
        onListen = { port -> state = AppState.Streaming(port) },
        onPickKeyLog = { keyLogPicker.launch(arrayOf("*/*")) },
        onClearKeyLog = { KeyLogStore.clear() },
        onShowAbout = { state = AppState.About },
    )

    Surface(modifier = Modifier.fillMaxSize()) {
        when (val s = state) {
            AppState.Empty -> OpenFileScreen(
                callbacks = openFileCallbacks,
                keyLogStatus = keyLogStatus,
                error = null,
            )
            AppState.About -> AboutScreen(onBack = { state = AppState.Empty })
            is AppState.Loading -> OpenFileScreen(
                callbacks = openFileCallbacks,
                keyLogStatus = keyLogStatus,
                loading = true,
                error = null,
            )
            is AppState.Error -> OpenFileScreen(
                callbacks = openFileCallbacks,
                keyLogStatus = keyLogStatus,
                error = s.message,
            )
            is AppState.Loaded -> {
                when {
                    s.followStream != null -> FollowStreamScreen(
                        allFrames = s.frames,
                        anchor = s.followStream,
                        onBack = { state = s.copy(followStream = null) },
                    )
                    s.selectedConversation != null -> ConversationDetailScreen(
                        conversation = s.selectedConversation,
                        allFrames = s.frames,
                        onBack = { state = s.copy(selectedConversation = null) },
                        onFollowStream = { state = s.copy(
                            followStream = it, selectedConversation = null) },
                    )
                    s.showConversations -> ConversationsScreen(
                        frames = s.frames,
                        onBack = { state = s.copy(showConversations = false) },
                        onSelect = { c -> state = s.copy(selectedConversation = c) },
                    )
                    s.selectedFrame != null -> FrameDetailScreen(
                        frame = s.selectedFrame,
                        onBack = { state = s.copy(selectedFrame = null) },
                        onFollowStream = { state = s.copy(followStream = it) },
                    )
                    else -> FrameListScreen(
                        sourceName = s.sourceName,
                        linkType = s.linkType,
                        frames = s.frames,
                        indices = s.indices,
                        onSelect = { frame -> state = s.copy(selectedFrame = frame) },
                        onClose = { state = AppState.Empty },
                        onShowConversations = { state = s.copy(showConversations = true) },
                    )
                }
            }
            is AppState.Streaming -> StreamingHost(
                streaming = s,
                onStateChange = { state = it },
            )
        }
    }
}

/**
 * 由 [UdpExporterService]（ForegroundService）实际跑 UDP 接收，本 Composable 只负责：
 *   1. 启动/停止 Service
 *   2. 从 [StreamingSession]（进程级共享 state）读 frames/status 渲染列表/详情
 */
@Composable
private fun StreamingHost(
    streaming: AppState.Streaming,
    onStateChange: (AppState) -> Unit,
) {
    val context = LocalContext.current

    // Activity 重建（旋转屏）后 streaming.port 不变 → Service 不重启
    DisposableEffect(streaming.port) {
        UdpExporterService.start(context, streaming.port)
        onDispose {
            UdpExporterService.stop(context)
            StreamingSession.reset()
        }
    }

    val frames: List<Frame> = StreamingSession.frames
    val linkType by StreamingSession.linkType
    val status by StreamingSession.status

    when {
        streaming.followStream != null -> FollowStreamScreen(
            allFrames = frames,
            anchor = streaming.followStream,
            onBack = { onStateChange(streaming.copy(followStream = null)) },
        )
        streaming.selectedConversation != null -> ConversationDetailScreen(
            conversation = streaming.selectedConversation,
            allFrames = frames,
            onBack = { onStateChange(streaming.copy(selectedConversation = null)) },
            onFollowStream = { onStateChange(streaming.copy(
                followStream = it, selectedConversation = null)) },
        )
        streaming.showConversations -> ConversationsScreen(
            frames = frames,
            onBack = { onStateChange(streaming.copy(showConversations = false)) },
            onSelect = { c -> onStateChange(streaming.copy(selectedConversation = c)) },
        )
        streaming.selectedFrame != null -> FrameDetailScreen(
            frame = streaming.selectedFrame,
            onBack = { onStateChange(streaming.copy(selectedFrame = null)) },
            onFollowStream = { onStateChange(streaming.copy(followStream = it)) },
        )
        else -> FrameListScreen(
            sourceName = if (status != null)
                stringResource(R.string.source_name_live_with_status, streaming.port, status!!)
            else stringResource(R.string.source_name_live, streaming.port),
            linkType = linkType,
            frames = frames,
            onSelect = { frame ->
                onStateChange(streaming.copy(selectedFrame = frame))
            },
            onClose = { onStateChange(AppState.Empty) },
            onShowConversations = { onStateChange(streaming.copy(showConversations = true)) },
            confirmClose = true,
            // 清空已收 frames 但不停 listener，方便反复测试
            onClear = { StreamingSession.frames.clear() },
        )
    }
}
