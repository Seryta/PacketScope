package io.github.packetscope.ui.screen

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.DisableSelection
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import io.github.packetscope.R
import io.github.packetscope.core.pcap.FieldNames
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols

private val MonoFont = FontFamily.Monospace

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FollowStreamScreen(
    allFrames: List<Frame>,
    anchor: Frame,
    onBack: () -> Unit,
) {
    val segments = remember(allFrames.size, anchor.index) {
        buildSegments(allFrames, anchor)
    }
    val totalBytes = segments.sumOf { it.payload.size }
    val sourceLabel = segments.firstOrNull()?.let {
        "${it.clientEp}  ↔  ${it.serverEp}"
    } ?: "—"

    // 每段单 LazyColumn item，段内 payload 是单 Text 含 \n——SelectionContainer
    // 内多个 Text 复制不会自动加 \n 分隔，按行拆 item 后用户长按复制结果会被
    // 拼成一长串（UX 反馈：复制后没有换行）。
    // 行级跳转通过 listState.animateScrollToItem(segIdx, scrollOffset=Y) 走 px
    // 偏移精算：段内 Y = headerOffsetPx + 段内行号 × lineHeightPx；
    // viewport/4 留上文锚定。lineHeight 在 SegmentCard payload Text 内显式声明
    // 与本处一致，估算才准。
    var searchOpen by remember(anchor.index) { mutableStateOf(false) }
    var searchQuery by remember(anchor.index) { mutableStateOf("") }
    val rendered = remember(segments) { segments.map { renderPayload(it.payload) } }
    val perSegmentMatches by remember(rendered, searchQuery) {
        derivedStateOf {
            if (searchQuery.isEmpty()) List(rendered.size) { emptyList<IntRange>() }
            else rendered.map { findAllOccurrences(it, searchQuery) }
        }
    }
    // 扁平 (segIdx, matchIdxInSeg) 列表，prev/next 跨段连续跳
    val globalMatches by remember(perSegmentMatches) {
        derivedStateOf {
            buildList {
                perSegmentMatches.forEachIndexed { si, ranges ->
                    ranges.indices.forEach { idx -> add(si to idx) }
                }
            }
        }
    }
    var currentMatch by remember(anchor.index, searchQuery) { mutableStateOf(0) }
    val activeSegIdx = globalMatches.getOrNull(currentMatch)?.first ?: -1
    val activeLocalIdx = globalMatches.getOrNull(currentMatch)?.second ?: -1

    val listState = rememberLazyListState()
    val density = androidx.compose.ui.platform.LocalDensity.current
    val configuration = androidx.compose.ui.platform.LocalConfiguration.current
    // SegmentCard 内 header 区估算：dp 部分（段间 padding 6dp + Card vertical
    // padding 6dp + payload 顶部 padding 4dp ≈ 16dp）+ sp 部分（header Text 字号
    // 11sp，默认 lineHeight ratio ≈ 1.3 → ~14sp）。
    // 注意 lineHeight 是 sp 而不是 dp：用户系统字号缩放后 sp 实际像素跟着变，
    // 必须用 sp.toPx() 才会带 fontScale；之前用 dp.toPx() 在字号放大时少算
    // 几十趴，行级跳转跑去段头看起来"没跳到位"。
    val headerPadPx = with(density) { 16.dp.toPx().toInt() }
    val headerTextPx = with(density) { 14.sp.toPx().toInt() }
    val headerOffsetPx = headerPadPx + headerTextPx
    val lineHeightPx = with(density) { 16.sp.toPx().toInt() }
    // viewport fallback：LaunchedEffect 在 LazyColumn 首次 measure 之前跑时
    // layoutInfo 给 0，没 fallback 会让 vp/4=0，target offset 不带上文锚定
    val vpFallbackPx = with(density) { configuration.screenHeightDp.dp.toPx().toInt() }
    LaunchedEffect(currentMatch, globalMatches.size) {
        val target = globalMatches.getOrNull(currentMatch) ?: return@LaunchedEffect
        val measuredVp = listState.layoutInfo.viewportEndOffset -
            listState.layoutInfo.viewportStartOffset
        val vp = if (measuredVp > 0) measuredVp else vpFallbackPx
        val (segIdx, offset) = computeJumpTarget(
            rendered = rendered,
            perSegmentMatches = perSegmentMatches,
            target = target,
            headerOffsetPx = headerOffsetPx,
            lineHeightPx = lineHeightPx,
            vp = vp,
        ) ?: return@LaunchedEffect
        listState.animateScrollToItem(index = segIdx, scrollOffset = offset)
    }

    BackHandler(enabled = searchOpen) { searchOpen = false; searchQuery = "" }
    BackHandler(enabled = !searchOpen, onBack = onBack)

    Scaffold(
        topBar = {
            if (searchOpen) {
                FollowStreamSearchTopBar(
                    query = searchQuery,
                    matchCount = globalMatches.size,
                    currentMatch = currentMatch,
                    onQueryChange = { searchQuery = it; currentMatch = 0 },
                    onAdvance = { delta ->
                        if (globalMatches.isNotEmpty()) {
                            currentMatch = (currentMatch + delta + globalMatches.size) %
                                globalMatches.size
                        }
                    },
                    onClose = { searchOpen = false; searchQuery = "" },
                )
            } else {
                val segCountText = pluralStringResource(
                    R.plurals.count_segments, segments.size, segments.size,
                )
                val totalBytesText = pluralStringResource(
                    R.plurals.count_bytes, totalBytes, totalBytes,
                )
                TopAppBar(
                    title = {
                        Column {
                            Text(stringResource(R.string.follow_stream_title))
                            Text(
                                "$sourceLabel · $segCountText · $totalBytesText",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    },
                    navigationIcon = {
                        TextButton(onClick = onBack) {
                            Text(stringResource(R.string.action_back))
                        }
                    },
                    actions = {
                        IconButton(onClick = { searchOpen = true }) {
                            Icon(
                                Icons.Filled.Search,
                                contentDescription = stringResource(R.string.search_action),
                            )
                        }
                    },
                )
            }
        },
    ) { padding ->
        if (segments.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = androidx.compose.ui.Alignment.Center) {
                Text(stringResource(R.string.follow_stream_empty))
            }
        } else {
            FollowStreamBody(
                segments = segments,
                rendered = rendered,
                perSegmentMatches = perSegmentMatches,
                listState = listState,
                activeSegIdx = activeSegIdx,
                activeLocalIdx = activeLocalIdx,
                modifier = Modifier.fillMaxSize().padding(padding).padding(horizontal = 8.dp),
            )
        }
    }
}

private fun segmentBg(fromClient: Boolean): Color =
    if (fromClient) Color(0xFFE3F2FD) else Color(0xFFFFF3E0)

/** SearchHeaderBar 适配：把 prev/next 折成单一 onAdvance(delta) 让 caller
 *  Composable 内少几个 lambda + if 分支，绕开 detekt CyclomaticComplexity 上限。 */
@Composable
private fun FollowStreamSearchTopBar(
    query: String,
    matchCount: Int,
    currentMatch: Int,
    onQueryChange: (String) -> Unit,
    onAdvance: (delta: Int) -> Unit,
    onClose: () -> Unit,
) {
    SearchHeaderBar(
        query = query,
        onQueryChange = onQueryChange,
        matchCount = matchCount,
        currentMatch = if (matchCount == 0) 0 else currentMatch + 1,
        onPrev = { onAdvance(-1) },
        onNext = { onAdvance(+1) },
        onClose = onClose,
    )
}

/** segments 列表渲染：SelectionContainer 包 LazyColumn 让选区跨段；段内
 *  SegmentCard payload 是单 Text 含 \n，复制结果自带换行；Header 用
 *  DisableSelection 跳过 metadata。 */
@Composable
private fun FollowStreamBody(
    segments: List<Segment>,
    rendered: List<String>,
    perSegmentMatches: List<List<IntRange>>,
    listState: androidx.compose.foundation.lazy.LazyListState,
    activeSegIdx: Int,
    activeLocalIdx: Int,
    modifier: Modifier = Modifier,
) {
    SelectionContainer(modifier = modifier) {
        LazyColumn(state = listState) {
            items(segments.size, key = { segments[it].frameIndex }) { si ->
                SegmentCard(
                    seg = segments[si],
                    renderedText = rendered[si],
                    matches = perSegmentMatches[si],
                    activeLocalMatch = if (si == activeSegIdx) activeLocalIdx else -1,
                )
            }
        }
    }
}

/** 算出"跳到第 currentMatch 个命中"的 scrollToItem 参数：(segIdx, scrollOffset)。
 *  scrollOffset = 段内 header 区高度 + 段内目标行号 × 行高 - viewport/4
 *  （viewport/4 给上文锚定）。 */
private fun computeJumpTarget(
    rendered: List<String>,
    perSegmentMatches: List<List<IntRange>>,
    target: Pair<Int, Int>,
    headerOffsetPx: Int,
    lineHeightPx: Int,
    vp: Int,
): Pair<Int, Int>? {
    val (segIdx, matchIdxInSeg) = target
    val matchRange = perSegmentMatches.getOrNull(segIdx)?.getOrNull(matchIdxInSeg)
        ?: return null
    // 数 match 起始 offset 之前有多少个 \n，得段内行号
    val text = rendered[segIdx]
    val lineIdxInSeg = text
        .substring(0, matchRange.first.coerceAtMost(text.length))
        .count { it == '\n' }
    val rawOffset = headerOffsetPx + lineIdxInSeg * lineHeightPx - vp / 4
    return segIdx to rawOffset.coerceAtLeast(0)
}

/** 单个 segment 卡：Header（metadata 不参与选区）+ 单 Text payload（含 \n
 *  让复制带换行）。Text 显式 lineHeight=16.sp，跟主 Composable 内
 *  scrollOffset 估算保持一致——改这里务必同步改 [FollowStreamScreen] 的
 *  lineHeightPx。 */
@Composable
private fun SegmentCard(
    seg: Segment,
    renderedText: String,
    matches: List<IntRange>,
    activeLocalMatch: Int,
) {
    val annotated: AnnotatedString = remember(renderedText, matches, activeLocalMatch) {
        if (matches.isEmpty()) AnnotatedString(renderedText)
        else highlightMatches(renderedText, matches, activeLocalMatch)
    }
    val direction = stringResource(
        if (seg.fromClient) R.string.follow_stream_direction_to_server
        else R.string.follow_stream_direction_from_server
    )
    val sizeText = pluralStringResource(
        R.plurals.count_bytes, seg.payload.size, seg.payload.size,
    )
    val matchSuffix = if (matches.isNotEmpty()) {
        "  · " + pluralStringResource(R.plurals.count_matches, matches.size, matches.size)
    } else ""
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 6.dp)  // 段间留白
            .clip(RoundedCornerShape(6.dp))
            .background(segmentBg(seg.fromClient))
            .padding(horizontal = 8.dp, vertical = 6.dp),
    ) {
        DisableSelection {
            Text(
                text = "#${seg.frameIndex}  $direction  ($sizeText)$matchSuffix",
                fontFamily = MonoFont, fontSize = 11.sp,
                color = Color(0xFF555555),
            )
        }
        // lineHeight 显式 16.sp，让 FollowStreamScreen 跳转计算的 lineHeightPx
        // 跟实际行高对齐；改这里务必同步改 FollowStreamScreen 内 lineHeightPx
        Text(
            text = annotated,
            style = androidx.compose.ui.text.TextStyle(
                fontFamily = MonoFont,
                fontSize = 12.sp,
                lineHeight = 16.sp,
            ),
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 4.dp),
        )
    }
}

private data class Segment(
    val frameIndex: Int,
    val clientEp: String,
    val serverEp: String,
    val fromClient: Boolean,
    val payload: ByteArray,
)

private fun buildSegments(allFrames: List<Frame>, anchor: Frame): List<Segment> {
    val tuple = tupleOf(anchor) ?: return emptyList()
    val anchorKey = canonicalKey(tuple)
    val (anchorA, anchorB) = tuple
    val client = anchorA  // 退化：用 anchor 的 src 端作客户端推断
    val server = anchorB
    val sessionFrames = allFrames.filter { f ->
        val t = tupleOf(f) ?: return@filter false
        canonicalKey(t) == anchorKey
    }.sortedBy { it.index }

    return sessionFrames.mapNotNull { frame ->
        val tcp = frame.layers.firstOrNull { it.protocol == Protocols.TCP } ?: return@mapNotNull null
        val payload = payloadOf(frame, tcp)
        if (payload.isEmpty()) return@mapNotNull null
        val from = tupleOf(frame)?.first ?: return@mapNotNull null
        Segment(
            frameIndex = frame.index,
            clientEp = client, serverEp = server,
            fromClient = from == client,
            payload = payload,
        )
    }
}

private fun canonicalKey(t: Pair<String, String>): String {
    val (a, b) = t
    return if (a < b) "$a|$b" else "$b|$a"
}

private fun tupleOf(frame: Frame): Pair<String, String>? {
    val ip = frame.layers.firstOrNull { it.protocol == Protocols.IPV4 || it.protocol == Protocols.IPV6 } ?: return null
    val tcp = frame.layers.firstOrNull { it.protocol == Protocols.TCP } ?: return null
    val srcIp = ip.fields.firstOrNull { it.name == FieldNames.SOURCE }?.value ?: return null
    val dstIp = ip.fields.firstOrNull { it.name == FieldNames.DESTINATION }?.value ?: return null
    val sport = tcp.fields.firstOrNull { it.name == FieldNames.SOURCE_PORT }?.value ?: return null
    val dport = tcp.fields.firstOrNull { it.name == FieldNames.DESTINATION_PORT }?.value ?: return null
    return "$srcIp:$sport" to "$dstIp:$dport"
}

private fun payloadOf(frame: Frame, tcp: Layer): ByteArray {
    val hasTrailer = frame.layers.any { it.protocol == Protocols.PCAPDROID_META }
    val end = if (hasTrailer) frame.data.size - 32 else frame.data.size
    val start = tcp.byteRange.last + 1
    if (start >= end) return ByteArray(0)
    return frame.data.copyOfRange(start, end)
}

/** payload 优先解为文本，全部不可打印则 hex */
private fun renderPayload(data: ByteArray): String {
    var printable = 0
    for (b in data) {
        val v = b.toInt() and 0xFF
        if (v in 0x20..0x7E || v == 0x09 || v == 0x0A || v == 0x0D) printable++
    }
    return if (printable * 5 >= data.size * 4) {
        data.toString(Charsets.UTF_8)
    } else {
        buildString(data.size * 3) {
            for ((i, b) in data.withIndex()) {
                if (i > 0 && i % 16 == 0) append('\n')
                append("%02x ".format(b.toInt() and 0xFF))
            }
        }
    }
}
