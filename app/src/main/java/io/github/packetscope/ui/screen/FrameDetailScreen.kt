package io.github.packetscope.ui.screen

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import io.github.packetscope.R
import io.github.packetscope.core.pcap.Field
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.FrameBytes
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols

private val MonoFont = FontFamily.Monospace
private val HighlightColor = Color(0xFFFFE57F)
private val LayerHeaderBg = Color(0xFFE3F2FD)
/** 所有 section header（协议层 / Payload / Hex dump）统一高度，让滚动列表
 *  视觉对齐。值取 Material default IconButton 48dp，能放下 PayloadHeader 的
 *  ⤢ IconButton 不撑变形（UX 反馈：原来 PayloadHeader 因 IconButton 多 ~12dp） */
private val SectionHeaderHeight = 48.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FrameDetailScreen(
    frame: Frame,
    onBack: () -> Unit,
    onFollowStream: (Frame) -> Unit = {},
) {
    // 选中的字节范围；切换 frame 时重置
    var selectedRange by remember(frame.index) { mutableStateOf<IntRange?>(null) }
    // 全屏查看的字段（来自长按 / "⤢" 按钮）
    var fullscreenField by remember(frame.index) { mutableStateOf<Field?>(null) }

    // Payload section（如有），跟 hex dump 都作为顶层 LazyColumn 的 section 渲染
    val payload = remember(frame.index) { extractPayload(frame) }

    // 各 section 的展开状态。**默认全收缩**（UX 反馈：用户希望快速定位想看的一项）
    // key 形如 "L0" / "L1" ... / "payload" / "hex"
    val sectionExpanded = remember(frame.index) { mutableStateMapOf<String, Boolean>() }
    val allSectionKeys: List<String> = remember(frame.index, payload) {
        buildList {
            frame.layers.indices.forEach { add("L$it") }
            if (payload != null) add("payload")
            add("hex")
        }
    }
    // 当一半以上 section 展开时按钮显 ⊟（点击全部收起），否则显 ⊞（点击全部展开）
    val sectionsMostlyExpanded = allSectionKeys.count { sectionExpanded[it] == true } >
        allSectionKeys.size / 2

    BackHandler(onBack = onBack)

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(stringResource(R.string.frame_detail_title, frame.index))
                        // 间距在拼接处补，不在资源里放空白（资源 loader 会剥前导空白）
                        val truncationNote = if (frame.capturedLength < frame.originalLength) {
                            "  " + stringResource(
                                R.string.frame_detail_truncation,
                                frame.capturedLength, frame.originalLength,
                            )
                        } else ""
                        val layers = frame.layers.joinToString(" / ") { it.protocol }
                        val bytesText = pluralStringResource(
                            R.plurals.count_bytes,
                            frame.originalLength, frame.originalLength,
                        )
                        Text(
                            text = "$bytesText · $layers$truncationNote",
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
                    // 一键展开 / 收缩全部 section（UX 反馈）。emoji 字符走 Text，
                    // 但要让 TalkBack 念出有意义的描述（review v0.6-round5 F-002）
                    val toggleAllDesc = stringResource(
                        if (sectionsMostlyExpanded) R.string.action_collapse_all
                        else R.string.action_expand_all
                    )
                    IconButton(
                        onClick = {
                            val target = !sectionsMostlyExpanded
                            allSectionKeys.forEach { sectionExpanded[it] = target }
                        },
                        modifier = Modifier.semantics { contentDescription = toggleAllDesc },
                    ) {
                        Text(
                            text = if (sectionsMostlyExpanded) "⊟" else "⊞",
                            fontSize = 20.sp,
                            color = Color(0xFF1565C0),
                        )
                    }
                    if (frame.layers.any { it.protocol == Protocols.TCP }) {
                        TextButton(onClick = { onFollowStream(frame) }) {
                            Text(stringResource(R.string.action_follow_stream))
                        }
                    }
                },
            )
        },
    ) { padding ->
        // 单一 LazyColumn 渲染所有 section（协议层 + Payload + Hex dump），
        // 全部同视觉同行为 — 一致的展开/收缩 + 选中字节联动（UX 反馈：
        // 之前分两栏 Payload/Hex 看着别扭）
        LazyColumn(modifier = Modifier.fillMaxSize().padding(padding)) {
            // 协议层
            frame.layers.forEachIndexed { i, layer ->
                val key = "L$i"
                val isExpanded = sectionExpanded[key] == true
                item(key) {
                    LayerHeader(
                        layer = layer,
                        isExpanded = isExpanded,
                        onToggle = { sectionExpanded[key] = !isExpanded },
                        onSelectAll = { selectedRange = layer.byteRange },
                        selected = selectedRange == layer.byteRange,
                    )
                }
                if (isExpanded) {
                    items(layer.fields, key = { "${key}_${it.name}" }) { field ->
                        FieldRow(
                            field = field,
                            depth = 1,
                            selectedRange = selectedRange,
                            onSelect = { selectedRange = it },
                            onExpand = { fullscreenField = it },
                        )
                    }
                }
            }
            // Payload section（如果非空）
            payload?.let { p ->
                val key = "payload"
                val isExpanded = sectionExpanded[key] == true
                item(key) {
                    PayloadHeader(
                        payload = p,
                        isExpanded = isExpanded,
                        selected = selectedRange == p.byteRange,
                        onToggle = { sectionExpanded[key] = !isExpanded },
                        onSelect = { selectedRange = p.byteRange },
                        onExpand = { fullscreenField = p.asField() },
                    )
                }
                if (isExpanded) {
                    item("${key}_content") { PayloadContent(p) }
                }
            }
            // Hex dump section
            run {
                val key = "hex"
                val isExpanded = sectionExpanded[key] == true
                item(key) {
                    HexHeader(
                        dataSize = frame.data.size,
                        isExpanded = isExpanded,
                        onToggle = { sectionExpanded[key] = !isExpanded },
                    )
                }
                if (isExpanded) {
                    val rowCount = (frame.data.size + BYTES_PER_ROW - 1) / BYTES_PER_ROW
                    items(rowCount, key = { "hex_$it" }) { rowIdx ->
                        HexRow(frame.data, rowIdx * BYTES_PER_ROW, selectedRange)
                    }
                }
            }
        }
    }

    fullscreenField?.let { field ->
        FieldDetailDialog(field = field, onDismiss = { fullscreenField = null })
    }
}

private const val PCAPDROID_TRAILER_SIZE = 32

/** Hex dump 上方"Payload" 面板的数据 */
private data class PayloadInfo(
    val byteRange: IntRange,
    val bytes: ByteArray,
    /** UTF-8 解码后的文本；为 null 表示 payload 非可打印文本（用 hex 显示） */
    val text: String?,
) {
    /** 用于喂给 FieldDetailDialog 全屏查看 */
    fun asField(): Field = Field(
        name = if (text != null) "Payload (UTF-8)" else "Payload (hex)",
        value = text ?: bytes.joinToString(" ") { "%02x".format(it.toInt() and 0xFF) },
        byteRange = byteRange,
    )
}

private fun extractPayload(frame: Frame): PayloadInfo? {
    val hasTrailer = frame.layers.any { it.protocol == Protocols.PCAPDROID_META }
    val trailerSize = if (hasTrailer) PCAPDROID_TRAILER_SIZE else 0
    val lastLayer = frame.layers.lastOrNull { it.protocol != Protocols.PCAPDROID_META }
        ?: return null
    val payloadStart = lastLayer.byteRange.last + 1
    val payloadEnd = frame.data.size - trailerSize
    if (payloadStart >= payloadEnd) return null

    val bytes = frame.data.copyOfRange(payloadStart, payloadEnd)
    return PayloadInfo(
        byteRange = payloadStart..(payloadEnd - 1),
        bytes = bytes,
        text = decodePayloadText(bytes),
    )
}

private fun decodePayloadText(data: ByteArray): String? {
    if (data.isEmpty()) return null
    var printable = 0
    for (b in data) {
        val v = b.toInt() and 0xFF
        if (v in 0x20..0x7E || v == 0x09 || v == 0x0A || v == 0x0D) printable++
    }
    if (printable * 5 < data.size * 4) return null
    return String(data, Charsets.UTF_8)
}

/**
 * Payload section header — 跟协议层 [LayerHeader] 同视觉同行为：
 * - 点整行 toggle 展开 / 选中 payload byte range
 * - 右侧大 IconButton ⤢ 全屏（48dp 触控目标，UX 反馈必须保留）
 */
@Composable
private fun PayloadHeader(
    payload: PayloadInfo,
    isExpanded: Boolean,
    selected: Boolean,
    onToggle: () -> Unit,
    onSelect: () -> Unit,
    onExpand: () -> Unit,
) {
    val bg = if (selected) HighlightColor else LayerHeaderBg
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = SectionHeaderHeight)
            .background(bg)
            .clickable { onToggle(); onSelect() }
            .padding(start = 8.dp, end = 0.dp),  // 右侧让 IconButton 自己占
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = if (isExpanded) "▾" else "▸",
            fontFamily = MonoFont,
            modifier = Modifier.width(16.dp),
        )
        Text(
            text = stringResource(R.string.section_payload),
            fontFamily = MonoFont,
            style = MaterialTheme.typography.bodyMedium,
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = payloadSummary(payload),
            fontFamily = MonoFont,
            fontSize = 12.sp,
            color = Color(0xFF555555),
            maxLines = 1,
            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f),
        )
        val fullscreenDesc = stringResource(R.string.action_open_fullscreen)
        IconButton(
            onClick = onExpand,
            modifier = Modifier.semantics { contentDescription = fullscreenDesc },
        ) {
            // 大尺寸 emoji 让 IconButton 默认 40dp 触控区显眼
            Text("⤢", fontSize = 20.sp, color = Color(0xFF1565C0))
        }
    }
}

@Composable
private fun payloadSummary(p: PayloadInfo): String {
    val kindRes = if (p.text != null) R.string.payload_kind_utf8 else R.string.payload_kind_binary
    val kind = stringResource(kindRes)
    val sizeText = pluralStringResource(R.plurals.count_bytes, p.bytes.size, p.bytes.size)
    val preview = (p.text ?: p.bytes.joinToString(" ") {
        "%02x".format(it.toInt() and 0xFF)
    }).lineSequence().firstOrNull()?.take(50) ?: ""
    return "$sizeText · $kind · $preview"
}

/** Payload 展开后显示完整内容。点 ⤢ 全屏只是为了搜索 / 复制方便，不是因为
 *  这里是预览（UX 反馈：原来截断到 2000 字符显示"…（点 ⤢ 看完整）"，让用户
 *  误以为详情页"显示不全"）。
 *
 *  注：单 Text 渲染极长 payload (> 256KB) 会有性能问题；这种情况建议直接走
 *  ⤢ 全屏，那边的 verticalScroll + onTextLayout 跳转更适合。但抓包场景一帧
 *  payload 极少超几 KB，本地实测 1500B 流畅。 */
@Composable
private fun PayloadContent(payload: PayloadInfo) {
    val display = payload.text
        ?: payload.bytes.joinToString(" ") { "%02x".format(it.toInt() and 0xFF) }
    SelectionContainer(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 16.dp, top = 6.dp, end = 16.dp, bottom = 12.dp),
    ) {
        Text(text = display, fontFamily = MonoFont, fontSize = 12.sp)
    }
}

/** Hex dump section header — 跟协议层同视觉，展开后下方渲染 [HexRow] 行列表 */
@Composable
private fun HexHeader(dataSize: Int, isExpanded: Boolean, onToggle: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = SectionHeaderHeight)
            .background(LayerHeaderBg)
            .clickable(onClick = onToggle)
            .padding(horizontal = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = if (isExpanded) "▾" else "▸",
            fontFamily = MonoFont,
            modifier = Modifier.width(16.dp),
        )
        Text(
            text = stringResource(R.string.section_hex_dump),
            fontFamily = MonoFont,
            style = MaterialTheme.typography.bodyMedium,
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = pluralStringResource(R.plurals.count_bytes, dataSize, dataSize),
            fontFamily = MonoFont,
            fontSize = 12.sp,
            color = Color(0xFF555555),
        )
    }
}

@Composable
private fun LayerHeader(
    layer: Layer,
    isExpanded: Boolean,
    onToggle: () -> Unit,
    onSelectAll: () -> Unit,
    selected: Boolean,
) {
    val bg = if (selected) HighlightColor else LayerHeaderBg
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = SectionHeaderHeight)
            .background(bg)
            .clickable { onToggle(); onSelectAll() }
            .padding(horizontal = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = if (isExpanded) "▾" else "▸",
            fontFamily = MonoFont,
            modifier = Modifier.width(16.dp),
        )
        Text(
            // 资源里不带前导空格，间距用字符串拼接补
            text = layer.protocol +
                if (layer.truncated) "  " + stringResource(R.string.frame_detail_layer_truncated) else "",
            fontFamily = MonoFont,
            style = MaterialTheme.typography.bodyMedium,
        )
        layer.summary?.let {
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = it,
                fontFamily = MonoFont,
                fontSize = 12.sp,
                color = Color(0xFF555555),
                maxLines = 1,
                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun FieldRow(
    field: Field,
    depth: Int,
    selectedRange: IntRange?,
    onSelect: (IntRange?) -> Unit,
    onExpand: (Field) -> Unit,
) {
    val hasChildren = field.children.isNotEmpty()
    var expanded by remember(field) { mutableStateOf(false) }
    val isSelected = field.byteRange != null && selectedRange == field.byteRange
    val bg = if (isSelected) HighlightColor else Color.Transparent
    // 任何 value 足够长（80+ 字符）或含换行的字段，都允许全屏展开看
    val canExpand = field.value.length > 80 || field.value.contains('\n')

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(bg)
            .combinedClickable(
                onClick = {
                    if (hasChildren) expanded = !expanded
                    if (field.byteRange != null) onSelect(field.byteRange)
                },
                onLongClick = { onExpand(field) },
            )
            .padding(start = (depth * 16).dp, top = 2.dp, bottom = 2.dp, end = 8.dp),
    ) {
        Text(
            text = when {
                hasChildren && expanded -> "▾"
                hasChildren -> "▸"
                else -> "  "
            },
            fontFamily = MonoFont,
            fontSize = 12.sp,
            modifier = Modifier.width(16.dp),
        )
        Text(
            text = "${field.name}: ${field.value}",
            fontFamily = MonoFont,
            fontSize = 12.sp,
            // weight(1f) 让 Text 占据 Row 剩余宽度，超长自动 softwrap 换行
            modifier = Modifier.weight(1f),
        )
        if (canExpand) {
            // IconButton 默认 40dp 触控目标；emoji 字号 18 让 hit-box 落在合理位置
            // （UX 反馈：原 Text 太小不好戳）
            val fullscreenDesc = stringResource(R.string.action_open_fullscreen)
            IconButton(
                onClick = { onExpand(field) },
                modifier = Modifier
                    .align(Alignment.CenterVertically)
                    .semantics { contentDescription = fullscreenDesc },
            ) {
                Text("⤢", fontSize = 18.sp, color = Color(0xFF1565C0))
            }
        }
    }

    if (hasChildren && expanded) {
        Column {
            field.children.forEach { child ->
                FieldRow(child, depth + 1, selectedRange, onSelect, onExpand)
            }
        }
    }
}

/**
 * 全屏查看字段值（payload Text/Hex 或任意长字段）。
 *
 * 实现要点：
 * - 单 Text + verticalScroll Column：让选区天然跨行（SelectionContainer 包
 *   多个 Text 时 Compose 不会自动加 \n，复制结果会把视觉换行的内容拼成一
 *   长串——之前按行 LazyColumn 拆 item 就吃过这亏，UX 反馈"复制不能复制
 *   多段"）
 * - 命中跳转用 TextLayoutResult.getLineTop + ScrollState.animateScrollTo，
 *   把目标行滚到视口 1/4 处留上文锚定；LaunchedEffect key 含 textLayout，
 *   首次回调到位后才尝试跳转，避免首帧 textLayout=null 漏跳
 * - Column 用 fillMaxWidth + verticalScroll，不用 fillMaxSize（fillMaxSize
 *   会让 Column 高度被父限定，长 Text 显示被夹）
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FieldDetailDialog(field: Field, onDismiss: () -> Unit) {
    var searchOpen by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }

    val matches by remember(field, searchQuery) {
        derivedStateOf {
            if (searchQuery.isEmpty()) emptyList()
            else findAllOccurrences(field.value, searchQuery)
        }
    }
    var currentMatch by remember(field, searchQuery) { mutableStateOf(0) }

    val annotated = remember(field, matches, currentMatch) {
        if (matches.isEmpty()) AnnotatedString(field.value)
        else highlightMatches(field.value, matches, currentMatch)
    }

    BackHandler(enabled = searchOpen) { searchOpen = false; searchQuery = "" }
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            contentWindowInsets = WindowInsets.safeDrawing,
            topBar = {
                if (searchOpen) {
                    SearchHeaderBar(
                        query = searchQuery,
                        onQueryChange = { searchQuery = it; currentMatch = 0 },
                        matchCount = matches.size,
                        currentMatch = if (matches.isEmpty()) 0 else currentMatch + 1,
                        onPrev = {
                            if (matches.isNotEmpty()) {
                                currentMatch = (currentMatch - 1 + matches.size) % matches.size
                            }
                        },
                        onNext = {
                            if (matches.isNotEmpty()) {
                                currentMatch = (currentMatch + 1) % matches.size
                            }
                        },
                        onClose = { searchOpen = false; searchQuery = "" },
                    )
                } else {
                    FieldDetailDefaultTopBar(
                        field = field,
                        onOpenSearch = { searchOpen = true },
                        onDismiss = onDismiss,
                    )
                }
            },
        ) { padding ->
            FieldDetailContent(
                annotated = annotated,
                matches = matches,
                currentMatch = currentMatch,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(padding),
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FieldDetailDefaultTopBar(
    field: Field,
    onOpenSearch: () -> Unit,
    onDismiss: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    TopAppBar(
        title = {
            Column {
                Text(field.name, maxLines = 1)
                Text(
                    text = pluralStringResource(
                        R.plurals.count_characters,
                        field.value.length, field.value.length,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
        navigationIcon = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.action_back))
            }
        },
        actions = {
            IconButton(onClick = onOpenSearch) {
                Icon(
                    Icons.Filled.Search,
                    contentDescription = stringResource(R.string.search_action),
                )
            }
            TextButton(onClick = { clipboard.setText(AnnotatedString(field.value)) }) {
                Text(stringResource(R.string.action_copy))
            }
        },
    )
}

@Composable
private fun FieldDetailContent(
    annotated: AnnotatedString,
    matches: List<IntRange>,
    currentMatch: Int,
    modifier: Modifier = Modifier,
) {
    val scrollState = rememberScrollState()
    var textLayout by remember(annotated) {
        mutableStateOf<androidx.compose.ui.text.TextLayoutResult?>(null)
    }
    // 命中跳转：算出 active range 所在行的 Y，再滚到视口 1/4 处；textLayout
    // 也是 key，首次回调到位后才尝试跳，避免首帧 layout=null 漏跳。
    LaunchedEffect(currentMatch, matches.size, textLayout) {
        val activeRange = matches.getOrNull(currentMatch) ?: return@LaunchedEffect
        val layout = textLayout ?: return@LaunchedEffect
        if (activeRange.first >= layout.layoutInput.text.length) return@LaunchedEffect
        val lineIdx = layout.getLineForOffset(activeRange.first)
        val targetY = layout.getLineTop(lineIdx).toInt()
        val vp = scrollState.viewportSize
        val target = (targetY - vp / 4).coerceIn(0, scrollState.maxValue)
        scrollState.animateScrollTo(target)
    }
    // SelectionContainer 包整个 Column，单 Text 内 \n 让复制带换行；
    // fillMaxWidth 不用 fillMaxSize（避免长 Text 高度被父限定夹断）
    SelectionContainer(modifier = modifier) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(scrollState)
                .padding(horizontal = 12.dp, vertical = 8.dp),
        ) {
            Text(
                text = annotated,
                fontFamily = MonoFont,
                fontSize = 13.sp,
                onTextLayout = { textLayout = it },
                modifier = Modifier.fillMaxWidth(),
            )
            // 圆角 / 手势条手机底部 96dp 兜底，避免最后一行被遮挡
            Spacer(modifier = Modifier.height(96.dp))
        }
    }
}

// SearchTopBar / findAllOccurrences / highlightMatches 抽到 Search.kt 公共文件

// 手机宽度装不下 16 字节/行的 hex+ASCII，改用 8 字节/行
private const val BYTES_PER_ROW = 8

/**
 * 一行 hex+ASCII。原来用 17 个 Text composable 拼，导致几百行时 LazyColumn
 * 渲染卡顿。改用单 [AnnotatedString] + SpanStyle 给选中字节加背景色，
 * 整行只产 **1 个** Text 节点（UX 反馈：hex dump 展开后变卡）。
 */
@Composable
private fun HexRow(data: FrameBytes, start: Int, selectedRange: IntRange?) {
    val annotated = remember(data, start, selectedRange) {
        buildHexRow(data, start, selectedRange)
    }
    Text(
        text = annotated,
        fontFamily = MonoFont,
        fontSize = 12.sp,
        // softWrap=false + maxLines=1：39 字符整行在窄屏边界条件不被 wrap
        // 切成两行（用户反馈"hex 显示不全"），保证整行可见
        softWrap = false,
        maxLines = 1,
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
    )
}

/**
 * 构造 hex 行的 AnnotatedString。结构（每个 hex byte "%02x " 占 3 字符，分隔
 * "  " 占 2 字符，每个 ASCII 字符 1 个）：
 *
 *   "0010  16 03 01 00 dc 01 00 00  ......"
 *    └ off ─┘└──── hex 24 chars ────┘└─2─┘└─ascii 8─┘
 *
 * 选中字节段在 hex 和 ascii 两处都加 SpanStyle background 高亮。
 */
private fun buildHexRow(
    data: FrameBytes,
    start: Int,
    selectedRange: IntRange?,
): AnnotatedString = buildAnnotatedString {
    // 偏移列：4 hex chars + 2 spaces
    withStyle(SpanStyle(color = Color(0xFF888888))) {
        append("%04x  ".format(start))
    }
    // Hex 字节区
    for (i in 0 until BYTES_PER_ROW) {
        val pos = start + i
        if (pos >= data.size) {
            append("   ")  // 缺位 3 空格保持对齐
        } else {
            val hl = selectedRange?.contains(pos) == true
            val byteStart = length
            append("%02x ".format(data[pos].toInt() and 0xFF))
            if (hl) {
                addStyle(
                    SpanStyle(background = HighlightColor),
                    byteStart, length - 1,  // 不含末尾空格
                )
            }
        }
    }
    append(" ")  // hex / ascii 分隔
    // ASCII 区
    for (i in 0 until BYTES_PER_ROW) {
        val pos = start + i
        if (pos >= data.size) break
        val b = data[pos].toInt() and 0xFF
        val ch = if (b in 0x20..0x7E) b.toChar() else '.'
        val hl = selectedRange?.contains(pos) == true
        val charStart = length
        append(ch.toString())
        if (hl) {
            addStyle(SpanStyle(background = HighlightColor), charStart, length)
        }
    }
}
