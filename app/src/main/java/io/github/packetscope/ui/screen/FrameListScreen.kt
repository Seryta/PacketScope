package io.github.packetscope.ui.screen

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
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
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import io.github.packetscope.R
import io.github.packetscope.core.filter.FilterIndex
import io.github.packetscope.core.filter.FilterParseError
import io.github.packetscope.core.filter.FilterParseException
import io.github.packetscope.core.filter.FilterParser
import io.github.packetscope.core.filter.FrameFilter
import io.github.packetscope.core.pcap.FieldNames
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.LinkType
import io.github.packetscope.core.pcap.Protocols

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FrameListScreen(
    sourceName: String,
    linkType: LinkType,
    frames: List<Frame>,
    onSelect: (Frame) -> Unit,
    onClose: () -> Unit,
    onShowConversations: () -> Unit = {},
    initialFilter: String = "",
    /** 文件模式预算的 [FilterIndex]，与 frames 平行；为 null 时（流式模式）filter
     *  回退到 layer 树遍历，见 [FrameFilter] kdoc */
    indices: List<FilterIndex>? = null,
    /** true 时关闭/返回弹确认对话框（监听模式下避免误退导致丢失实时数据） */
    confirmClose: Boolean = false,
    /** 非 null 时顶栏显示「清空」按钮（监听模式下清空已收 frames 但不停 listener） */
    onClear: (() -> Unit)? = null,
) {
    val baseNanos = frames.firstOrNull()?.timestampNanos ?: 0L
    var query by remember { mutableStateOf(initialFilter) }
    // 点击列头排序：默认 (TIME, desc) 即最新在顶
    var sortColumn by remember { mutableStateOf(SortColumn.TIME) }
    var sortDesc by remember { mutableStateOf(true) }
    var showCloseConfirm by remember { mutableStateOf(false) }
    var showFilterHelp by remember { mutableStateOf(false) }

    val tryClose = {
        if (confirmClose) showCloseConfirm = true else onClose()
    }
    BackHandler { tryClose() }

    val parseResult = remember(query) {
        runCatching { FilterParser.parse(query) }
    }
    val filter = parseResult.getOrDefault(FrameFilter.MatchAll)
    // 不直接用 exception.message —— message 是开发者诊断文本（toString 兜底），
    // user-facing 走 filterErrorMessage @Composable helper 映射到 locale 资源
    val parseError = (parseResult.exceptionOrNull() as? FilterParseException)
        ?.let { filterErrorMessage(it.error) }
    // 注意：用 frames.size 而不是 frames 作 remember key —— SnapshotStateList 的
    // equals 是结构相等，但 self.equals(self) 走 identity 短路恒为 true，所以
    // remember(filter, frames) 在 SnapshotStateList 内容变化时不会重算。
    val filtered = remember(filter, frames.size, sortColumn, sortDesc, indices != null) {
        val matched = if (indices != null && indices.size == frames.size) {
            // 文件模式：用预算索引走 atom 的索引分支
            frames.filterIndexed { i, f -> filter.matches(f, indices[i]) }
        } else {
            // 流式模式（or 索引规模与 frames 不一致的兜底）：走旧 layer 遍历
            frames.filter { filter.matches(it) }
        }
        sortFrames(matched, sortColumn, sortDesc)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(sourceName, maxLines = 1)
                        // plurals 拼 packets，linkType 走外部拼接
                        val packetsText = pluralStringResource(
                            R.plurals.count_packets, frames.size, frames.size)
                        Text(
                            text = "$packetsText · ${linkType.name}",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                },
                actions = {
                    onClear?.let {
                        TextButton(onClick = it) {
                            Text(stringResource(R.string.action_clear_data))
                        }
                    }
                    TextButton(onClick = onShowConversations) {
                        Text(stringResource(R.string.nav_conversations))
                    }
                    TextButton(onClick = { tryClose() }) {
                        Text(stringResource(R.string.action_close))
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            FilterBar(
                query = query,
                onChange = { query = it },
                error = parseError,
                shown = filtered.size,
                total = frames.size,
                onShowHelp = { showFilterHelp = true },
            )
            HorizontalDivider()
            HeaderRow(
                sortColumn = sortColumn,
                sortDesc = sortDesc,
                onSort = { col ->
                    if (sortColumn == col) sortDesc = !sortDesc
                    else { sortColumn = col; sortDesc = (col == SortColumn.TIME) }
                },
            )
            HorizontalDivider()
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(filtered, key = { it.index }) { frame ->
                    FrameRow(frame, baseNanos, onClick = { onSelect(frame) })
                    HorizontalDivider(color = Color(0x10000000))
                }
            }
        }
    }

    if (showCloseConfirm) {
        AlertDialog(
            onDismissRequest = { showCloseConfirm = false },
            confirmButton = {
                TextButton(onClick = {
                    showCloseConfirm = false
                    onClose()
                }) { Text(stringResource(R.string.action_stop_listen)) }
            },
            dismissButton = {
                TextButton(onClick = { showCloseConfirm = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
            title = { Text(stringResource(R.string.dialog_stop_listen_title)) },
            text = { Text(stringResource(R.string.dialog_stop_listen_text)) },
        )
    }

    if (showFilterHelp) {
        FilterHelpDialog(
            query = query,
            onChange = { query = it },
            onDismiss = { showFilterHelp = false },
        )
    }
}

@Composable
private fun FilterBar(
    query: String,
    onChange: (String) -> Unit,
    error: String?,
    shown: Int,
    total: Int,
    onShowHelp: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp)) {
        OutlinedTextField(
            value = query,
            onValueChange = onChange,
            placeholder = {
                Text(stringResource(R.string.filter_placeholder),
                    fontFamily = MonoFont, fontSize = 12.sp)
            },
            // X 清除按钮（仅 query 非空）+ ? 帮助按钮并排在右侧；
            // Compose 把 trailingIcon 渲染在 TextField 内部右边的 indicator
            // 槽位，不占输入区域。
            trailingIcon = {
                Row {
                    if (query.isNotEmpty()) {
                        IconButton(onClick = { onChange("") }) {
                            Icon(
                                Icons.Filled.Close,
                                contentDescription = stringResource(R.string.filter_clear),
                            )
                        }
                    }
                    TextButton(onClick = onShowHelp) {
                        Text("?", fontFamily = MonoFont, fontSize = 16.sp)
                    }
                }
            },
            singleLine = true,
            isError = error != null,
            modifier = Modifier.fillMaxWidth(),
            textStyle = androidx.compose.ui.text.TextStyle(
                fontFamily = MonoFont, fontSize = 13.sp),
        )
        Row(modifier = Modifier.fillMaxWidth().padding(top = 2.dp)) {
            if (error != null) {
                Text(
                    text = error,
                    color = Color(0xFFB00020),
                    fontSize = 11.sp,
                    modifier = Modifier.weight(1f),
                )
            } else {
                Box(modifier = Modifier.weight(1f))
            }
            Text(
                text = "$shown / $total",
                fontFamily = MonoFont,
                fontSize = 11.sp,
                color = Color(0xFF666666),
            )
        }
    }
}

private val MonoFont = FontFamily.Monospace
private val RowFontSize = 11.sp

// 列宽设计：Pixel5 宽 411dp 减 16dp padding ≈ 395dp。
// 固定 4 列合计 ~176dp，给 Info 留 ~220dp 才能放下 "51234 → 80 [SYN] seq=0" 这种 21 字符摘要。
private val NumColW = 36.dp
private val TimeColW = 60.dp
private val ProtoColW = 48.dp
private val LenColW = 40.dp

enum class SortColumn { INDEX, TIME, PROTOCOL, LENGTH, INFO }

private fun sortFrames(list: List<Frame>, col: SortColumn, desc: Boolean): List<Frame> {
    val sorted = when (col) {
        SortColumn.INDEX -> list.sortedBy { it.index }
        SortColumn.TIME -> list.sortedBy { it.timestampNanos }
        SortColumn.PROTOCOL -> list.sortedBy { it.topProtocol }
        SortColumn.LENGTH -> list.sortedBy { it.originalLength }
        SortColumn.INFO -> list.sortedBy { it.info }
    }
    return if (desc) sorted.asReversed() else sorted
}

@Composable
private fun HeaderRow(
    sortColumn: SortColumn,
    sortDesc: Boolean,
    onSort: (SortColumn) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0x08000000))
            .padding(horizontal = 8.dp),
    ) {
        SortableHeaderCell("#", SortColumn.INDEX, sortColumn, sortDesc, onSort, width = NumColW)
        SortableHeaderCell(stringResource(R.string.header_time),
            SortColumn.TIME, sortColumn, sortDesc, onSort, width = TimeColW)
        SortableHeaderCell(stringResource(R.string.header_protocol),
            SortColumn.PROTOCOL, sortColumn, sortDesc, onSort, width = ProtoColW)
        SortableHeaderCell(stringResource(R.string.header_length),
            SortColumn.LENGTH, sortColumn, sortDesc, onSort, width = LenColW)
        InfoSortableHeaderCell(stringResource(R.string.header_info),
            sortColumn, sortDesc, onSort)
    }
}

@Composable
private fun SortableHeaderCell(
    text: String,
    column: SortColumn,
    activeColumn: SortColumn,
    desc: Boolean,
    onSort: (SortColumn) -> Unit,
    width: androidx.compose.ui.unit.Dp,
) {
    Box(modifier = Modifier
        .width(width)
        .clickable { onSort(column) }
        .padding(vertical = 6.dp)) {
        Text(headerLabel(text, column == activeColumn, desc),
            style = MaterialTheme.typography.labelSmall, fontFamily = MonoFont)
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.InfoSortableHeaderCell(
    text: String,
    activeColumn: SortColumn,
    desc: Boolean,
    onSort: (SortColumn) -> Unit,
) {
    Box(modifier = Modifier
        .weight(1f)
        .clickable { onSort(SortColumn.INFO) }
        .padding(vertical = 6.dp)) {
        Text(headerLabel(text, SortColumn.INFO == activeColumn, desc),
            style = MaterialTheme.typography.labelSmall, fontFamily = MonoFont)
    }
}

private fun headerLabel(text: String, active: Boolean, desc: Boolean): String =
    if (active) "$text ${if (desc) "▼" else "▲"}" else text

@Composable
private fun FrameRow(frame: Frame, baseNanos: Long, onClick: () -> Unit) {
    val tSec = (frame.timestampNanos - baseNanos) / 1_000_000_000.0
    val appName = frame.layers.firstOrNull { it.protocol == Protocols.PCAPDROID_META }
        ?.fields?.firstOrNull { it.name == FieldNames.APP_NAME }?.value
        ?.takeIf { it.isNotEmpty() }
    val infoText = if (appName != null) "[$appName] ${frame.info}" else frame.info
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 6.dp),
    ) {
        FixedCell(frame.index.toString(), NumColW)
        FixedCell("%.4f".format(tSec), TimeColW)
        FixedCell(frame.topProtocol, ProtoColW)
        FixedCell(frame.originalLength.toString(), LenColW)
        Box(modifier = Modifier.weight(1f)) {
            Text(
                text = infoText.ifEmpty { "—" },
                fontFamily = MonoFont,
                fontSize = RowFontSize,
                maxLines = 2,
                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun FixedCell(text: String, width: androidx.compose.ui.unit.Dp) {
    Box(modifier = Modifier.width(width)) {
        Text(
            text = text,
            fontFamily = MonoFont,
            fontSize = RowFontSize,
            maxLines = 1,
        )
    }
}

/** FilterHelpDialog 的输入栏：回车 IME → 关 dialog 回列表；X 清除按钮。 */
@Composable
private fun FilterHelpInputField(
    query: String,
    onChange: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    OutlinedTextField(
        value = query,
        onValueChange = onChange,
        placeholder = {
            Text(stringResource(R.string.filter_help_placeholder),
                fontFamily = MonoFont, fontSize = 12.sp)
        },
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
        keyboardActions = KeyboardActions(onSearch = { onDismiss() }),
        trailingIcon = {
            if (query.isNotEmpty()) {
                IconButton(onClick = { onChange("") }) {
                    Icon(
                        Icons.Filled.Close,
                        contentDescription = stringResource(R.string.filter_clear),
                    )
                }
            }
        },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
        textStyle = androidx.compose.ui.text.TextStyle(
            fontFamily = MonoFont, fontSize = 13.sp),
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FilterHelpDialog(
    query: String,
    onChange: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            topBar = {
                TopAppBar(
                    title = { Text(stringResource(R.string.filter_help_title)) },
                    navigationIcon = {
                        TextButton(onClick = onDismiss) {
                            Text(stringResource(R.string.action_back))
                        }
                    },
                    actions = {
                        TextButton(onClick = { onChange("") }) {
                            Text(stringResource(R.string.action_clear_data))
                        }
                    },
                )
            },
        ) { padding ->
            Column(
                modifier = Modifier.fillMaxSize().padding(padding)
                    .padding(horizontal = 12.dp, vertical = 8.dp),
            ) {
                FilterHelpInputField(query, onChange, onDismiss)
                Spacer(modifier = Modifier.height(12.dp))
                Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                    // 协议名 / 完整示例：点击直接替换 query —— 都是无需参数的完整片段
                    // 参数 atom（host/port/sni 等）：点击插 "atom " 让用户接着输实参，不
                    // 强塞占位 IP/数字让用户手动删（UX 反馈：原来的"host 1.1.1.1"点了
                    // 还要删 1.1.1.1 很怪）
                    HelpSection(stringResource(R.string.filter_section_protocols), listOf(
                        HelpItem("tcp", stringResource(R.string.filter_proto_tcp), "tcp"),
                        HelpItem("udp", stringResource(R.string.filter_proto_udp), "udp"),
                        HelpItem("dns", stringResource(R.string.filter_proto_dns), "dns"),
                        HelpItem("http", stringResource(R.string.filter_proto_http), "http"),
                        HelpItem("tls", stringResource(R.string.filter_proto_tls), "tls"),
                        HelpItem("quic", stringResource(R.string.filter_proto_quic), "quic"),
                        HelpItem("icmp / icmpv6", stringResource(R.string.filter_proto_icmp), "icmp"),
                        HelpItem("ipv4 / ipv6", stringResource(R.string.filter_proto_ip), "ipv4"),
                        HelpItem("ethernet", stringResource(R.string.filter_proto_eth), "ethernet"),
                    ), onPick = onChange)
                    HelpSection(stringResource(R.string.filter_section_addr_port), listOf(
                        HelpItem("host <IP>", stringResource(R.string.filter_field_host), "host "),
                        HelpItem("port <数字>", stringResource(R.string.filter_field_port), "port "),
                    ), onPick = onChange)
                    HelpSection(stringResource(R.string.filter_section_l7), listOf(
                        HelpItem("sni <子串>", stringResource(R.string.filter_field_sni), "sni "),
                        HelpItem("url <子串>", stringResource(R.string.filter_field_url), "url "),
                        HelpItem("http.host <子串>", stringResource(R.string.filter_field_http_host), "http.host "),
                        HelpItem("http.path <子串>", stringResource(R.string.filter_field_http_path), "http.path "),
                        HelpItem("http.method <方法>", stringResource(R.string.filter_field_http_method), "http.method "),
                        HelpItem("dns.name <子串>", stringResource(R.string.filter_field_dns_name), "dns.name "),
                        HelpItem("app <子串>", stringResource(R.string.filter_field_app), "app "),
                        HelpItem("text <子串>", stringResource(R.string.filter_field_text), "text "),
                    ), onPick = onChange)
                    HelpSection(stringResource(R.string.filter_section_combine), listOf(
                        HelpItem("<a> and <b>", stringResource(R.string.filter_op_and), null),
                        HelpItem("<a> or <b>", stringResource(R.string.filter_op_or), null),
                        HelpItem("not <expr>", stringResource(R.string.filter_op_not), null),
                        HelpItem("( <expr> )", stringResource(R.string.filter_op_paren), null),
                    ), onPick = null)
                    HelpSection(stringResource(R.string.filter_section_examples), listOf(
                        HelpItem("tcp", stringResource(R.string.filter_example_tcp), "tcp"),
                        HelpItem("udp and port 53", stringResource(R.string.filter_example_dns_query), "udp and port 53"),
                        HelpItem("tls and sni github", stringResource(R.string.filter_example_github_tls), "tls and sni github"),
                        HelpItem("host 8.8.8.8 or host 8.8.4.4", stringResource(R.string.filter_example_google_dns), "host 8.8.8.8 or host 8.8.4.4"),
                        HelpItem("not tcp", stringResource(R.string.filter_example_no_tcp), "not tcp"),
                        HelpItem("(tcp or udp) and not port 53", stringResource(R.string.filter_example_tcpudp_no_dns), "(tcp or udp) and not port 53"),
                        HelpItem("http.method POST and url login", stringResource(R.string.filter_example_post_login), "http.method POST and url login"),
                        HelpItem("app chrome and dns.name google", stringResource(R.string.filter_example_chrome_dns), "app chrome and dns.name google"),
                    ), onPick = onChange)
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = stringResource(R.string.filter_note),
                        fontSize = 11.sp,
                        color = Color(0xFF888888),
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                }
            }
        }
    }
}

/**
 * @param display 显示给用户看的语法摘要（含占位 `<...>` / 真实示例 IP）
 * @param desc 描述
 * @param insert 点击行时实际填进 query 的字符串；null 表示该行不可点击（如组合操作符）
 */
private data class HelpItem(
    val display: String,
    val desc: String,
    val insert: String?,
)

@Composable
private fun HelpSection(
    title: String,
    items: List<HelpItem>,
    onPick: ((String) -> Unit)?,
) {
    Column(modifier = Modifier.padding(vertical = 4.dp)) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleSmall,
            color = Color(0xFF1565C0),
        )
        Spacer(modifier = Modifier.height(4.dp))
        items.forEach { item ->
            val clickable = onPick != null && item.insert != null
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .let { m -> if (clickable) m.clickable { onPick!!(item.insert!!) } else m }
                    .padding(vertical = 4.dp),
            ) {
                Text(
                    text = item.display,
                    fontFamily = MonoFont,
                    fontSize = 12.sp,
                    color = if (clickable) Color(0xFF1565C0) else Color.Unspecified,
                    modifier = Modifier.width(160.dp),
                )
                Text(
                    text = item.desc,
                    fontSize = 12.sp,
                    modifier = Modifier.weight(1f),
                )
            }
        }
        Spacer(modifier = Modifier.height(4.dp))
    }
}

/** 把 core 抛出的 [FilterParseError] 映射成当前 locale 的本地化字符串。
 *  review v0.6-round2 F-002：core 层不持有 user-facing 字符串。 */
@Composable
private fun filterErrorMessage(err: FilterParseError): String = when (err) {
    is FilterParseError.MissingRightParen ->
        stringResource(R.string.filter_error_missing_right_paren)
    is FilterParseError.ExpectedRightParen ->
        stringResource(R.string.filter_error_expected_right_paren, err.got)
    is FilterParseError.UnexpectedEndOfExpr ->
        stringResource(R.string.filter_error_unexpected_end_of_expr)
    is FilterParseError.ExpectedDigit ->
        stringResource(R.string.filter_error_expected_digit, err.token)
    is FilterParseError.PortOutOfRange ->
        stringResource(R.string.filter_error_port_out_of_range, err.port)
    is FilterParseError.UnknownToken ->
        stringResource(R.string.filter_error_unknown_token, err.token)
    is FilterParseError.MissingArg ->
        stringResource(R.string.filter_error_missing_arg, err.atom)
    is FilterParseError.ExtraToken ->
        stringResource(R.string.filter_error_extra_token, err.token)
}
