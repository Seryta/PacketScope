package io.github.packetscope.ui.screen

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.packetscope.R

/**
 * 搜索 UI helpers，共享给 FieldDetailDialog / FollowStreamScreen 等需要"全屏内
 * 搜索 + 命中高亮"的页面。
 */

private val MonoFont = FontFamily.Monospace
private val HighlightNormal = Color(0xFFFFF59D)   // yellow-200
private val HighlightActive = Color(0xFFFFB300)   // amber-600

/** 找出 [query] 在 [text] 中所有不重叠的出现区间（大小写无关） */
internal fun findAllOccurrences(text: String, query: String): List<IntRange> {
    if (query.isEmpty()) return emptyList()
    val needle = query.lowercase()
    val haystack = text.lowercase()
    val result = mutableListOf<IntRange>()
    var idx = 0
    while (true) {
        val found = haystack.indexOf(needle, idx)
        if (found < 0) break
        result += found until (found + needle.length)
        idx = found + needle.length
    }
    return result
}

/** 把 [text] 包成 AnnotatedString：所有 [matches] 高亮黄色，[active] 索引那段
 *  用更深的橙色表示"当前命中"；[active] < 0 时无活跃命中 */
internal fun highlightMatches(
    text: String,
    matches: List<IntRange>,
    active: Int = -1,
): AnnotatedString {
    if (matches.isEmpty()) return AnnotatedString(text)
    val normalStyle = SpanStyle(background = HighlightNormal)
    val activeStyle = SpanStyle(background = HighlightActive)
    return buildAnnotatedString {
        var cursor = 0
        matches.forEachIndexed { i, range ->
            if (range.first > cursor) append(text.substring(cursor, range.first))
            withStyle(if (i == active) activeStyle else normalStyle) {
                append(text.substring(range.first, range.last + 1))
            }
            cursor = range.last + 1
        }
        if (cursor < text.length) append(text.substring(cursor))
    }
}

/**
 * 两行布局的搜索栏，给 Scaffold.topBar 用：
 *   行 1：关闭按钮 + TextField
 *   行 2：命中计数 + prev/next（仅 query 非空时显示）
 *
 * 之前嵌进 TopAppBar 单行布局时，长 query 让 TextField 跟"1 / 1"计数重叠
 * （UX 反馈）。两行布局给 TextField 整宽，命中导航单独一行。
 */
@Composable
internal fun SearchHeaderBar(
    query: String,
    onQueryChange: (String) -> Unit,
    matchCount: Int,
    currentMatch: Int,
    onPrev: () -> Unit,
    onNext: () -> Unit,
    onClose: () -> Unit,
) {
    // 进入搜索栏自动聚焦 TextField + 唤起软键盘，让用户点完 ⌕ 直接打字
    // （UX 反馈：原本还要再点一次输入框）。LaunchedEffect(Unit) 在 SearchHeaderBar
    // 首次进入时跑一次；关搜索→重开时整个 Composable 会重 mount，再次自动聚焦。
    val focusRequester = remember { FocusRequester() }
    LaunchedEffect(Unit) {
        focusRequester.requestFocus()
    }
    Surface(tonalElevation = 3.dp) {
        androidx.compose.foundation.layout.Column(modifier = Modifier.fillMaxWidth()) {
            // 顶行：close + TextField
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 4.dp, end = 8.dp, top = 6.dp, bottom = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(onClick = onClose) {
                    Icon(
                        Icons.Filled.Close,
                        contentDescription = stringResource(R.string.search_close),
                    )
                }
                OutlinedTextField(
                    value = query,
                    onValueChange = onQueryChange,
                    placeholder = {
                        Text(stringResource(R.string.search_placeholder), fontSize = 13.sp)
                    },
                    singleLine = true,
                    modifier = Modifier
                        .weight(1f)
                        .focusRequester(focusRequester),
                    textStyle = TextStyle(fontFamily = MonoFont, fontSize = 13.sp),
                )
            }
            // 命中行：query 为空时隐藏（避免空 row 占高度）
            if (query.isNotEmpty()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 16.dp, end = 4.dp, bottom = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = if (matchCount > 0) "$currentMatch / $matchCount"
                        else "No matches",
                        fontSize = 12.sp,
                        color = Color(0xFF555555),
                    )
                    Spacer(modifier = Modifier.weight(1f))
                    IconButton(onClick = onPrev, enabled = matchCount > 0) {
                        Icon(
                            Icons.Filled.KeyboardArrowUp,
                            contentDescription = stringResource(R.string.search_prev_match),
                        )
                    }
                    IconButton(onClick = onNext, enabled = matchCount > 0) {
                        Icon(
                            Icons.Filled.KeyboardArrowDown,
                            contentDescription = stringResource(R.string.search_next_match),
                        )
                    }
                }
            }
        }
    }
}
