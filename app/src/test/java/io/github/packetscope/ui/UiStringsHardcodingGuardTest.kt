package io.github.packetscope.ui

import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * UI 字符串硬编码守护测试：扫 `app/src/main/java/io/github/packetscope/ui/screen/`
 * 下所有 .kt 文件（注意 Kotlin 块注释嵌套，KDoc 不能写裸 slash-star 通配）。
 * 文件里的 `Text("...")` 与 `contentDescription = "..."` 字符串字面量，如果像
 * user-facing 文本，**必须**走 `stringResource(R.string.xxx)`。
 *
 * 历史问题（review v0.6-round5 F-001）：5 个 UX commit 一口气加了 12+ 处硬编码
 * 英文字面量，绕过了 CONTRIBUTING.md §1 i18n 约定，让 Chinese locale UI 中英
 * 混排。本测试沉淀 review 的 i18n 检查，让"过去人 review 反复说的事"机器自动
 * 抓——参考 [LintBaselineGuardTest] / [FieldNamesUsageTest] 思路。
 *
 * 不抓哪些字面量（数据 / 符号 / 不是 user-facing 文本）：
 * - 单字符（emoji / 符号 / 单位）：⊞ ⊟ ⤢ ▾ ▸ → ← B
 * - 全部非字母（空白 / 分隔符 / 纯数字）："  " " · "
 * - 短 token（≤ 5 字符，全部 大写 / 数字 / `/`）：UTF-8 TCP UDP IPv6 GET
 *
 * 抓什么：长度 ≥ 2、含字母、不像 token，例如 "Payload" "Search…" "→ server"。
 *
 * 命中后修法：把字面量挪到 `values/strings.xml` + `values-zh/strings.xml`，
 * 调用点改 `stringResource(R.string.xxx)`。
 */
class UiStringsHardcodingGuardTest {

    @Test
    fun `ui screen 内不允许出现硬编码 user-facing 字符串`() {
        val uiRoot = File("src/main/java/io/github/packetscope/ui/screen")
        require(uiRoot.exists() && uiRoot.isDirectory) {
            "ui/screen 源码目录不存在: ${uiRoot.absolutePath}"
        }

        // 普通字符串 + 转义。raw string 里有 [ " ] 太靠近闭包 """ 时 kotlin
        // parser 偶尔判错，这里走最稳的路径。
        // Text("..." 第一参数 String literal
        val textRegex = Regex("Text\\(\\s*\"((?:[^\"\\\\]|\\\\.)*)\"")
        // contentDescription = "..."
        val cdRegex = Regex("contentDescription\\s*=\\s*\"((?:[^\"\\\\]|\\\\.)*)\"")

        val violations = mutableListOf<String>()
        uiRoot.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .forEach { file ->
                file.readLines().forEachIndexed { idx, line ->
                    val trimmed = line.trim()
                    // 跳过单行 / 块注释行（不抓注释里的示例字符串）
                    if (trimmed.startsWith("//") ||
                        trimmed.startsWith("*") ||
                        trimmed.startsWith("/*")
                    ) return@forEachIndexed

                    fun scan(regex: Regex, kind: String) {
                        regex.findAll(line).forEach { m ->
                            val literal = m.groupValues[1]
                            if (looksLikeUiText(literal)) {
                                violations += "${file.relativeTo(File(".")).path}:${idx + 1}: " +
                                    "$kind(\"$literal\") → 应改为 stringResource(R.string.xxx)"
                            }
                        }
                    }
                    scan(textRegex, "Text")
                    scan(cdRegex, "contentDescription")
                }
            }

        if (violations.isNotEmpty()) {
            fail(
                "发现 ${violations.size} 处硬编码 user-facing 字符串（违反 i18n 约定，" +
                    "见 CONTRIBUTING.md §1 + review v0.6-round5 F-001）：\n" +
                    violations.joinToString("\n") { "  $it" } +
                    "\n\n" +
                    "修法：把字面量挪到 values/strings.xml + values-zh/strings.xml，" +
                    "调用点改 stringResource。若 *不是* user-facing 文本（数据 token / " +
                    "格式占位 / 符号），优化 looksLikeUiText 的白名单——别加 @Suppress " +
                    "或拆字面量绕过这条测试。"
            )
        }
    }

    /** 判定一个字符串字面量是否看起来像 user-facing 文本（需走 stringResource） */
    internal fun looksLikeUiText(s: String): Boolean {
        if (s.isEmpty()) return false
        if (s.length <= 1) return false  // 单字符 emoji / 符号
        // 先去 string template 占位（${...} / $name），剩下才是真字面内容；
        // 拼接 stringResource 变量 + 标点（"$a · $b"）的情形 stripped 后空，豁免。
        val stripped = s.replace(Regex("""\$\{[^}]*\}|\$[A-Za-z_]\w*"""), "")
        if (stripped.none { it.isLetter() }) return false  // 纯符号 / 空白
        // 已知 user-facing 短英文 token 优先白名单 ——「OK / URL / API / DONE」这种
        // 按钮 / 操作 label 即使全大写也算 user-facing，不该被下面 "短 token 豁免"
        // 漏过（v0.6-round6 F-003 deferred 兑现）
        if (stripped.uppercase() in UI_TEXT_WHITELIST_SHORT) return true
        // 短 token（≤ 5 字符，全部 大写 / 数字 / `/` `-`）：UTF-8 TCP IPv6 GET
        if (stripped.length <= 5 && stripped.all { it.isShortTokenChar() }) return false
        return true
    }

    private fun Char.isShortTokenChar(): Boolean =
        isUpperCase() || isDigit() || this in SHORT_TOKEN_SYMBOLS

    @Test
    fun `looksLikeUiText 短全大写白名单`() {
        // 白名单 user-facing 短词应命中（即使全大写）
        for (word in listOf("OK", "URL", "API", "DONE", "YES", "NO", "BACK", "SAVE")) {
            assert(looksLikeUiText(word)) {
                "expected $word to be flagged user-facing"
            }
        }
        // 协议 / 字段 token 仍豁免
        for (token in listOf("TCP", "UDP", "HTTP", "TLS", "GET", "POST", "DNS", "QUIC")) {
            assert(!looksLikeUiText(token)) {
                "expected $token to be exempt (protocol/method token)"
            }
        }
    }

    private companion object {
        private val SHORT_TOKEN_SYMBOLS = setOf('/', '-')

        /** Letter-form (uppercase 比对) 的 user-facing 短词白名单：
         *  按钮 / 操作 label，不是协议 / 字段名常量。在
         *  [looksLikeUiText] 的"短全大写豁免"规则前优先匹配 */
        private val UI_TEXT_WHITELIST_SHORT = setOf(
            "OK", "URL", "API", "DONE", "YES", "NO", "ADD", "NEW",
            "BACK", "NEXT", "PREV", "SAVE", "EDIT", "VIEW", "OPEN", "STOP",
            "MORE", "LESS", "INFO", "HELP",
        )
    }
}
