package io.github.packetscope.core.filter

import io.github.packetscope.core.pcap.Protocols

/**
 * 极简过滤表达式解析器（Wireshark 风格的子集）。
 *
 *   expr     ::= term ("or" term)*
 *   term     ::= factor ("and" factor)*
 *   factor   ::= "not" factor | "(" expr ")" | atom
 *   atom     ::= protocol
 *              | "host" IP | "port" NUMBER
 *              | "sni" STRING
 *              | "http.host" STRING | "http.path" STRING | "http.method" STRING
 *              | "url" STRING
 *              | "dns.name" STRING
 *              | "app" STRING
 *              | "text" STRING
 *
 * `and` 优先级高于 `or`，左结合。
 *
 * 错误通过 [FilterParseException] + sealed [FilterParseError] 抛出，UI 层做
 * locale 映射（review v0.6-round2 F-002）。core 层不持有任何 user-facing 字符串。
 *
 * 例：
 *   - `tcp`
 *   - `udp and port 53`
 *   - `not tls`
 *   - `host 1.1.1.1 or sni google`
 *   - `(tcp or udp) and not port 53`
 *   - `http.host github.com and http.method GET`
 */
class FilterParser private constructor(private val tokens: List<String>) {

    private var pos = 0

    private fun parseExpr(): FrameFilter {
        var left = parseTerm()
        while (peek()?.lowercase() == "or") {
            consume()
            left = FrameFilter.Or(left, parseTerm())
        }
        return left
    }

    private fun parseTerm(): FrameFilter {
        var left = parseFactor()
        while (peek()?.lowercase() == "and") {
            consume()
            left = FrameFilter.And(left, parseFactor())
        }
        return left
    }

    private fun parseFactor(): FrameFilter {
        val tok = peek()?.lowercase()
        if (tok == "not") {
            consume()
            return FrameFilter.Not(parseFactor())
        }
        if (tok == "(") {
            consume()
            val inner = parseExpr()
            val close = consume()
                ?: throw FilterParseException(FilterParseError.MissingRightParen)
            if (close != ")") {
                throw FilterParseException(FilterParseError.ExpectedRightParen(close))
            }
            return inner
        }
        return parseAtom()
    }

    private fun parseAtom(): FrameFilter {
        val token = consume()
            ?: throw FilterParseException(FilterParseError.UnexpectedEndOfExpr)
        val key = token.lowercase()
        return when (key) {
            "host" -> FrameFilter.Host(needArg("host"))
            "port" -> {
                val arg = needArg("port")
                val port = arg.toIntOrNull()
                    ?: throw FilterParseException(FilterParseError.ExpectedDigit(arg))
                if (port !in 0..65535) {
                    throw FilterParseException(FilterParseError.PortOutOfRange(port))
                }
                FrameFilter.Port(port)
            }
            "sni" -> FrameFilter.Sni(needArg("sni"))
            "http.host" -> FrameFilter.HttpHost(needArg("http.host"))
            "http.path" -> FrameFilter.HttpPath(needArg("http.path"))
            "http.method" -> FrameFilter.HttpMethod(needArg("http.method"))
            "url" -> FrameFilter.Url(needArg("url"))
            "dns.name" -> FrameFilter.DnsName(needArg("dns.name"))
            "app" -> FrameFilter.App(needArg("app"))
            "text" -> FrameFilter.Text(needArg("text"))
            in PROTOCOL_NAMES -> FrameFilter.Protocol(canonicalProto(key))
            else -> throw FilterParseException(FilterParseError.UnknownToken(token))
        }
    }

    private fun needArg(atom: String): String =
        consume() ?: throw FilterParseException(FilterParseError.MissingArg(atom))

    private fun peek(): String? = tokens.getOrNull(pos)
    private fun consume(): String? = tokens.getOrNull(pos)?.also { pos++ }

    companion object {
        private val PROTOCOL_NAMES = setOf(
            "tcp", "udp", "dns", "http", "tls", "quic", "icmp", "icmpv6",
            "ipv4", "ipv6", "ethernet",
        )

        // internal 而非 private：Kotlin 顶层 / companion private 在 JVM 上让
        // 同文件 sealed atom 走 synthetic accessor bridge，增加 dex 体积。
        // review v0.6-round4 F-004。
        internal fun canonicalProto(name: String): String = when (name.lowercase()) {
            "tcp" -> Protocols.TCP
            "udp" -> Protocols.UDP
            "dns" -> Protocols.DNS
            "http" -> Protocols.HTTP
            "tls" -> Protocols.TLS
            "quic" -> Protocols.QUIC
            "icmp" -> Protocols.ICMP
            "icmpv6" -> Protocols.ICMPV6
            "ipv4" -> Protocols.IPV4
            "ipv6" -> Protocols.IPV6
            "ethernet" -> Protocols.ETHERNET
            else -> name
        }

        /**
         * 解析输入字符串到 [FrameFilter]。
         * 空字符串/纯空白返回 [FrameFilter.MatchAll]。
         * 解析失败抛 [FilterParseException]，其 `error` 字段是 sealed [FilterParseError]。
         */
        fun parse(input: String): FrameFilter {
            // 把括号当独立 token：在 ( 和 ) 周围补空格再按空白切分。
            // 我们的参数（IP / 数字 / 子串）里不会出现括号，故安全。
            val padded = input.replace("(", " ( ").replace(")", " ) ")
            val tokens = padded.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
            if (tokens.isEmpty()) return FrameFilter.MatchAll
            val parser = FilterParser(tokens)
            val result = parser.parseExpr()
            if (parser.pos < tokens.size) {
                throw FilterParseException(FilterParseError.ExtraToken(tokens[parser.pos]))
            }
            return result
        }
    }
}

/**
 * 解析失败异常。`error` 是 sealed 错误类型；`message` 仅供开发者日志，不直接显示
 * 给用户（UI 层用 @Composable helper 映射到本地化资源）。
 */
class FilterParseException(val error: FilterParseError) : RuntimeException(error.toString())
