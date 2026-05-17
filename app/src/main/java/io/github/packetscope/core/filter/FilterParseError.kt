package io.github.packetscope.core.filter

/**
 * 过滤表达式解析错误。core 层抛 [FilterParseException] 带这个 sealed 类型作为
 * `error` 字段，UI 层通过 @Composable helper（见 FrameListScreen 的
 * `filterErrorMessage`）按当前 locale 映射成 `R.string.filter_error_*` 资源。
 *
 * 出于 review v0.6-round2 F-002：之前 FilterParser 抛中文 message，i18n 后默认
 * 英语 locale 用户仍看到中文报错，跟整个 UI 英文混排不一致。
 */
sealed interface FilterParseError {
    /** 输入末尾左括号没闭合：`(tcp or udp` */
    data object MissingRightParen : FilterParseError

    /** 应该是右括号但得到别的：`(tcp or udp]` */
    data class ExpectedRightParen(val got: String) : FilterParseError

    /** 完整表达式末尾突然结束：`host` */
    data object UnexpectedEndOfExpr : FilterParseError

    /** port 后面不是数字：`port abc` */
    data class ExpectedDigit(val token: String) : FilterParseError

    /** 端口超出 0..65535：`port 99999` */
    data class PortOutOfRange(val port: Int) : FilterParseError

    /** 不识别的关键字 / 协议名：`garbage` */
    data class UnknownToken(val token: String) : FilterParseError

    /** atom 缺参数：`host` / `sni` / `http.host` / ...。`atom` 是关键字本身，便于 UI 提示用户该 atom 期望什么参数 */
    data class MissingArg(val atom: String) : FilterParseError

    /** 表达式合法但末尾还有多余 token：`tcp foobar` */
    data class ExtraToken(val token: String) : FilterParseError
}
