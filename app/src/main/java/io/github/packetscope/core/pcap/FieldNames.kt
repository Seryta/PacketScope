package io.github.packetscope.core.pcap

/**
 * 字段名常量集合（review v0.6-round2 F-011）。
 *
 * round1 F-008 收敛了协议名，本轮兑现 review 当时承诺的"字段名留下一轮"——
 * dissector 产出的 `Field.name` + 其它 pass / filter 字符串比对都用这里的常量，
 * 避免 hardcoded `"Source port"` 这种字面量散落造成 typo 隐患。
 *
 * 新加字段名要在此处加一行常量。
 */
object FieldNames {
    // IP layer
    const val SOURCE = "Source"
    const val DESTINATION = "Destination"

    // L4
    const val SOURCE_PORT = "Source port"
    const val DESTINATION_PORT = "Destination port"

    // TLS
    const val HANDSHAKE = "Handshake"
    const val SERVER_NAME_INDICATION = "Server Name Indication"

    // HTTP
    const val REQUEST_LINE = "Request line"
    const val HOST = "Host"

    // DNS
    const val NAME = "Name"

    // PCAPdroid metadata
    const val APP_NAME = "App name"
}
