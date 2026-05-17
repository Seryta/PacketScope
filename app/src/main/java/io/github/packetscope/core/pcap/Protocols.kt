package io.github.packetscope.core.pcap

/**
 * 全仓库协议名常量，避免散落字面量造成 typo 隐患
 * （review v0.6-round1 F-008）。
 *
 * 这是显示名 / [Layer.protocol] 的唯一真源；filter 解析协议关键字时也比对
 * 这里的常量。新增协议要在此处加一行。
 *
 * 字段名（"Source"、"Destination"、"Source port"、"Server Name Indication"
 * ...）见同目录 [FieldNames]（review v0.6-round2 F-011 兑现）。
 */
object Protocols {
    const val ETHERNET = "Ethernet"
    const val LINUX_SLL_V1 = "Linux cooked v1"
    const val LINUX_SLL_V2 = "Linux cooked v2"

    const val IPV4 = "IPv4"
    const val IPV6 = "IPv6"
    const val ICMP = "ICMP"
    const val ICMPV6 = "ICMPv6"

    const val TCP = "TCP"
    const val UDP = "UDP"

    const val DNS = "DNS"
    const val HTTP = "HTTP"
    const val TLS = "TLS"
    const val QUIC = "QUIC"

    const val PCAPDROID_META = "PCAPdroid metadata"

    /** 未识别 L2/L3 时显示的兜底 */
    const val RAW = "Raw"
}
