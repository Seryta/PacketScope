package io.github.packetscope.core.pcap

/**
 * PCAP link-layer header type.
 * 完整列表：https://www.tcpdump.org/linktypes.html
 * v0.2 只关心常见几种。
 */
enum class LinkType(val value: Int) {
    ETHERNET(1),
    RAW_IP(101),      // L3 直接是 IPv4/v6（PCAPdroid 默认导出格式）
    LINUX_SLL(113),   // Linux cooked v1（root 抓 any 接口时常见）
    LINUX_SLL2(276),  // Linux cooked v2
    UNKNOWN(-1);

    companion object {
        fun fromValue(value: Int): LinkType =
            entries.firstOrNull { it.value == value } ?: UNKNOWN
    }
}
