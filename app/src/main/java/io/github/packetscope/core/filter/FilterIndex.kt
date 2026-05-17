package io.github.packetscope.core.filter

import io.github.packetscope.core.pcap.Field
import io.github.packetscope.core.pcap.FieldNames
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.Protocols

/**
 * 每个 Frame 的过滤预算索引。在 [io.github.packetscope.ui.PcapLoader] 解析末尾
 * 一次性算出来，与 frames 平行存（不入 Frame 本体，避免 dissector / decrypt
 * pass 全要 propagate 这个字段）。
 *
 * 索引覆盖 review v0.6-round1 F-004 列出的字段：5-tuple、SNI、http.host /
 * http.path / http.method、dns names、app name。`Text` atom 仍扫整帧 raw
 * bytes，未索引化（成本 O(n × frame_size) 太高，开 lazy 写也大）。
 *
 * 字符串字段全部小写存，子串匹配时 caller 只需 `pattern.lowercase()`。
 */
class FilterIndex(
    val protocols: Set<String>,
    val srcIp: String?,
    val dstIp: String?,
    val srcPort: Int?,
    val dstPort: Int?,
    val sniLower: String?,
    val httpHostLower: String?,
    /** HTTP Request line 的 path 部分，已小写化（review v0.6-round2 F-007） */
    val httpPathLower: String?,
    val httpMethodUpper: String?,
    val dnsNamesLower: List<String>,
    val appNameLower: String?,
) {
    fun hasProtocol(name: String): Boolean = protocols.any { it.equals(name, ignoreCase = true) }
    fun hasPort(p: Int): Boolean = srcPort == p || dstPort == p
    fun hasIp(ip: String): Boolean = srcIp == ip || dstIp == ip

    companion object {
        fun build(frame: Frame): FilterIndex {
            val protocols = HashSet<String>(frame.layers.size)
            var srcIp: String? = null
            var dstIp: String? = null
            var srcPort: Int? = null
            var dstPort: Int? = null
            var sniLower: String? = null
            var httpHostLower: String? = null
            var httpPathLower: String? = null
            var httpMethodUpper: String? = null
            val dnsNames = mutableListOf<String>()
            var appNameLower: String? = null

            for (layer in frame.layers) {
                protocols += layer.protocol
                when (layer.protocol) {
                    Protocols.IPV4, Protocols.IPV6 -> {
                        srcIp = srcIp ?: fieldValue(layer.fields, FieldNames.SOURCE)
                        dstIp = dstIp ?: fieldValue(layer.fields, FieldNames.DESTINATION)
                    }
                    Protocols.TCP, Protocols.UDP -> {
                        srcPort = srcPort ?: fieldValue(layer.fields, FieldNames.SOURCE_PORT)?.toIntOrNull()
                        dstPort = dstPort ?: fieldValue(layer.fields, FieldNames.DESTINATION_PORT)?.toIntOrNull()
                    }
                    Protocols.TLS, Protocols.QUIC -> {
                        if (sniLower == null) {
                            collectByName(layer.fields, FieldNames.SERVER_NAME_INDICATION) { v ->
                                sniLower = v.lowercase()
                                false  // 取第一个就够
                            }
                        }
                    }
                    Protocols.HTTP -> {
                        val line = fieldValue(layer.fields, FieldNames.REQUEST_LINE)
                        if (line != null) {
                            val parts = line.split(' ', limit = 3)
                            httpMethodUpper = httpMethodUpper ?: parts.getOrNull(0)?.uppercase()
                            httpPathLower = httpPathLower ?: parts.getOrNull(1)?.lowercase()
                        }
                        if (httpHostLower == null) {
                            layer.fields.firstOrNull {
                                it.name.equals(FieldNames.HOST, ignoreCase = true)
                            }?.value?.let { httpHostLower = it.lowercase() }
                        }
                    }
                    Protocols.DNS -> {
                        collectByName(layer.fields, FieldNames.NAME) { v ->
                            dnsNames += v.lowercase(); true  // 继续收集所有 Question/Answer name
                        }
                    }
                    Protocols.PCAPDROID_META -> {
                        appNameLower = appNameLower
                            ?: fieldValue(layer.fields, FieldNames.APP_NAME)?.lowercase()
                    }
                }
            }

            return FilterIndex(
                protocols, srcIp, dstIp, srcPort, dstPort,
                sniLower, httpHostLower, httpPathLower, httpMethodUpper,
                dnsNames, appNameLower,
            )
        }
    }
}

private fun fieldValue(fields: List<Field>, name: String): String? =
    fields.firstOrNull { it.name == name }?.value

/** 递归扫 fields 树命中所有 `name == [name]` 的字段，回调返回 true 表继续收集 */
private fun collectByName(fields: List<Field>, name: String, visit: (String) -> Boolean) {
    for (f in fields) {
        if (f.name == name) {
            if (!visit(f.value)) return
        }
        if (f.children.isNotEmpty()) collectByName(f.children, name, visit)
    }
}
