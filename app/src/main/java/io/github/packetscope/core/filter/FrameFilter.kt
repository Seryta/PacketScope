package io.github.packetscope.core.filter

import io.github.packetscope.core.pcap.Field
import io.github.packetscope.core.pcap.FieldNames
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.Layer
import io.github.packetscope.core.pcap.Protocols

/**
 * 帧过滤表达式 AST。
 *
 * 双路径匹配（review v0.6-round1 F-004）：
 *   - 文件模式：[io.github.packetscope.ui.PcapLoader] 在解析末尾构建 [FilterIndex]
 *     与 frames 平行；UI 调 [matches] 时传 index，atom 走 O(1)/O(small) 字段读。
 *   - 流式模式：[io.github.packetscope.service.UdpExporterService] 把帧追加进
 *     SnapshotStateList，没有预算索引；UI 调 [matches] 不传 index，atom 回退到
 *     旧的 layer 树遍历。
 *
 * `Text` atom 两条路径都扫整帧 raw bytes（O(n × frame_size)），未索引化 ——
 * 预算 rawTextLower 字符串的空间成本太高，留 backlog。
 */
sealed interface FrameFilter {
    fun matches(frame: Frame, index: FilterIndex? = null): Boolean

    /** 匹配全部，空过滤表达式的默认值 */
    data object MatchAll : FrameFilter {
        override fun matches(frame: Frame, index: FilterIndex?): Boolean = true
    }

    /** 按协议名（不区分大小写） */
    data class Protocol(val name: String) : FrameFilter {
        override fun matches(frame: Frame, index: FilterIndex?): Boolean =
            if (index != null) index.hasProtocol(name)
            else frame.layers.any { it.protocol.equals(name, ignoreCase = true) }
    }

    /** 任一方向的 TCP/UDP 端口匹配 */
    data class Port(val port: Int) : FrameFilter {
        override fun matches(frame: Frame, index: FilterIndex?): Boolean {
            if (index != null) return index.hasPort(port)
            return frame.layers.any { layer ->
                (layer.protocol == Protocols.TCP || layer.protocol == Protocols.UDP) &&
                    hasPort(layer.fields, port)
            }
        }

        private fun hasPort(fields: List<Field>, port: Int): Boolean {
            val src = fields.firstOrNull { it.name == FieldNames.SOURCE_PORT }?.value?.toIntOrNull()
            val dst = fields.firstOrNull { it.name == FieldNames.DESTINATION_PORT }?.value?.toIntOrNull()
            return src == port || dst == port
        }
    }

    /** 任一方向的 IP 地址（精确字符串匹配，不做 CIDR） */
    data class Host(val ip: String) : FrameFilter {
        override fun matches(frame: Frame, index: FilterIndex?): Boolean {
            if (index != null) return index.hasIp(ip)
            return frame.layers.any { layer ->
                (layer.protocol == Protocols.IPV4 || layer.protocol == Protocols.IPV6) &&
                    hasHost(layer.fields, ip)
            }
        }

        private fun hasHost(fields: List<Field>, ip: String): Boolean {
            val src = fields.firstOrNull { it.name == FieldNames.SOURCE }?.value
            val dst = fields.firstOrNull { it.name == FieldNames.DESTINATION }?.value
            return src == ip || dst == ip
        }
    }

    /** TLS ClientHello 内的 SNI 子串包含（"google" 能匹配 "www.google.com"） */
    data class Sni(val pattern: String) : FrameFilter {
        // 在 atom 构造时一次性 lowercase，避免 matches 热路径每次重算
        // （review v0.6-round2 F-007）
        private val patternLower: String = pattern.lowercase()
        override fun matches(frame: Frame, index: FilterIndex?): Boolean {
            if (index != null) {
                return index.sniLower?.contains(patternLower) == true
            }
            for (layer in frame.layers) {
                if (layer.protocol != Protocols.TLS) continue
                val hs = layer.fields.firstOrNull { it.name == FieldNames.HANDSHAKE } ?: continue
                val sni = hs.children.firstOrNull { it.name == FieldNames.SERVER_NAME_INDICATION } ?: continue
                if (sni.value.contains(pattern, ignoreCase = true)) return true
            }
            return false
        }
    }

    /** HTTP "Host" header 子串包含 */
    data class HttpHost(val pattern: String) : FrameFilter {
        private val patternLower: String = pattern.lowercase()
        override fun matches(frame: Frame, index: FilterIndex?): Boolean {
            if (index != null) {
                return index.httpHostLower?.contains(patternLower) == true
            }
            return frame.layers.any { layer ->
                layer.protocol == Protocols.HTTP && layer.fields.any {
                    it.name.equals(FieldNames.HOST, ignoreCase = true) &&
                        it.value.contains(pattern, ignoreCase = true)
                }
            }
        }
    }

    /** HTTP Request line 中 path 部分子串包含（如 "/api/v1"） */
    data class HttpPath(val pattern: String) : FrameFilter {
        private val patternLower: String = pattern.lowercase()
        override fun matches(frame: Frame, index: FilterIndex?): Boolean {
            if (index != null) {
                return index.httpPathLower?.contains(patternLower) == true
            }
            return frame.layers.any { layer ->
                if (layer.protocol != Protocols.HTTP) return@any false
                val line = requestLine(layer) ?: return@any false
                val path = line.split(' ').getOrNull(1) ?: return@any false
                path.contains(pattern, ignoreCase = true)
            }
        }
    }

    /** HTTP method 等于（GET/POST/...） */
    data class HttpMethod(val method: String) : FrameFilter {
        override fun matches(frame: Frame, index: FilterIndex?): Boolean {
            if (index != null) {
                return index.httpMethodUpper?.equals(method, ignoreCase = true) == true
            }
            return frame.layers.any { layer ->
                if (layer.protocol != Protocols.HTTP) return@any false
                val line = requestLine(layer) ?: return@any false
                line.substringBefore(' ').equals(method, ignoreCase = true)
            }
        }
    }

    /** "URL" 模糊匹配：HTTP 拼 Host+path、TLS 拼 SNI、QUIC 拼 SNI 一起子串包含 */
    data class Url(val pattern: String) : FrameFilter {
        private val patternLower: String = pattern.lowercase()
        override fun matches(frame: Frame, index: FilterIndex?): Boolean {
            if (index != null) {
                val httpFull = index.httpHostLower.orEmpty() + index.httpPathLower.orEmpty()
                if (httpFull.contains(patternLower)) return true
                if (index.sniLower?.contains(patternLower) == true) return true
                return false
            }
            // 非索引分支也用 patternLower 风格一致（review v0.6-round3 F-008）
            for (layer in frame.layers) when (layer.protocol) {
                Protocols.HTTP -> {
                    val host = layer.fields.firstOrNull {
                        it.name.equals(FieldNames.HOST, ignoreCase = true)
                    }?.value.orEmpty()
                    val line = requestLine(layer).orEmpty()
                    val path = line.split(' ').getOrNull(1).orEmpty()
                    // 只匹配 "Host+path"，不再扫整条 Request line —— 否则会被 method
                    // / HTTP version 字符串误命中（review v0.6-round2 F-005）
                    if ((host + path).lowercase().contains(patternLower)) return true
                }
                Protocols.TLS, Protocols.QUIC -> {
                    if (anyFieldNamed(layer.fields, FieldNames.SERVER_NAME_INDICATION) {
                            it.lowercase().contains(patternLower)
                        }) return true
                }
            }
            return false
        }
    }

    /** DNS 任意 Question / Answer 中 "Name" 字段子串包含 */
    data class DnsName(val pattern: String) : FrameFilter {
        private val patternLower: String = pattern.lowercase()
        override fun matches(frame: Frame, index: FilterIndex?): Boolean {
            if (index != null) {
                return index.dnsNamesLower.any { it.contains(patternLower) }
            }
            return frame.layers.any { layer ->
                layer.protocol == Protocols.DNS && anyFieldNamed(layer.fields, FieldNames.NAME) {
                    it.contains(pattern, ignoreCase = true)
                }
            }
        }
    }

    /** PCAPdroid metadata 中的 App name 子串包含 */
    data class App(val pattern: String) : FrameFilter {
        private val patternLower: String = pattern.lowercase()
        override fun matches(frame: Frame, index: FilterIndex?): Boolean {
            if (index != null) {
                return index.appNameLower?.contains(patternLower) == true
            }
            return frame.layers.any { layer ->
                layer.protocol == Protocols.PCAPDROID_META && layer.fields.any {
                    it.name == FieldNames.APP_NAME && it.value.contains(pattern, ignoreCase = true)
                }
            }
        }
    }

    /** 帧 raw bytes 当 Latin-1 字符串后子串包含；二进制载荷的文本片段都能命中。
     *  注：未索引化（O(n × frame_size)），大列表上注意性能。 */
    data class Text(val pattern: String) : FrameFilter {
        override fun matches(frame: Frame, index: FilterIndex?): Boolean =
            String(frame.data, Charsets.ISO_8859_1).contains(pattern, ignoreCase = true)
    }

    data class And(val left: FrameFilter, val right: FrameFilter) : FrameFilter {
        override fun matches(frame: Frame, index: FilterIndex?) =
            left.matches(frame, index) && right.matches(frame, index)
    }

    data class Or(val left: FrameFilter, val right: FrameFilter) : FrameFilter {
        override fun matches(frame: Frame, index: FilterIndex?) =
            left.matches(frame, index) || right.matches(frame, index)
    }

    data class Not(val inner: FrameFilter) : FrameFilter {
        override fun matches(frame: Frame, index: FilterIndex?) =
            !inner.matches(frame, index)
    }
}

// internal 而非 private：被同文件 sealed atom 调用，private 顶层会让 JVM
// 走 synthetic accessor bridge（review v0.6-round4 F-004）
internal fun requestLine(layer: Layer): String? =
    layer.fields.firstOrNull { it.name == FieldNames.REQUEST_LINE }?.value

/** 递归扫 fields 树，找叫 [name] 且 value 满足 [predicate] 的字段。
 *  internal 同 [requestLine] 原因：避免 synthetic accessor bridge */
internal fun anyFieldNamed(
    fields: List<Field>,
    name: String,
    predicate: (String) -> Boolean,
): Boolean {
    for (f in fields) {
        if (f.name == name && predicate(f.value)) return true
        if (f.children.isNotEmpty() && anyFieldNamed(f.children, name, predicate)) return true
    }
    return false
}
