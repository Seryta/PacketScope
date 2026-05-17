package io.github.packetscope.core.analysis

import io.github.packetscope.core.pcap.FieldNames
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.Protocols

/**
 * 按 5-tuple 聚合的 TCP/UDP 会话统计。
 *
 * endpointA / endpointB 用排序后的 "ip:port" 作 key，保证双向是同一个 Conversation。
 */
data class Conversation(
    val endpointA: String,
    val endpointB: String,
    val protocol: String,    // TCP / UDP / Other
    val packets: Int,
    val bytes: Long,
    val firstFrameIndex: Int,
    val lastFrameIndex: Int,
    val appName: String?,    // PCAPdroid metadata 提取，若有
)

object ConversationBuilder {

    fun build(frames: List<Frame>): List<Conversation> {
        val map = mutableMapOf<String, Acc>()
        for (frame in frames) {
            val tuple = extractTuple(frame) ?: continue
            val key = sessionKey(tuple)
            val acc = map.getOrPut(key) {
                Acc(tuple.endpointA, tuple.endpointB, tuple.protocol, frame.index)
            }
            acc.packets++
            acc.bytes += frame.originalLength.toLong()
            acc.lastFrameIndex = frame.index
            if (acc.appName == null) acc.appName = appNameOf(frame)
        }
        return map.values
            .map { it.toConversation() }
            .sortedByDescending { it.bytes }
    }

    private data class Tuple(
        val endpointA: String,
        val endpointB: String,
        val protocol: String,
    )

    private class Acc(
        val endpointA: String,
        val endpointB: String,
        val protocol: String,
        val firstFrameIndex: Int,
    ) {
        var packets: Int = 0
        var bytes: Long = 0
        var lastFrameIndex: Int = firstFrameIndex
        var appName: String? = null
        fun toConversation() = Conversation(
            endpointA, endpointB, protocol, packets, bytes,
            firstFrameIndex, lastFrameIndex, appName,
        )
    }

    private fun extractTuple(frame: Frame): Tuple? {
        val ip = frame.layers.firstOrNull { it.protocol == Protocols.IPV4 || it.protocol == Protocols.IPV6 } ?: return null
        val l4 = frame.layers.firstOrNull { it.protocol == Protocols.TCP || it.protocol == Protocols.UDP } ?: return null
        val srcIp = ip.fields.firstOrNull { it.name == FieldNames.SOURCE }?.value ?: return null
        val dstIp = ip.fields.firstOrNull { it.name == FieldNames.DESTINATION }?.value ?: return null
        val sport = l4.fields.firstOrNull { it.name == FieldNames.SOURCE_PORT }?.value?.toIntOrNull() ?: return null
        val dport = l4.fields.firstOrNull { it.name == FieldNames.DESTINATION_PORT }?.value?.toIntOrNull() ?: return null
        // 结构化比较：先按 IP 字面（IPv4/IPv6 段都用十进制字符串，字典序对 v4 段
        // 有错——10.0.0.1 < 9.0.0.1——但 review F-015 标 P3，先按数值比 port
        // 修掉端口反直觉，IP 段比较留 backlog；同 IP 时 port 走数值比就够。
        val (endpointA, endpointB) = if (compareEndpoints(srcIp, sport, dstIp, dport) <= 0) {
            "$srcIp:$sport" to "$dstIp:$dport"
        } else {
            "$dstIp:$dport" to "$srcIp:$sport"
        }
        return Tuple(endpointA, endpointB, l4.protocol)
    }

    /** 先比 IP 字符串，相等再比 port 数值。避免 ":9" > ":80" 的字典序反直觉 */
    private fun compareEndpoints(ipA: String, portA: Int, ipB: String, portB: Int): Int {
        val ipCmp = ipA.compareTo(ipB)
        return if (ipCmp != 0) ipCmp else portA.compareTo(portB)
    }

    private fun sessionKey(t: Tuple): String = "${t.protocol}|${t.endpointA}|${t.endpointB}"

    private fun appNameOf(frame: Frame): String? =
        frame.layers.firstOrNull { it.protocol == Protocols.PCAPDROID_META }
            ?.fields?.firstOrNull { it.name == FieldNames.APP_NAME }?.value
            ?.takeIf { it.isNotEmpty() }
}
