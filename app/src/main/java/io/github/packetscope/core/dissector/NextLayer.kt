package io.github.packetscope.core.dissector

import io.github.packetscope.core.dissector.l3.IPv4Dissector
import io.github.packetscope.core.dissector.l3.IPv6Dissector
import io.github.packetscope.core.dissector.l3.IcmpDissector
import io.github.packetscope.core.dissector.l3.Icmpv6Dissector
import io.github.packetscope.core.dissector.l4.TcpDissector
import io.github.packetscope.core.dissector.l4.UdpDissector
import io.github.packetscope.core.dissector.l7.DnsDissector
import io.github.packetscope.core.dissector.l7.HttpDissector
import io.github.packetscope.core.dissector.l7.QuicDissector
import io.github.packetscope.core.dissector.l7.TlsDissector

/** L2/L3/L4 之间以及 L4 → L7 的路由表 */
internal object NextLayer {

    /**
     * 探针 fallback 时把已经 dissect 出来的 L7 result 一起带回，Pipeline 复用
     * 避免重复 dissect（review v0.6-round2 F-006）。端口命中分支没 prefetched，
     * 留给 Pipeline 正常走。
     */
    data class Probed(val dissector: Dissector, val prefetched: DissectResult?) {
        /** 转换成 sealed [NextStep]：有 prefetched 走 Prefetched 否则 Continue。 */
        fun toNextStep(continueOffset: Int): NextStep =
            if (prefetched != null) NextStep.Prefetched(prefetched)
            else NextStep.Continue(continueOffset, dissector)
    }

    fun byEtherType(etherType: Int): Dissector? = when (etherType) {
        0x0800 -> IPv4Dissector
        0x86DD -> IPv6Dissector
        else -> null
    }

    fun byIpProtocol(proto: Int): Dissector? = when (proto) {
        1 -> IcmpDissector
        6 -> TcpDissector
        17 -> UdpDissector
        58 -> Icmpv6Dissector
        else -> null
    }

    /**
     * 按 TCP 任一方向端口选 L7 dissector，端口未命中时按 TLS → HTTP 顺序做探针式
     * fallback。TLS 守得严（record type + version 都检），HTTP 文本检测较松，故
     * TLS 排前面避免 HTTP 误抢非默认端口的 TLS 流量。DNS 自防弱，不参加 fallback。
     */
    fun byTcpPort(
        srcPort: Int, dstPort: Int,
        payload: ByteArray, payloadOffset: Int,
    ): Probed? {
        val anyMatch = { ports: Set<Int> -> srcPort in ports || dstPort in ports }
        when {
            anyMatch(HTTP_PORTS) -> return Probed(HttpDissector, null)
            anyMatch(TLS_PORTS) -> return Probed(TlsDissector, null)
        }
        // fallback：依次试 TLS / HTTP；把 dissect 结果一并带回供 Pipeline 复用
        if (payloadOffset < payload.size) {
            TlsDissector.dissect(payload, payloadOffset)?.let {
                return Probed(TlsDissector, it)
            }
            HttpDissector.dissect(payload, payloadOffset)?.let {
                return Probed(HttpDissector, it)
            }
        }
        return null
    }

    /**
     * 按 UDP 端口选 L7 dissector，端口未命中时探针 QUIC（long-header 严守 0xC0+
     * plausible version，误命中风险低）。DNS 同 TCP 因自防弱不参加 fallback。
     */
    fun byUdpPort(
        srcPort: Int, dstPort: Int,
        payload: ByteArray, payloadOffset: Int,
    ): Probed? {
        val anyMatch = { ports: Set<Int> -> srcPort in ports || dstPort in ports }
        when {
            anyMatch(DNS_PORTS) -> return Probed(DnsDissector, null)
            anyMatch(QUIC_PORTS) -> return Probed(QuicDissector, null)
        }
        if (payloadOffset < payload.size) {
            QuicDissector.dissect(payload, payloadOffset)?.let {
                return Probed(QuicDissector, it)
            }
        }
        return null
    }

    private val HTTP_PORTS = setOf(80, 8000, 8080, 8081)
    private val TLS_PORTS = setOf(443, 8443)
    private val DNS_PORTS = setOf(53)
    private val QUIC_PORTS = setOf(443)  // QUIC 默认也 443 (UDP)
}
