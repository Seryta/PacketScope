package io.github.packetscope.core.pcap

/**
 * 单个数据包的完整模型。
 *
 * **equals/hashCode 设计说明**（review v0.6-round1 F-007）：
 * 这是 data class 但 equals 改为身份比较（this === other），hashCode 用
 * index。原因是 [data] 在 v1.1 前是 ByteArray，data class 默认 equals 会逐字节比较，
 * 把 Frame 放进 HashMap / HashSet 时巨大开销；而且 Compose [SnapshotStateList]
 * 内部用 equals 判断是否变更，逐字节比较反而引起不必要 recompose。
 * 我们仍依赖 [copy()] 在 TcpSessionAnalyzer / TlsDecryptionPass 中产生加了
 * layers 的衍生 Frame，所以保留 `data class` 修饰。
 *
 * @property index 1-based 帧序号
 * @property timestampNanos 自 epoch 的纳秒时间戳
 * @property capturedLength 实际抓到的字节数（== data.size）
 * @property originalLength 网线上的原始字节数（可能 > capturedLength，如果 snaplen 截断）
 * @property data 原始字节抽象（[FrameBytes]），layers 中所有 byteRange 都相对这块数据；
 *   v1.1 LAZY-001 把它从 ByteArray 抽象成 FrameBytes，mmap 路径可零拷贝持视图
 * @property layers 解析出的协议层，从外到内（L2 → L7）
 */
data class Frame(
    val index: Int,
    val timestampNanos: Long,
    val capturedLength: Int,
    val originalLength: Int,
    val data: FrameBytes,
    val layers: List<Layer>,
) {
    /** 最外层协议名简称，用于列表显示。PCAPdroid metadata 是元数据不算协议，跳过 */
    val topProtocol: String
        get() = layers.lastOrNull { it.protocol != Protocols.PCAPDROID_META }?.protocol
            ?: Protocols.RAW

    /** 简要 Info 列内容：从最内层 layer 找有 summary 的，跳过 PCAPdroid metadata */
    val info: String
        get() = layers.asReversed()
            .firstOrNull { it.protocol != Protocols.PCAPDROID_META && !it.summary.isNullOrEmpty() }
            ?.summary ?: ""

    override fun equals(other: Any?): Boolean = this === other
    override fun hashCode(): Int = index
}

/**
 * 一个协议层的解析结果。
 *
 * @property protocol 协议名（"Ethernet"、"IPv4"、"TCP" ...）
 * @property byteRange 本层在 Frame.data 中的字节范围（含起止）
 * @property fields 字段列表，UI 协议树会按此渲染
 * @property summary 一行摘要，可用于包列表 Info 列（如 "10.0.0.1 → 8.8.8.8"）
 * @property truncated 解析时数据不足；UI 上提示
 */
data class Layer(
    val protocol: String,
    val byteRange: IntRange,
    val fields: List<Field>,
    val summary: String? = null,
    val truncated: Boolean = false,
)

/**
 * 协议树中的字段。
 *
 * @property name 字段名（"Source MAC"、"TTL" ...）
 * @property value 显示值（已格式化为字符串）
 * @property byteRange 字段在 Frame.data 中的字节范围；为空表示派生字段（没有直接对应字节）
 * @property children 嵌套子字段，例如 TCP flags 下的 SYN/ACK/FIN
 */
data class Field(
    val name: String,
    val value: String,
    val byteRange: IntRange? = null,
    val children: List<Field> = emptyList(),
)
