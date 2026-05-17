package io.github.packetscope.core.decrypt

import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf

/**
 * 进程级别的 (client_random → labels → secret) 索引。
 *
 * 设计取舍：把 keylog 作为 process-singleton 而不是 AppState 字段，因为
 * keylog 通常是「一次加载，多次使用」——用户加载 PCAP 时 PcapLoader 会查它。
 */
object KeyLogStore {
    // key = lowercase hex(client_random)，value = label → secret
    private val byRandom = mutableMapOf<String, MutableMap<String, ByteArray>>()

    val sessionCount = mutableIntStateOf(0)
    val fileName = mutableStateOf<String?>(null)

    fun load(entries: List<KeyLogEntry>, sourceName: String?) {
        // 走 clear() 确保旧 secret bytes 也被 fill(0) 擦除（review v0.6-round3
        // F-002：避免用户直接选另一份 keylog 替换时旧 secret 残留堆）
        clear()
        for (e in entries) {
            val key = e.clientRandom.toHexLower()
            val m = byRandom.getOrPut(key) { mutableMapOf() }
            m[e.label] = e.secret
        }
        sessionCount.intValue = byRandom.size
        fileName.value = sourceName
    }

    /**
     * 释放所有 keylog。先 [ByteArray.fill] 0 覆盖 secret 字节再 clear，避免
     * GC 异步回收前敏感数据残留堆。威胁模型不强（消费 Android 设备 root 需要
     * 解锁 bootloader），但密码学敏感数据**清就该清干净**（review v0.6-round2
     * F-008）。
     */
    fun clear() {
        for (labels in byRandom.values) {
            for (secret in labels.values) secret.fill(0)
        }
        byRandom.clear()
        sessionCount.intValue = 0
        fileName.value = null
    }

    fun lookup(clientRandom: ByteArray): Map<String, ByteArray>? =
        byRandom[clientRandom.toHexLower()]

    /** UI 测试用 */
    val isLoaded: Boolean get() = byRandom.isNotEmpty()
}
