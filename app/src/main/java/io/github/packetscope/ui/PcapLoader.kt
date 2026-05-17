package io.github.packetscope.ui

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import io.github.packetscope.R
import io.github.packetscope.core.analysis.TcpSessionAnalyzer
import io.github.packetscope.core.decrypt.QuicInitialPass
import io.github.packetscope.core.decrypt.TlsDecryptionPass
import io.github.packetscope.core.dissector.Pipeline
import io.github.packetscope.core.filter.FilterIndex
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.LinkType
import io.github.packetscope.core.pcap.PcapMmapReader
import io.github.packetscope.core.pcap.PcapReader
import io.github.packetscope.core.pcap.RawFrame
import io.github.packetscope.core.reassemble.HttpStreamPass
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.FileInputStream
import java.io.IOException
import java.io.PushbackInputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel

/**
 * 把 URI 指向的 PCAP 文件读完并交给 [Pipeline] 解析。
 *
 * v1.0 round1 REFACTOR-001（兑现 v0.6-round7 F-007 deferred）：单 fd 路径。
 *
 * 路径优先级：
 *  1. ParcelFileDescriptor.openFileDescriptor("r") → FileChannel
 *     - `FileChannel.read(buf, position=0)` 读首 4 字节判 PCAPng magic
 *       （不动 channel position，下一步 map 不受影响）
 *     - 非 PCAPng → `FileChannel.map(...)` 走 PcapMmapReader
 *  2. fd 不可用（cloud provider / 异常）→ fallback `openInputStream`
 *     + PushbackInputStream + PcapReader
 *
 * 原 v0.9 实现先开 InputStream 检 magic、再开 fd 走 mmap，浪费一个 fd
 * （review v0.6-round7 F-007）。本轮合到单 fd。
 */
object PcapLoader {

    /** 单次加载体积上限。v0.9 引入 mmap IO；v1.1 LAZY-002 让 Frame.data 真 lazy
     *  （MmapBytes 视图零拷贝），raw bytes 不再占 heap——只剩 layers / fields /
     *  indices 元数据是堆压力来源。本 commit (LAZY-005) 把上限从 500 MB 推到
     *  1 GB，给同样元数据 budget 留 ~2 倍 PCAP 体积空间。
     *
     *  2 GB 留 v2.0：[java.nio.MappedByteBuffer] 单 buffer 索引上限 Int.MAX_VALUE
     *  (~2.1 GB)，> 2 GB 需要多段 mmap (PcapMultiMapReader)；GB 级 metadata 树
     *  本身也开始压 heap。详见 ANDROID_PITFALLS.md。 */
    const val MAX_FILE_BYTES: Long = 1L * 1024 * 1024 * 1024

    /**
     * 加载并解析 PCAP 文件。所有 user-facing 错误消息走 [Context.getString]
     * 走资源本地化。
     */
    suspend fun load(context: Context, uri: Uri): Result = withContext(Dispatchers.IO) {
        val resolver = context.contentResolver
        // 先查文件大小，超过阈值直接拒绝，避免一路读到 OOM 才崩
        val size = querySize(resolver, uri)
        if (size != null && size > MAX_FILE_BYTES) {
            return@withContext Result.Failure(
                context.getString(
                    R.string.error_file_too_large,
                    (size / 1024 / 1024).toInt(),
                    (MAX_FILE_BYTES / 1024 / 1024).toInt(),
                )
            )
        }

        // 优先 fd → FileChannel → mmap 单 fd 路径；fd 不可用 fallback InputStream
        tryLoadViaFd(context, uri) ?: loadViaInputStream(context, uri)
    }

    /** ParcelFileDescriptor → FileChannel 路径：读首 4 字节 magic + mmap 解析。
     *  fd 不可用返 null 让 caller fallback；mmap 解析期间 IOException 直接
     *  返 Failure（不再 fallback，避免同一文件解析两遍）。 */
    private fun tryLoadViaFd(context: Context, uri: Uri): Result? {
        val pfd = runCatching {
            context.contentResolver.openFileDescriptor(uri, "r")
        }.getOrNull() ?: return null
        return try {
            pfd.use { p ->
                FileInputStream(p.fileDescriptor).channel.use { ch ->
                    loadViaChannel(context, ch)
                }
            }
        } catch (e: IOException) {
            Result.Failure(context.getString(R.string.error_parse, e.message ?: ""))
        } catch (e: Exception) {
            Result.Failure(context.getString(R.string.error_unexpected, e.message ?: ""))
        }
    }

    /** 在已开 [FileChannel] 上：读 magic → 非 PCAPng → mmap reader → 解析。
     *  reader 不 close —— mmap 视图随 Frame.data 存活到 PcapHandle.close()；
     *  channel 由 [tryLoadViaFd] 外层 .use{} 在 load 完成后关闭，但 mmap 已
     *  mapped 进进程地址空间，不依赖 channel 持续 alive。 */
    private fun loadViaChannel(context: Context, ch: FileChannel): Result {
        val magic = ByteArray(4)
        // FileChannel.read(buf, position) 不消耗 channel position；map 不受影响
        val n = ch.read(ByteBuffer.wrap(magic), 0)
        if (n == 4 && isPcapNgMagic(magic)) {
            return Result.Failure(context.getString(R.string.error_pcapng_unsupported))
        }
        val reader = PcapMmapReader(ch)
        return loadFromRawFrames(
            linkType = reader.linkType,
            rawList = reader.frames().toList(),
            // PcapHandle.close → 显式 unmap，释放 mmap 占的进程地址空间。
            // reader 强引用走 lambda capture，与 PcapHandle 共存活。
            onClose = { reader.tryExplicitUnmap() },
        )
    }

    /** Fallback：fd 不可用时走 InputStream + PushbackInputStream peek magic +
     *  PcapReader。SAF provider 不支持 fd（cloud-only）时唯一路径。 */
    private fun loadViaInputStream(context: Context, uri: Uri): Result {
        val resolver = context.contentResolver
        val stream = try {
            resolver.openInputStream(uri)
                ?: return Result.Failure(context.getString(R.string.error_open_stream_null))
        } catch (e: Exception) {
            return Result.Failure(context.getString(R.string.error_open_stream, e.message ?: ""))
        }
        return try {
            stream.use { input ->
                val pushback = PushbackInputStream(input, 4)
                val magic = ByteArray(4)
                val n = pushback.read(magic)
                if (n == 4) pushback.unread(magic)
                if (n == 4 && isPcapNgMagic(magic)) {
                    return Result.Failure(
                        context.getString(R.string.error_pcapng_unsupported)
                    )
                }
                val reader = PcapReader(pushback)
                loadFromRawFrames(
                    linkType = reader.linkType,
                    rawList = reader.frames().toList(),
                    // InputStream 路径下 Frame.data 是 HeapBytes，无 mmap 资源
                    // 需要释放——close 是 no-op
                    onClose = {},
                )
            }
        } catch (e: IOException) {
            Result.Failure(context.getString(R.string.error_parse, e.message ?: ""))
        } catch (e: Exception) {
            Result.Failure(context.getString(R.string.error_unexpected, e.message ?: ""))
        }
    }

    /** 公共解析路径：raw frames → Pipeline + analyzer + decrypt + filter index */
    private fun loadFromRawFrames(
        linkType: LinkType,
        rawList: List<RawFrame>,
        onClose: () -> Unit,
    ): Result {
        val pipeline = Pipeline(linkType)
        val rawFrames = rawList.map(pipeline::process)
        val withTcpAnalysis = TcpSessionAnalyzer.process(rawFrames)
        val withHttp = HttpStreamPass.process(withTcpAnalysis)
        val withTls = TlsDecryptionPass.process(withHttp)
        val frames = QuicInitialPass.process(withTls)
        val indices = frames.map(FilterIndex::build)
        return Result.Success(PcapHandle(linkType, frames, indices, onClose))
    }

    /** PCAPng Section Header Block magic: 0x0A 0x0D 0x0D 0x0A
     *  （字节序无关，四字节都不同） */
    private fun isPcapNgMagic(b: ByteArray): Boolean =
        b[0] == 0x0A.toByte() && b[1] == 0x0D.toByte() &&
            b[2] == 0x0D.toByte() && b[3] == 0x0A.toByte()

    /** 查询 SAF URI 的文件大小；某些 provider 可能不报，那时返回 null 不卡限制 */
    private fun querySize(resolver: ContentResolver, uri: Uri): Long? = try {
        resolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (!c.moveToFirst()) null
            else c.getColumnIndex(OpenableColumns.SIZE)
                .takeIf { it >= 0 && !c.isNull(it) }
                ?.let { c.getLong(it) }
        }
    } catch (_: Exception) {
        null
    }

    sealed interface Result {
        /** 成功路径——产物用 [PcapHandle] 持有以管 mmap 生命周期。
         *  调用方拿到 frames/indices/linkType 通过 `handle.frames` 等；用完调
         *  `handle.close()` 释放 mmap（AppScreen 在 state 切换时通过
         *  DisposableEffect 触发）。 */
        data class Success(val handle: PcapHandle) : Result
        data class Failure(val message: String) : Result
    }
}
