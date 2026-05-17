package io.github.packetscope.ui

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.fakes.RoboCursor
import java.io.ByteArrayInputStream

/**
 * review v0.6-round3 F-004：兑现 round2 F-012 deferred 的尾巴。
 * Robolectric ShadowContentResolver.registerInputStream + 自定义 cursor
 * 模拟 SAF URI，覆盖 PCAPng magic + 50MB 阈值 + 正常加载 + 缺 SIZE column
 * 几条路径。
 */
@RunWith(AndroidJUnit4::class)
@Config(sdk = [35])
class PcapLoaderTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val resolver: ContentResolver get() = context.contentResolver
    // Robolectric 4.14 ShadowContentResolver 没 clearContentProviders；每个 @Test
    // 拿到的是新 application context，无需手动 cleanup。

    @Test
    fun `PCAPng SHB magic 返回 Failure error_pcapng_unsupported`() = runBlocking {
        val pcapng = byteArrayOf(0x0A, 0x0D, 0x0D, 0x0A, 0, 0, 0, 28)
        val uri = registerStream("file.pcapng", pcapng)
        // SIZE column 不提供（querySize 返回 null），让流程进到 magic 检测
        val result = PcapLoader.load(context, uri)
        assertTrue("PCAPng magic 应触发 Failure", result is PcapLoader.Result.Failure)
        val expected = context.getString(
            io.github.packetscope.R.string.error_pcapng_unsupported)
        assertEquals(expected, (result as PcapLoader.Result.Failure).message)
    }

    @Test
    fun `文件大小超阈值返回 Failure error_file_too_large`() = runBlocking {
        // v0.9 拆 50MB → 500MB；用 600MB sample 触发上限
        val uri = registerStreamWithSize(
            "huge.pcap", ByteArray(0),
            sizeBytes = 600L * 1024 * 1024,
        )
        val result = PcapLoader.load(context, uri)
        assertTrue("超阈值应直接 Failure，不读 stream",
            result is PcapLoader.Result.Failure)
        val msg = (result as PcapLoader.Result.Failure).message
        assertTrue("message 应含 600（实际大小）", msg.contains("600"))
        assertTrue("message 应含 500（阈值）", msg.contains("500"))
    }

    @Test
    fun `阈值内不触发 size check`() = runBlocking {
        // 报小 size 但流内容是 PCAPng magic —— 验证 size 检测放过后 magic 检测才生效
        val uri = registerStreamWithSize(
            "small.pcapng",
            byteArrayOf(0x0A, 0x0D, 0x0D, 0x0A, 0, 0, 0, 28),
            sizeBytes = 1024,
        )
        val result = PcapLoader.load(context, uri)
        assertTrue(result is PcapLoader.Result.Failure)
        assertTrue("应是 PCAPng error 而非 size error",
            (result as PcapLoader.Result.Failure).message.contains("PCAPng"))
    }

    @Test
    fun `provider 不报 size 时不卡限制`() = runBlocking {
        // querySize 返回 null（cursor 没 SIZE column）—— PCAPng magic 仍能检测
        val uri = registerStream("noSize.pcapng",
            byteArrayOf(0x0A, 0x0D, 0x0D, 0x0A))
        val result = PcapLoader.load(context, uri)
        assertNotNull(result)
        // 没 size column，能跑到 magic 检测路径
        assertTrue(result is PcapLoader.Result.Failure)
    }

    @Test
    fun `合法 PCAP 流返回 Success`() = runBlocking {
        // 构造最小合法 PCAP（global header + 0 packets），用 PcapTestFixtures
        val pcap = io.github.packetscope.core.PcapTestFixtures.build(
            linkType = 1, packets = emptyList())
        val uri = registerStream("ok.pcap", pcap)
        val result = PcapLoader.load(context, uri)
        assertTrue("合法 PCAP 应 Success", result is PcapLoader.Result.Success)
        val s = result as PcapLoader.Result.Success
        assertEquals(0, s.handle.frames.size)
        assertEquals(0, s.handle.indices.size)
        s.handle.close()
    }

    @Test
    fun `provider 不报 size + 合法 PCAP 仍返回 Success`() = runBlocking {
        // PCAPdroid 实时分享场景：content URI 来自其它 app provider，多数不报 SIZE
        // column。这条路径过去几个 round 没显式测过，本测试兜底 review v0.6-round4 F-008
        val pcap = io.github.packetscope.core.PcapTestFixtures.build(
            linkType = 1, packets = emptyList())
        // registerStream 不注 cursor → querySize 返回 null
        val uri = registerStream("no-size.pcap", pcap)
        val result = PcapLoader.load(context, uri)
        assertTrue("querySize 返回 null 不应影响合法 PCAP 加载",
            result is PcapLoader.Result.Success)
    }

    // ─── helpers ───────────────────────────────────────────────────────

    /** 注册 URI → InputStream，不暴露 SIZE column（query 返回 null cursor） */
    private fun registerStream(path: String, bytes: ByteArray): Uri {
        val uri = Uri.parse("content://test/$path")
        shadowOf(resolver).registerInputStream(uri, ByteArrayInputStream(bytes))
        return uri
    }

    /** 注册 URI → InputStream + SIZE column 的简单 cursor */
    private fun registerStreamWithSize(path: String, bytes: ByteArray, sizeBytes: Long): Uri {
        val uri = Uri.parse("content://test/$path")
        shadowOf(resolver).registerInputStream(uri, ByteArrayInputStream(bytes))
        val cursor = RoboCursor().apply {
            setColumnNames(listOf(OpenableColumns.SIZE))
            setResults(arrayOf(arrayOf<Any>(sizeBytes)))
        }
        shadowOf(resolver).setCursor(uri, cursor)
        return uri
    }
}
