package io.github.packetscope.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import io.github.packetscope.R
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.github.takahirom.roborazzi.RobolectricDeviceQualifiers
import com.github.takahirom.roborazzi.captureRoboImage
import io.github.packetscope.core.dissector.Pipeline
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.LinkType
import io.github.packetscope.core.pcap.PcapReader
import io.github.packetscope.core.L7Fixtures
import io.github.packetscope.core.PcapTestFixtures
import io.github.packetscope.ui.screen.ConversationsScreen
import io.github.packetscope.ui.screen.FollowStreamScreen
import io.github.packetscope.ui.screen.FrameDetailScreen
import io.github.packetscope.ui.screen.FrameListScreen
import io.github.packetscope.ui.screen.OpenFileScreen
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.ByteArrayInputStream

@RunWith(AndroidJUnit4::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = RobolectricDeviceQualifiers.Pixel5)
class ScreenshotTest {

    @get:Rule val composeRule = createComposeRule()

    @Test
    fun appIcon() {
        // 模拟启动器的圆形 mask 显示 adaptive icon
        capture("app_icon") {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center,
            ) {
                Box(
                    modifier = Modifier
                        .size(192.dp)
                        .clip(CircleShape)
                        .background(Color(0xFF6750A4)),
                    contentAlignment = Alignment.Center,
                ) {
                    androidx.compose.foundation.Image(
                        painter = painterResource(R.drawable.ic_launcher_foreground),
                        contentDescription = null,
                        modifier = Modifier.size(192.dp),
                    )
                }
            }
        }
    }

    @Test
    fun openFileScreen_default() {
        capture("open_file_default") {
            OpenFileScreen(callbacks = io.github.packetscope.ui.screen.OpenFileCallbacks(onPickFile = {}))
        }
    }

    @Test
    fun openFileScreen_loading() {
        capture("open_file_loading") {
            OpenFileScreen(
                callbacks = io.github.packetscope.ui.screen.OpenFileCallbacks(onPickFile = {}),
                loading = true,
            )
        }
    }

    @Test
    fun openFileScreen_error() {
        capture("open_file_error") {
            OpenFileScreen(
                callbacks = io.github.packetscope.ui.screen.OpenFileCallbacks(onPickFile = {}),
                error = "解析失败: Not a PCAP file (magic=0x12345678)",
            )
        }
    }

    @Test
    fun aboutScreen_default() {
        capture("about_screen") {
            io.github.packetscope.ui.screen.AboutScreen(onBack = {})
        }
    }

    @Test
    fun frameListScreen_streaming_waiting() {
        // 模拟刚启动 listener 还没收到 datagram 的状态
        capture("frame_list_streaming_waiting") {
            FrameListScreen(
                sourceName = "实时 :1234  (等待 PCAPdroid 第一个数据包)",
                linkType = LinkType.UNKNOWN,
                frames = emptyList(),
                onSelect = {},
                onClose = {},
            )
        }
    }

    @Test
    fun frameListScreen_streaming_with_frames() {
        capture("frame_list_streaming_with_frames") {
            FrameListScreen(
                sourceName = "实时 :1234",
                linkType = LinkType.ETHERNET,
                frames = loadDiverseFrames(),
                onSelect = {},
                onClose = {},
            )
        }
    }

    @Test
    fun frameListScreen_sample() {
        capture("frame_list") {
            FrameListScreen(
                sourceName = "sample.pcap",
                linkType = LinkType.ETHERNET,
                frames = loadDiverseFrames(),
                onSelect = {},
                onClose = {},
            )
        }
    }

    @Test
    fun frameListScreen_filtered_udp() {
        capture("frame_list_filtered_udp") {
            FrameListScreen(
                sourceName = "sample.pcap",
                linkType = LinkType.ETHERNET,
                frames = loadDiverseFrames(),
                onSelect = {},
                onClose = {},
                initialFilter = "udp",
            )
        }
    }

    @Test
    fun conversationsScreen_sample() {
        capture("conversations") {
            ConversationsScreen(
                frames = framesWithAppLabels(),
                onBack = {},
            )
        }
    }

    @Test
    fun followStreamScreen_http_exchange() {
        capture("follow_stream") {
            val frames = httpExchangeFrames()
            FollowStreamScreen(
                allFrames = frames,
                anchor = frames.first(),
                onBack = {},
            )
        }
    }

    @Test
    fun frameListScreen_pcapdroid_apps() {
        capture("frame_list_pcapdroid_apps") {
            FrameListScreen(
                sourceName = "pcapdroid.pcap",
                linkType = LinkType.ETHERNET,
                frames = framesWithAppLabels(),
                onSelect = {},
                onClose = {},
            )
        }
    }

    @Test
    fun frameListScreen_filter_error() {
        capture("frame_list_filter_error") {
            FrameListScreen(
                sourceName = "sample.pcap",
                linkType = LinkType.ETHERNET,
                frames = loadDiverseFrames(),
                onSelect = {},
                onClose = {},
                initialFilter = "garbage",
            )
        }
    }

    @Test
    fun frameDetailScreen_tcpSyn() {
        // 仍用纯 SYN 帧做详情屏，保持与之前 baseline 接近
        val pcap = PcapTestFixtures.build(linkType = 1,
            packets = listOf(PcapTestFixtures.ethernetIpv4TcpSyn()))
        val frame = PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).first()
        }
        capture("frame_detail_tcp_syn") {
            FrameDetailScreen(frame = frame, onBack = {})
        }
    }

    private fun capture(name: String, content: @Composable () -> Unit) {
        composeRule.setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    content()
                }
            }
        }
        // filePath 相对 test cwd (= app/)，落到 app/snapshots/ 跟入库 baseline
        // 同位置；CI fresh clone 时 verify 直接读这里。Roborazzi DSL outputDir
        // 只影响 implicit-name 模式，显式 filePath 必须自己指对位置
        composeRule
            .onRoot()
            .captureRoboImage(filePath = "snapshots/$name.png")
    }

    /** 构造一段双向 HTTP 交互，用于 Follow Stream 截图 */
    private fun httpExchangeFrames(): List<Frame> {
        val req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
        val resp = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!".toByteArray()
        val clientIp = byteArrayOf(10, 0, 0, 1)
        val serverIp = byteArrayOf(8, 8, 8, 8)
        val pcap = PcapTestFixtures.build(linkType = 1, packets = listOf(
            PcapTestFixtures.ethIpv4Tcp(51234, 80, req,
                seq = 1, ack = 1, flags = 0x18,
                srcIp = clientIp, dstIp = serverIp),
            PcapTestFixtures.ethIpv4Tcp(80, 51234, resp,
                seq = 1, ack = 30, flags = 0x18,
                srcIp = serverIp, dstIp = clientIp),
        ))
        return PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).toList()
        }
    }

    /** PCAPdroid 抓包视角：每个包带 trailer 标注 app 来源，加一个未标注的包演示兼容 */
    private fun framesWithAppLabels(): List<Frame> {
        val chromeTrailer = PcapTestFixtures.pcapdroidTrailer(10001, "com.android.chrome")
        val waTrailer = PcapTestFixtures.pcapdroidTrailer(10002, "com.whatsapp")
        val pcap = PcapTestFixtures.build(linkType = 1, packets = listOf(
            PcapTestFixtures.ethernetIpv4TcpSyn() + chromeTrailer,
            PcapTestFixtures.ethIpv4Udp(51234, 53, L7Fixtures.dnsQueryExampleCom()) + waTrailer,
            PcapTestFixtures.ethIpv4Tcp(51234, 443, L7Fixtures.tlsClientHelloWithSni()) + chromeTrailer,
            PcapTestFixtures.ethernetIpv4TcpSyn(),  // 这一帧无 trailer，演示兼容
        ))
        return PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).toList()
        }
    }

    /** 多协议混合样例：1 SYN + 1 DNS + 1 HTTP + 1 TLS */
    private fun loadDiverseFrames(): List<Frame> {
        val pcap = PcapTestFixtures.build(linkType = 1, packets = listOf(
            PcapTestFixtures.ethernetIpv4TcpSyn(),
            PcapTestFixtures.ethIpv4Udp(51234, 53, L7Fixtures.dnsQueryExampleCom()),
            PcapTestFixtures.ethIpv4Tcp(51234, 80, L7Fixtures.httpGetRequest()),
            PcapTestFixtures.ethIpv4Tcp(51234, 443, L7Fixtures.tlsClientHelloWithSni()),
        ))
        return PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).toList()
        }
    }
}
