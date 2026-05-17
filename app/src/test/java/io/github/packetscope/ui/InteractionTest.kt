package io.github.packetscope.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.github.takahirom.roborazzi.RobolectricDeviceQualifiers
import io.github.packetscope.R
import io.github.packetscope.core.PcapTestFixtures
import io.github.packetscope.core.dissector.Pipeline
import io.github.packetscope.core.pcap.Frame
import io.github.packetscope.core.pcap.LinkType
import io.github.packetscope.core.pcap.PcapReader
import io.github.packetscope.ui.screen.FrameDetailScreen
import io.github.packetscope.ui.screen.FrameListScreen
import io.github.packetscope.ui.screen.OpenFileScreen
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.ByteArrayInputStream

@RunWith(AndroidJUnit4::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = RobolectricDeviceQualifiers.Pixel5)
class InteractionTest {

    @get:Rule val composeRule = createComposeRule()

    @Test
    fun `点击打开按钮触发 onPickFile`() {
        var clicked = false
        composeRule.setContent {
            MaterialTheme {
                OpenFileScreen(
                    callbacks = io.github.packetscope.ui.screen.OpenFileCallbacks(
                        onPickFile = { clicked = true },
                    ),
                )
            }
        }
        // 取当前 locale 下解析后的按钮文本，i18n 之后默认 locale 是 en_US（Robolectric）
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        composeRule.onNodeWithText(context.getString(R.string.action_open_pcap)).performClick()
        assertTrue(clicked)
    }

    @Test
    fun `点击包列表行返回对应 frame`() {
        val frames = sampleFrames()
        var selected: Frame? = null
        composeRule.setContent {
            MaterialTheme {
                FrameListScreen(
                    sourceName = "sample.pcap",
                    linkType = LinkType.ETHERNET,
                    frames = frames,
                    onSelect = { selected = it },
                    onClose = {},
                )
            }
        }
        // 点击第 2 行的 # 单元格（值为 "2"）
        composeRule.onNodeWithText("2").performClick()
        assertEquals(2, selected?.index)
    }

    @Test
    fun `OpenFileScreen overflow 进 About 再 back 不崩`() {
        composeRule.setContent {
            val showAbout = androidx.compose.runtime.remember {
                androidx.compose.runtime.mutableStateOf(false)
            }
            MaterialTheme {
                val callbacks = io.github.packetscope.ui.screen.OpenFileCallbacks(
                    onPickFile = {},
                    onShowAbout = { showAbout.value = true },
                )
                if (!showAbout.value) {
                    OpenFileScreen(callbacks = callbacks)
                } else {
                    io.github.packetscope.ui.screen.AboutScreen(
                        onBack = { showAbout.value = false },
                    )
                }
            }
        }
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        // 点 overflow 三点 icon —— contentDescription 指 action_more_options
        composeRule.onNodeWithContentDescription(
            context.getString(R.string.action_more_options),
        ).performClick()
        // dropdown 弹出后点「关于」
        composeRule.onNodeWithText(context.getString(R.string.action_about)).performClick()
        // AboutScreen TopBar 显示标题
        composeRule.onNodeWithText(context.getString(R.string.about_title)).assertIsDisplayed()
        // 点 navigationIcon Back —— action_back
        composeRule.onNodeWithText(context.getString(R.string.action_back)).performClick()
        // 回到 OpenFileScreen → app_name 仍可见（TopAppBar 内）
        composeRule.onNodeWithText(context.getString(R.string.app_name)).assertIsDisplayed()
    }

    @Test
    fun `详情屏 Ethernet 头部字段点击展开后可见`() {
        val frame = sampleFrames().first()
        composeRule.setContent {
            MaterialTheme {
                FrameDetailScreen(frame = frame, onBack = {})
            }
        }
        // 协议树最顶部是 Ethernet，必然在视口内
        composeRule.onNodeWithText("Ethernet").assertIsDisplayed()
        // 详情页改成"默认全收缩"后（UX 反馈），需要点击 Ethernet 行先展开
        composeRule.onNodeWithText("Ethernet").performClick()
        // Ethernet 展开后的字段
        composeRule.onNodeWithText("Source MAC: bb:bb:bb:bb:bb:bb").assertIsDisplayed()
    }

    private fun sampleFrames(): List<Frame> {
        val pcap = PcapTestFixtures.build(
            linkType = 1,
            packets = listOf(
                PcapTestFixtures.ethernetIpv4TcpSyn(),
                PcapTestFixtures.ethernetIpv4TcpSyn(),
                PcapTestFixtures.ethernetIpv4TcpSyn(),
            ),
        )
        return PcapReader(ByteArrayInputStream(pcap)).use { reader ->
            val pipeline = Pipeline(reader.linkType)
            reader.frames().map(pipeline::process).toList()
        }
    }
}
