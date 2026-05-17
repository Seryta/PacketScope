package io.github.packetscope.ui.screen

import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.github.packetscope.BuildConfig
import io.github.packetscope.R

private const val GITHUB_REPO_URL = "https://github.com/Seryta/PacketScope"
private const val LICENSE_URL = "$GITHUB_REPO_URL/blob/master/LICENSE"
private const val THIRD_PARTY_URL = "$GITHUB_REPO_URL/blob/master/THIRD_PARTY_LICENSES.md"
private const val PRIVACY_URL = "$GITHUB_REPO_URL/blob/master/PRIVACY.md"
private const val PCAPDROID_URL = "https://github.com/emanuele-f/PCAPdroid"
private const val RELEASES_LATEST_URL = "$GITHUB_REPO_URL/releases/latest"
private const val ISSUES_URL = "$GITHUB_REPO_URL/issues"

/**
 * 「关于」屏幕：app info / source / related / actions 四段。
 *
 * 入口在 OpenFileScreen overflow → "About"（round1 UI-003 接的 navigation）。
 *
 * "检查更新" 按钮（UI-002）：浏览器跳转 GitHub Releases latest，零网络 / API /
 * 维护。"反馈问题" 跳转 GitHub Issues。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AboutScreen(onBack: () -> Unit) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.about_title)) },
                navigationIcon = {
                    TextButton(onClick = onBack) {
                        Text(stringResource(R.string.action_back))
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            item { AppInfoSection() }
            item { HorizontalDivider() }
            item { SectionHeader(stringResource(R.string.about_section_source)) }
            items(SOURCE_LINKS) { link -> LinkRow(link) }
            item { HorizontalDivider() }
            item { SectionHeader(stringResource(R.string.about_section_related)) }
            item { RelatedProjectRow() }
            item { HorizontalDivider() }
            item { SectionHeader(stringResource(R.string.about_section_actions)) }
            item { ActionsSection() }
        }
    }
}

@Composable
private fun AppInfoSection() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 24.dp, vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Image(
            painter = painterResource(R.drawable.ic_launcher_foreground),
            contentDescription = null,
            modifier = Modifier.size(96.dp),
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.app_name),
            style = MaterialTheme.typography.headlineMedium,
        )
        Text(
            text = stringResource(R.string.app_subtitle),
            style = MaterialTheme.typography.bodyMedium,
            color = Color(0xFF666666),
            modifier = Modifier.padding(top = 4.dp),
            textAlign = TextAlign.Center,
        )
        Text(
            text = stringResource(
                R.string.about_version_label,
                BuildConfig.VERSION_NAME, BuildConfig.VERSION_CODE,
            ),
            style = MaterialTheme.typography.bodySmall,
            color = Color(0xFF888888),
            modifier = Modifier.padding(top = 8.dp),
        )
    }
}

private data class AboutLink(val labelRes: Int, val url: String)

private val SOURCE_LINKS: List<AboutLink> = listOf(
    AboutLink(R.string.about_link_source, GITHUB_REPO_URL),
    AboutLink(R.string.about_link_license, LICENSE_URL),
    AboutLink(R.string.about_link_third_party, THIRD_PARTY_URL),
    AboutLink(R.string.about_link_privacy, PRIVACY_URL),
)

@Composable
private fun SectionHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        color = Color(0xFF1565C0),
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
    )
}

@Composable
private fun LinkRow(link: AboutLink) {
    val context = LocalContext.current
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { openExternalUrl(context, link.url) }
            .padding(horizontal = 16.dp, vertical = 14.dp),
    ) {
        Text(stringResource(link.labelRes), style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun RelatedProjectRow() {
    val context = LocalContext.current
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { openExternalUrl(context, PCAPDROID_URL) }
            .padding(horizontal = 16.dp, vertical = 14.dp),
    ) {
        Text(
            text = stringResource(R.string.about_link_pcapdroid_title),
            style = MaterialTheme.typography.bodyLarge,
            color = Color(0xFF1565C0),
        )
        Text(
            text = stringResource(R.string.about_link_pcapdroid_desc),
            style = MaterialTheme.typography.bodySmall,
            color = Color(0xFF666666),
            modifier = Modifier.padding(top = 4.dp),
        )
    }
}

@Composable
private fun ActionsSection() {
    val context = LocalContext.current
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Button(
            onClick = { openExternalUrl(context, RELEASES_LATEST_URL) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.about_action_check_updates))
        }
        OutlinedButton(
            onClick = { openExternalUrl(context, ISSUES_URL) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.about_action_feedback))
        }
        Text(
            text = stringResource(
                R.string.about_version_label,
                BuildConfig.VERSION_NAME, BuildConfig.VERSION_CODE,
            ),
            style = MaterialTheme.typography.bodySmall,
            color = Color(0xFF888888),
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 12.dp),
            textAlign = TextAlign.Center,
        )
    }
}
