package io.github.packetscope.ui.screen

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.packetscope.BuildConfig
import io.github.packetscope.R

private const val GITHUB_ISSUES_URL = "https://github.com/Seryta/PacketScope/issues"

/** OpenFileScreen 接受的 callback 集合。collapse 进单一 data class 避免
 *  Composable signature 参数过多撞 detekt LongParameterList 阈值（8） */
data class OpenFileCallbacks(
    val onPickFile: () -> Unit,
    val onListen: (Int) -> Unit = {},
    val onPickKeyLog: () -> Unit = {},
    val onClearKeyLog: (() -> Unit)? = null,
    val onShowAbout: () -> Unit = {},
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OpenFileScreen(
    callbacks: OpenFileCallbacks,
    keyLogStatus: String? = null,
    loading: Boolean = false,
    error: String? = null,
) {
    var showPortDialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(stringResource(R.string.app_name))
                        Text(
                            text = "v${BuildConfig.VERSION_NAME}",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFF666666),
                        )
                    }
                },
                actions = { OpenFileOverflowMenu(onShowAbout = callbacks.onShowAbout) },
            )
        },
    ) { innerPadding ->
        OpenFileBody(
            innerPadding = innerPadding,
            callbacks = callbacks,
            keyLogStatus = keyLogStatus,
            loading = loading,
            error = error,
            onPortClick = { showPortDialog = true },
        )
    }

    if (showPortDialog) {
        PortInputDialog(
            onConfirm = { port ->
                showPortDialog = false
                callbacks.onListen(port)
            },
            onCancel = { showPortDialog = false },
        )
    }
}

/** TopAppBar 右侧 overflow menu：「关于」 / 「反馈问题」 */
@Composable
private fun OpenFileOverflowMenu(onShowAbout: () -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    val context = LocalContext.current
    IconButton(onClick = { expanded = true }) {
        Icon(
            imageVector = Icons.Filled.MoreVert,
            contentDescription = stringResource(R.string.action_more_options),
        )
    }
    DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
        DropdownMenuItem(
            text = { Text(stringResource(R.string.action_about)) },
            onClick = {
                expanded = false
                onShowAbout()
            },
        )
        DropdownMenuItem(
            text = { Text(stringResource(R.string.action_feedback)) },
            onClick = {
                expanded = false
                openExternalUrl(context, GITHUB_ISSUES_URL)
            },
        )
    }
}

/** 共用：用浏览器打开外部 URL，无浏览器时 Toast 提示。 */
internal fun openExternalUrl(context: android.content.Context, url: String) {
    try {
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
    } catch (_: ActivityNotFoundException) {
        Toast.makeText(
            context, context.getString(R.string.error_no_browser), Toast.LENGTH_SHORT,
        ).show()
    }
}

@Composable
private fun OpenFileBody(
    innerPadding: PaddingValues,
    callbacks: OpenFileCallbacks,
    keyLogStatus: String?,
    loading: Boolean,
    error: String?,
    onPortClick: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(innerPadding)
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        // TopAppBar 已显示 app_name + 版本号，body 内不重复 title。仅保留
        // tagline 给中性视觉锚
        Text(
            text = stringResource(R.string.app_subtitle),
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(bottom = 32.dp),
        )

        if (loading) {
            CircularProgressIndicator(modifier = Modifier.size(48.dp))
            Text(text = stringResource(R.string.status_parsing),
                modifier = Modifier.padding(top = 16.dp))
        } else {
            Button(
                onClick = callbacks.onPickFile,
                contentPadding = PaddingValues(horizontal = 24.dp, vertical = 12.dp),
            ) {
                Text(stringResource(R.string.action_open_pcap))
            }
            Spacer(modifier = Modifier.height(12.dp))
            OutlinedButton(
                onClick = onPortClick,
                contentPadding = PaddingValues(horizontal = 24.dp, vertical = 12.dp),
            ) {
                Text(stringResource(R.string.action_listen_pcapdroid))
            }
            Spacer(modifier = Modifier.height(12.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = callbacks.onPickKeyLog) {
                    Text(keyLogStatus ?: stringResource(R.string.action_load_keylog))
                }
                // keyLog 已加载时显示「清除」入口；公共设备上避免 session keys
                // 一直留在内存（review v0.6-round1 F-014）
                val clear = callbacks.onClearKeyLog
                if (keyLogStatus != null && clear != null) {
                    TextButton(onClick = clear) {
                        Text(stringResource(R.string.action_clear))
                    }
                }
            }

            if (error != null) {
                Text(
                    text = error,
                    color = Color(0xFFB00020),
                    modifier = Modifier.padding(top = 24.dp),
                    style = MaterialTheme.typography.bodySmall,
                )
            } else {
                Text(
                    text = stringResource(R.string.hint_share_pcap),
                    style = MaterialTheme.typography.bodySmall,
                    color = Color(0xFF666666),
                    modifier = Modifier.padding(top = 32.dp, start = 16.dp, end = 16.dp),
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}

@Composable
private fun PortInputDialog(
    initial: Int = 1234,
    onConfirm: (Int) -> Unit,
    onCancel: () -> Unit,
) {
    var text by remember { mutableStateOf(initial.toString()) }
    val port = text.toIntOrNull()
    val valid = port != null && port in 1..65535

    AlertDialog(
        onDismissRequest = onCancel,
        confirmButton = {
            TextButton(
                enabled = valid,
                onClick = { onConfirm(port!!) },
            ) {
                Text(stringResource(R.string.action_start_listen))
            }
        },
        dismissButton = {
            TextButton(onClick = onCancel) {
                Text(stringResource(R.string.action_cancel))
            }
        },
        title = { Text(stringResource(R.string.dialog_listen_title)) },
        text = {
            Column {
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it.filter { c -> c.isDigit() }.take(5) },
                    label = { Text(stringResource(R.string.dialog_listen_port_label)) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    isError = !valid,
                    singleLine = true,
                )
                Text(
                    text = stringResource(
                        R.string.dialog_listen_hint,
                        if (valid) text else "?",
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = Color(0xFF666666),
                    modifier = Modifier.padding(top = 12.dp),
                )
            }
        },
    )
}
