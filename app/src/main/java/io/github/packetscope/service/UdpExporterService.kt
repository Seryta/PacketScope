package io.github.packetscope.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import io.github.packetscope.R
import io.github.packetscope.core.stream.StreamEvent
import io.github.packetscope.core.stream.StreamingSession
import io.github.packetscope.core.stream.UdpExporterListener
import io.github.packetscope.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach

/**
 * ForegroundService 长时间持有 UDP socket 接收 PCAPdroid Exporter 数据。
 *
 * 状态流向：Listener Flow → 写入 [StreamingSession] → UI 读取并渲染。
 * Service 自己不暴露任何 binder，UI 通过 [StreamingSession] 解耦。
 */
class UdpExporterService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var listenerJob: Job? = null
    private var currentPort: Int = 0

    private val stopReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            stopSelf()
        }
    }

    override fun onCreate() {
        super.onCreate()
        ContextCompat.registerReceiver(
            this,
            stopReceiver,
            IntentFilter(ACTION_STOP),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val port = intent?.getIntExtra(EXTRA_PORT, 0) ?: 0
        if (port <= 0) {
            stopSelf()
            return START_NOT_STICKY
        }
        currentPort = port

        startInForeground(buildNotification(port, 0))

        // 重新启动场景：先 cancel 旧 listener（与之 awaitClose 同步关掉 socket），
        // 再起新 listener。避免同一进程内两个 socket 并存
        listenerJob?.cancel()
        listenerJob = null

        StreamingSession.reset()
        StreamingSession.port.intValue = port
        StreamingSession.isRunning.value = true
        StreamingSession.status.value = getString(R.string.status_waiting_first_datagram)

        listenerJob = UdpExporterListener.events(port)
            .onEach { event ->
                when (event) {
                    StreamEvent.Listening -> { /* status 已在 onStartCommand 设过 */ }
                    is StreamEvent.Capturing -> {
                        StreamingSession.linkType.value = event.linkType
                        StreamingSession.status.value = null
                    }
                    is StreamEvent.FrameReceived -> {
                        StreamingSession.frames.add(event.frame)
                        // 限频刷通知：每 32 帧或首帧
                        val n = StreamingSession.frames.size
                        if (n == 1 || n % 32 == 0) updateNotification(n)
                    }
                    is StreamEvent.Error -> StreamingSession.status.value = event.message
                }
            }
            .launchIn(scope)

        return START_NOT_STICKY
    }

    override fun onDestroy() {
        listenerJob?.cancel()
        scope.cancel()
        runCatching { unregisterReceiver(stopReceiver) }
        StreamingSession.isRunning.value = false
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // ─── Notification helpers ─────────────────────────────────────────

    private fun startInForeground(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification(count: Int) {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        nm.notify(NOTIFICATION_ID, buildNotification(currentPort, count))
    }

    private fun buildNotification(port: Int, count: Int): Notification {
        ensureChannel()

        val openIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getBroadcast(
            this, 0,
            Intent(ACTION_STOP).setPackage(packageName),
            PendingIntent.FLAG_IMMUTABLE,
        )

        // plurals 包成第 2 个参数传进 notif_text，避免 "1 packets received" 单复数问题
        val packetsText = resources.getQuantityString(
            R.plurals.count_packets_received, count, count)
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_notification)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(getString(R.string.notif_text, port, packetsText))
            .setContentIntent(openIntent)
            .addAction(0, getString(R.string.notif_action_stop), stopIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .build()
    }

    private fun ensureChannel() {
        // minSdk = 26 (O)，无需 SDK_INT 检查 —— review v0.6-round4 F-002 删 dead branch
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val name = getString(R.string.notif_channel_name)
        val desc = getString(R.string.notif_channel_desc)
        val existing = nm.getNotificationChannel(CHANNEL_ID)
        if (existing != null && existing.name == name && existing.description == desc) return
        // 已存在但 locale 切换后 name/desc 不一致 —— 重新 create（同 id 是 update
        // 等价操作，importance 不会被降低）。review v0.6-round2 F-010。
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID, name,
                existing?.importance ?: NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = desc
                setShowBadge(false)
            }
        )
    }

    companion object {
        const val EXTRA_PORT = "port"
        const val ACTION_STOP = "io.github.packetscope.action.STOP_LISTENING"
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "packetscope.listener"

        fun start(context: Context, port: Int) {
            val intent = Intent(context, UdpExporterService::class.java)
                .putExtra(EXTRA_PORT, port)
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, UdpExporterService::class.java))
        }
    }
}
