# PacketScope ProGuard / R8 keep rules.
# AGP default 含 proguard-android-optimize.txt + Compose / Kotlin / AndroidX
# 各 library 自带 consumer-proguard 文件已经覆盖绝大多数 case。本文件只补
# 项目特有需要保留的反射 / 日志可读性 keep rules。

# ─── Kotlinx coroutines ─────────────────────────────────────────
# coroutines 内部 ServiceLoader 加载 MainDispatcherFactory + 异常处理器，
# R8 默认不识别该模式，需要 keepnames 让全限定名留住
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}

# ─── PacketScope core enums / sealed classes ────────────────────
# 数据类大量用 data class + by remember；反射不重要，但保留 enum / sealed
# class 简单名让运行时日志 / crash 报告可读（混淆后 a/b/c 没法定位问题）
-keepnames enum io.github.packetscope.** { *; }
-keep class io.github.packetscope.core.pcap.LinkType { *; }

# ─── Compose 不需要额外规则 ──────────────────────────────────────
# androidx.compose.* 各 artifact 自带 consumer-proguard-rules.pro，AGP 会
# 自动 merge 进 release build。这里**不要**再加 -keep class androidx.compose.**，
# 会让 R8 失去优化空间（增加 APK 体积）。
