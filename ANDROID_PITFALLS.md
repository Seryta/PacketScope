# Android 平台陷阱清单

从 review v0.6 三轮迭代里积累的"被 Android specifics 坑过"清单。新人 / 新 agent
入职先扫一遍，跟 [`ARCHITECTURE.md`](ARCHITECTURE.md) 并读。

每条都给：**症状**、**根因**、**正确姿势**、**关联 review finding**。

---

## strings.xml 资源 / i18n

### P-1 字符串前后导空白被 strip

**症状**：资源里写 `"  ⚠ truncated"`，运行时拼接结果 `"…1500B⚠ truncated"`
没有间距。

**根因**：Android 资源 XML 加载器默认 strip 字符串首尾空白
（[官方文档](https://developer.android.com/guide/topics/resources/string-resource#FormattingAndStyling)）。

**正确姿势**：
- 资源里**不放**首尾空白
- 间距在调用点拼接（`"  " + stringResource(R.string.x)`）或用 `Spacer(width=Xdp)`
- 要保留空白时用双引号包整段：`<string name="x">"  trim-resistant"</string>`（不推荐，
  新增字符串容易疏忽）

**关联**：v0.6-round2 F-001

---

### P-2 plurals 必须用 `<plurals>` 而非 "%d items"

**症状**：英文 locale 看到 "1 packets" / "1 bytes" / "1 sessions"。

**根因**：硬拼 `"%d packets"` 永远是复数形式；英文需要单复数区分。

**正确姿势**：
```xml
<plurals name="count_packets">
    <item quantity="one">%d packet</item>
    <item quantity="other">%d packets</item>
</plurals>
```

Compose 调用 `pluralStringResource(R.plurals.count_packets, n, n)`；
非 Composable（Service）用 `resources.getQuantityString(...)`。

中文只需 `quantity="other"`，俄语 / 阿拉伯语等还需 `few` / `many` / `zero`。

**关联**：v0.6-round3 F-001

---

### P-3 NotificationChannel 一旦创建 name 被系统缓存，locale 切换不更新

**症状**：用户切语言后，系统设置 → 应用 → 通知里的 channel 名仍是首次创建时的语言。

**根因**：`NotificationManager.createNotificationChannel(channel)` 对**已存在的 id**
是 update 而非 no-op，但是只有当 `name` / `description` 不同时才真的更新。

**正确姿势**：`ensureChannel()` 每次都检查 existing 的 name/desc 跟当前 locale
资源是否一致，不一致就重 create（同 id 是 update 等价，importance 复用 existing
不降级）。

```kotlin
val existing = nm.getNotificationChannel(CHANNEL_ID)
if (existing != null && existing.name == name && existing.description == desc) return
nm.createNotificationChannel(NotificationChannel(CHANNEL_ID, name, existing?.importance
    ?: IMPORTANCE_LOW).apply { description = desc; ... })
```

**关联**：v0.6-round2 F-010

---

## 资源 / API

### P-4 `compileSdk` 与测试 `@Config(sdk=[X])` 必须对齐

**症状**：升 compileSdk 后测试基线截图没真覆盖新 SDK 的 system insets / behaviour。

**根因**：Robolectric 用 `@Config(sdk=...)` 选实际仿真的 SDK，跟 gradle
`compileSdk` 独立。

**正确姿势**：测试 `@Config(sdk = [35])` 跟 `compileSdk = 35` 同步改。
Robolectric 版本要 cover 目标 SDK（4.13 不识别 SDK 35，升 4.14.1+）。

**关联**：v0.6-round2 F-003

---

### P-5 AGP 8+ 默认不生成 `BuildConfig`

**症状**：代码引用 `BuildConfig.DEBUG` 编译报 `Unresolved reference 'BuildConfig'`。

**根因**：AGP 8 起 `buildFeatures.buildConfig` 默认 false。

**正确姿势**：
```kotlin
android {
    buildFeatures {
        compose = true
        buildConfig = true  // 需要 BuildConfig.DEBUG 等才开
    }
}
```

**关联**：v0.6-round1 F-009

---

### P-6 lint 资源 + `dataExtractionRules` / `fullBackupContent` 双轨

**症状**：写了 `<exclude domain="file" path="cache/" />` 没起作用。

**根因**：
- Android 12+（API 31+）走 `android:dataExtractionRules` 引用的 xml
- Android 11 及以下走 `android:fullBackupContent` 引用的 xml
- domain 有 `root` / `file` / `external` / `database` / `sharedpref` 等，
  各对应不同目录；`file` 不是 cache 目录
- Android 默认**已经**排除 `cache/`（内 + 外）—— 写 phantom 规则没意义

**正确姿势**：
- minSdk 26 → 两份 xml 都写（系统按 SDK 选用）
- 显式排除**未来要落盘的具体路径**：`frame_cache/` / `pcap_index.db`
- 不重复 Android 默认已排除的项

**关联**：v0.6-round2 F-009 + round3 F-005

---

## 测试 / Roborazzi

### P-7 ScreenshotTest 硬编码字符串断言 → i18n 后失败

**症状**：`composeRule.onNodeWithText("打开 PCAP 文件")` 在英语 locale 下找不到节点。

**正确姿势**：
```kotlin
val context: Context = ApplicationProvider.getApplicationContext()
composeRule.onNodeWithText(context.getString(R.string.action_open_pcap)).performClick()
```

测试硬编码字面量是脆性测试，i18n 后 locale 切换就破。

**关联**：v0.6 i18n round + round2 F-003 测试调整

---

### P-8 Roborazzi 截图基线随 UI 文本 / SDK 升级失效

**症状**：UI 改了 plurals / SDK 升 → verify 失败。

**正确姿势**：UI 文本 / API / SDK 变动后**主动**重录：

```bash
./gradlew recordRoborazziDebug && ./gradlew verifyRoborazziDebug
```

record 是 destructive 操作（覆盖基线），改完代码自己确认像素差异符合预期再 commit。
基线 png 放 `app/build/outputs/roborazzi/` 在 gitignore 内（不入库），每次新机器都
要 record 一次。

**关联**：v0.6-round1 F-001 / round2 F-001+F-003 / round3 F-001+F-003

---

## Docker 构建

### P-9 容器默认 root 跑 → 宿主 root-owned 产物

**症状**：docker 跑完 `./gradlew clean` 在宿主报 `Permission denied`。

**正确姿势**：所有 docker 命令加 `-u "$(id -u):$(id -g)"`，配合 `GRADLE_USER_HOME`
指到一个用户能写的目录：

```bash
docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$PWD":/work -w /work \
  -v "$HOME/.gradle-docker":/work/.gradle-cache \
  -e GRADLE_USER_HOME=/work/.gradle-cache \
  mingc/android-build-box:latest \
  ./gradlew assembleDebug
```

注意：切到 -u 跑之前要 `sudo chown` 已有缓存（被 root 写过的目录），或者用新
缓存目录。

**关联**：v0.6-round1 F-010 + round2 F-010

---

### P-10 Docker 容器内 dl.google.com TLS handshake 可能失败

**症状**：宿主 `curl dl.google.com` 200，容器里 Gradle 拉 AGP/SDK 时 TLS
"Remote host terminated the handshake"。

**根因**：容器 JVM 默认 TLS cipher suite 跟某些 CDN 节点不兼容（CN 区 DNS
解析到的 IP 多变），或者宿主走透明代理容器没继承。

**临时解法**：
- 用 `--network host` 让容器复用宿主网络栈
- 重试（DNS 重新解析换 CDN 节点）
- 实在不行：临时挂阿里云 maven init 脚本（仅本地 `$HOME/.gradle-docker/init.d/` 不进仓库）

**不该**：把阿里云镜像写进 settings.gradle.kts 上游仓库

**关联**：与 round1 i18n session 网络抖动事件

---

## Manifest / Intent

### P-11 ACTION_SEND vs ACTION_VIEW intent-filter

**症状**：PCAPdroid "分享 pcap" 列表里看不到本应用。

**根因**：PCAPdroid 用 `Intent.ACTION_SEND` + `EXTRA_STREAM` + MIME `application/cap`；
本应用如果只声明 `ACTION_VIEW` 就拿不到分享。

**正确姿势**：分享接收专门加 `ACTION_SEND` intent-filter，MIME 列上下游约定的所有可能值
（`application/cap`、`application/vnd.tcpdump.pcap`...）。

**关联**：v0.6 OOB（PCAPdroid 分享接入）

---

### P-12 通知 smallIcon 必须纯 alpha mask

**症状**：通知栏显示系统默认应用图标，看不到自定义 icon。

**根因**：Android 5.0+ 通知栏 smallIcon 只用 alpha 通道，系统按主题色着色。
有些 ROM（特别是 MIUI / EMUI 系）对 VectorDrawable `strokeWidth` 描边的渲染
不完整，会回退到 system fallback。

**正确姿势**：smallIcon vector 只用 `fillColor="#FFFFFFFF"` 纯填充 path，**不用**
`strokeWidth`。复杂形状用 `fillType="evenOdd"` 内圆挖外圆。

**关联**：v0.6 OOB（通知图标 round1）

---

## 权限

### P-13 INTERNET 即使只本地 socket bind 也要

**症状**：`DatagramSocket(port)` 抛 SecurityException。

**根因**：Android 把所有 socket 操作（包括 bind 本机端口）归在 INTERNET 下。

**正确姿势**：manifest 声明 `<uses-permission android:name="android.permission.INTERNET" />`。

---

### P-14 ForegroundService Android 14+ 需要 type-specific 权限

**症状**：API 34+ 上 `startForeground()` 被系统拒绝。

**正确姿势**：根据 service `foregroundServiceType` 加对应 type-permission：

- `dataSync` → `FOREGROUND_SERVICE_DATA_SYNC`
- `mediaPlayback` → `FOREGROUND_SERVICE_MEDIA_PLAYBACK`
- 其它见 [Android docs](https://developer.android.com/about/versions/14/changes/fgs-types-required)

---

## 数据类 / Kotlin

### P-15 `data class` 包含 `ByteArray` 时 equals 反直觉

**症状**：放进 HashMap / HashSet / Compose state 时性能差或行为不对。

**根因**：data class 默认 equals 走逐字段比较，ByteArray equals 是逐字节，
百 KB payload 进 hash 巨慢。

**正确姿势**（两种）：
- 没有 `copy()` 调用：去 `data` 修饰改普通 class（默认 equals 是身份比较）
- 有 `copy()` 调用：保留 data class 但手写 `equals/hashCode` 走身份 / 按 id 比较，
  **加 KDoc 注释明确说明原因**避免下个 reviewer 删

**关联**：v0.6-round1 F-007

---

## Compose 状态

### P-16 SnapshotStateList self-equals identity 短路

**症状**：`remember(filter, frames) { frames.filter(...) }` 在 `frames` 内容
变化时不重算。

**根因**：SnapshotStateList 的 `equals` 走结构比较，但 `self.equals(self)` 走
identity 短路恒为 true —— remember key 看到的是"还是同一个 list"。

**正确姿势**：用 `frames.size` 或 snapshot id 作为 key：
```kotlin
val filtered = remember(filter, frames.size, sortColumn, sortDesc) {
    frames.filter(filter::matches)
}
```

**关联**：早期 i18n round（中 frame list 显示空但 size 非零的 bug）

---

## 备份 / 隐私

### P-17 `ByteArray.clear()` 之前要 `fill(0)` 擦敏感数据

**症状**：调 clear() 后 ByteArray 引用被 drop 但 GC 异步回收前内容残留堆。
取证 / dump 堆能拿到 TLS session keys 等。

**正确姿势**：
```kotlin
fun clear() {
    for (secret in keys.values) secret.fill(0)
    keys.clear()
}
```

`load()` 替换路径**同样**要先 clear 旧数据再装新数据，不要内联 `byRandom.clear()`。

**关联**：v0.6-round2 F-008 + round3 F-002

---

## 静态分析 / 工具

### P-18 Android lint baseline 第一次跑会 "fail" 是正常行为

**症状**：`./gradlew lintDebug` 报 `Aborting build since new baseline file was created`。

**正确姿势**：第一次跑生成 `app/lint-baseline.xml`，之后跑就是 baseline mode。
入库 baseline 文件，CI 跑 lint 时新增问题才会 fail。

---

### P-19 detekt baseline 用 `detektBaseline` task 生成

**症状**：直接跑 `detekt` 失败一堆 issue。

**正确姿势**：先跑 `./gradlew detektBaseline` 把现有 issue 入库，之后 `detekt`
只 fail 新增问题。

---

## 速查表

| 你要做 | 想这些 |
|---|---|
| 加新 user-facing 字符串 | plurals?（任何含 %d）/ strings.xml 不带前后空白 / values + values-zh 同步 |
| 改 ContentResolver / 落盘 | dataExtractionRules + backup_rules 加 exclude |
| 加 ForegroundService | foregroundServiceType + 对应 type-permission |
| 加 Service 通知 | smallIcon 纯 fillColor / channel name locale 更新 |
| 升 compileSdk | 测试 @Config(sdk=...) 同步 + 跑 recordRoborazziDebug |
| 加 BuildConfig.X 引用 | buildFeatures.buildConfig = true |
| 写 ByteArray 字段 + data class | 想 equals 语义；没 copy() 用就去 data |
| 改协议 / 字段名 | 加进 Protocols / FieldNames，dissector + 消费端同步 |
| 抛 user-facing Exception | sealed error，core 不持中文 / 英文 message |
