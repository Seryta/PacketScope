# QA Checklist — Release 前手工验证

跑这份清单一次，每条 ✅ / ❌ + 备注。任何 ❌ 都 block release 直到修复或
在 RELEASE.md 显式 acknowledge。

跨 v0.6 → v0.9 大量改动 + AGP / Compose / Gradle 大版本跳跃 + targetSdk
35→36，只 Roborazzi 模拟器测过；真机 QA 是 release 前最关键一步。

## 环境

- 设备：___（型号 / Android 版本 / 屏幕尺寸）
- 时间：___
- 版本：v___（versionName）build ___（versionCode）

## A. 安装 / 卸载

- [ ] `adb install -r app-release.apk` 成功
- [ ] launcher 图标显示正确（不是默认 Android 机器人）
- [ ] 启动 app 不崩，OpenFileScreen 显示，顶部 TopAppBar 显示 app name
      + 版本号
- [ ] 卸载后重装，previously-loaded keylog 不残留

## B. 从文件打开

- [ ] 「打开 PCAP 文件」按钮 → SAF 文件选择器
- [ ] 选一个 5-50MB PCAP（建议 Wireshark 样例 / PCAPdroid 真实抓包）→
      三联视图
- [ ] 选一个 PCAPng 文件 → 看到「PacketScope 暂不支持 PCAPng」明确错误
- [ ] 选一个 > 500MB 文件 → 看到「文件大小 ... 超过 500 MB」明确错误
- [ ] 选一个非 PCAP 文件（mp4 / pdf）→ 看到「解析失败」错误，不崩

## C. 三联视图交互

- [ ] FrameList 列表能滚到底（10k+ 包）
- [ ] 点列头排序：时间 / 协议 / 长度 / Info 都能切升降序
- [ ] 点 frame 进 FrameDetailScreen，协议树默认全收缩
- [ ] ⊞ / ⊟ 一键展开 / 收缩工作
- [ ] 点字段高亮对应 hex 字节（黄色背景）
- [ ] Payload section 显示，⤢ 全屏按钮可点
- [ ] 长按字段 → 全屏 FieldDetailDialog
- [ ] Dialog 内打开搜索 → 输入关键词 → ↑/↓ 跳转 → 命中行滚到视口

## D. 过滤

- [ ] 顶栏 `?` 按钮打开「过滤语法」帮助 dialog
- [ ] 点协议名 / 完整示例直接填回输入框
- [ ] 点参数 atom (`host <IP>`) 只插前缀，光标停末尾
- [ ] 输入 `tcp and port 80` 过滤数变化
- [ ] 故意输错 `host` → 看到本地化错误提示

## E. Conversations 视图

- [ ] 顶栏「会话」按钮进 ConversationsScreen
- [ ] 卡片按字节降序，显示 TCP / UDP 徽章
- [ ] 点 conversation 卡片进详情屏
- [ ] 详情屏 stats 卡片显示双向 packets / bytes / duration
- [ ] TCP conversation 有「跟随 TCP 流」按钮 → FollowStreamScreen

## F. Follow Stream

- [ ] FollowStreamScreen 显示 N 个 segment 卡片
- [ ] 顶栏搜索按钮打开 SearchHeaderBar
- [ ] 跨段搜索：输入关键词命中多段，↑/↓ 跳到正确段 + 段内行
- [ ] 长按选区跨行 / 跨段复制 OK

## G. TLS 解密

- [ ] OpenFileScreen「加载 SSLKEYLOGFILE」选 keylog 文件
- [ ] 状态行显示「已加载 N 个 session keys」
- [ ] 「清除」按钮工作，状态行消失
- [ ] 打开含 TLS 流量的 PCAP（keylog 匹配的）→ TLS 层下挂解密结果 Field
- [ ] 加载第二份 keylog → 状态行 sessionCount 更新（旧 keys 不残留）

## H. PCAPdroid 实时接入

- [ ] OpenFileScreen「监听 PCAPdroid」→ 端口输入 dialog（默认 1234）
- [ ] 输入合法端口 → 监听 → 顶栏 source 行变「实时 :1234」
- [ ] PCAPdroid 设 UDP Exporter Collector = `127.0.0.1` Port = 1234 → 开抓
- [ ] frames 实时进列表，每 32 帧通知刷新
- [ ] 「清空」按钮只清 frames 不停 listener
- [ ] 按返回 → 「停止监听？」确认 dialog
- [ ] 确认 → 通知消失，回 OpenFileScreen

## I. PCAPdroid 文件互通

- [ ] PCAPdroid 抓包停止 → 长按 PCAP → 分享 → 选 PacketScope
- [ ] PacketScope 自动打开，显示三联视图
- [ ] frame 列表 Info 列显示 `[app名]` 前缀（来自 PCAPdroid trailer）

## J. 关于 / 更新（v1.0 新增）

- [ ] OpenFileScreen 右上 overflow（三点 icon）→ 「关于」
- [ ] AboutScreen 显示 launcher icon / app_name / tagline / 版本号
      (versionName + versionCode)
- [ ] Source 段 4 个 link 全部能跳浏览器：源代码 / 许可证 / 第三方依赖
      / 隐私政策
- [ ] Related projects: PCAPdroid 链接跳转 emanuele-f/PCAPdroid
- [ ] 「检查更新」按钮 → 浏览器打开 GitHub Releases /releases/latest
- [ ] 「反馈问题」按钮 → 浏览器打开 issues 页
- [ ] Overflow 「反馈问题」（OpenFileScreen 直接路径）也工作

## K. i18n

- [ ] 系统切英语 → 重启 app → UI 全英文，无中文残留（TopAppBar / About
      / 错误消息）
- [ ] 系统切简体中文 → 重启 → UI 全中文，无英文残留
- [ ] 系统切其它语言（日文）→ UI fallback 英文

## L. 屏幕旋转 / 后台恢复

- [ ] 各 screen 旋转屏幕，state 不丢
- [ ] 切后台 → 等 30 秒 → 切回，state 保留
- [ ] 实时监听模式切后台 → 通知保持 → 切回 frames 继续

## M. 通知

- [ ] 实时监听模式通知小图标显示正常（不是默认下载图标）
- [ ] 通知 action「停止监听」点击有效
- [ ] 系统设置 → 应用 → 通知 → channel 名「实时监听」（locale 对应）

## N. 性能 / 压力

- [ ] 200MB PCAP 加载 < 30 秒
- [ ] 50k 包 filter 实时输入无明显卡顿
- [ ] hex dump 展开后滚动流畅

### N.1 大文件 + lazy mmap heap 档案（v1.1 LAZY-005 入口）

`adb shell dumpsys meminfo io.github.packetscope.debug` 读 heap 档案：

- [ ] 200 MB PCAP 加载后 **Dalvik Heap < 200 MB**（v1.1 lazy 改造后
  raw bytes 不入 heap，仅元数据 + indices）
- [ ] **Native Heap** 反映 mmap 占用（应能看到 ≈ PCAP 文件大小的 mmapped
  region），证明 zero-copy 视图生效
- [ ] 1 GB PCAP 打开 < 5 秒 + 不 OOM（LAZY-005 上限提升后必测）
- [ ] 连续打开 5 个不同 PCAP，旧 mmap 立即释放——`procrank` /
  `dumpsys meminfo` 看 PSS 不累积增长（LAZY-003 PcapHandle 验收）

操作步骤：
```
adb shell dumpsys meminfo io.github.packetscope.debug | head -40
# 关注两段：
#   App Summary → Java Heap (Dalvik) + Native Heap
#   Mappings → mmap 字节数
```

期望档案（200 MB PCAP）：
- Dalvik Heap ≈ 50-150 MB（layers / fields / indices；跟帧数线性，跟单
  帧字节数无关）
- Native Heap + mmap ≈ 200 MB（OS paging 按需，cold cache 时较低）

## O. 不存在的 regressions

- [ ] 没有任何 logcat ERROR / FATAL 输出
- [ ] StrictMode（dev build）无 ANR / disk I/O on main thread 告警
- [ ] memory profile 无 leak（打开 / 关闭 PCAP 反复 10 次 heap 稳定）

---

## 截图收集（fastlane / docs/screenshots 共用）

跑 QA 时顺手存图，命名：

- `01-frame-list.png` (B 段)
- `02-frame-detail.png` (C 段)
- `03-conversations.png` (E 段)
- `04-follow-stream.png` (F 段)
- `05-filter-help.png` (D 段)
- `06-streaming.png` (H 段)

复制到：
- `docs/screenshots/` —— README 引用
- `fastlane/metadata/android/en-US/images/phoneScreenshots/` —— F-Droid
- `fastlane/metadata/android/zh-CN/images/phoneScreenshots/` —— F-Droid 中文

## 验证结果

- [ ] 全 ✅，release 放行
- [ ] 有 ❌：___（issue 编号 / 描述）→ 修复后重跑相关段

签字：___（reviewer 姓名 / 日期）
