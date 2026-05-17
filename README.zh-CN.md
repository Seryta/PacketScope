[English](README.md) | **简体中文**

[![CI](https://github.com/Seryta/PacketScope/actions/workflows/ci.yml/badge.svg)](https://github.com/Seryta/PacketScope/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Seryta/PacketScope?include_prereleases)](https://github.com/Seryta/PacketScope/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Android API 26+](https://img.shields.io/badge/API-26%2B-green.svg)](https://android-arsenal.com/api?level=26)

# PacketScope

Android 端 PCAP 查看器。**专做查看，不抓包。**

抓包交给 [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) 这类成熟工具，PacketScope 负责把抓到的流量以 Wireshark 风格（包列表 / 协议树 / Hex 三联视图）在手机上呈现。

## 为什么用 PacketScope 而不是 X

- **vs Wireshark / Termshark**：桌面构建在 Android 上跑不起，终端 TUI 不适合手机交互。PacketScope 是原生 Compose UI，按手机屏幕设计。
- **vs 直接看 PCAPdroid**：PCAPdroid 主功能是抓包，自带的查看功能较轻。PacketScope 专做 Wireshark 风格的协议树 + 字节高亮 + 过滤 + Follow Stream 分析。
- **vs 把 PCAP 拷到电脑看**：手机抓 → 手机看，不用切设备。

## App 语言

默认英文。系统 locale 为 `zh-*` 时自动切简体中文。

## 截图

> 真机 QA 阶段补，见 [`docs/screenshots/`](docs/screenshots/)。

## 直接安装

到 [Releases](https://github.com/Seryta/PacketScope/releases) 下载最新
`app-release.apk`，启用「未知来源」安装。或加入 F-Droid 仓库（计划中）。

## 当前状态：v0.9.0（≈ Roadmap v0.9）

已实现：

- **PCAP 解析**：classic PCAP 四种 magic（LE/BE × micro/nano），Ethernet / Linux SLL v1+v2 / Raw IP（**暂不支持 PCAPng**，magic 命中时给明确错误）
- **协议解析**：IPv4 / IPv6 / ICMP / ICMPv6 / TCP / UDP / DNS / HTTP / TLS（含 SNI）/ QUIC long header；非默认端口靠 dissector 自防做 fallback 探针
- **三联视图**：包列表 + 协议树 + Hex 联动（点字段高亮对应字节）
- **过滤表达式**：协议 / `host` / `port` / `sni` / `http.host` / `http.path` / `http.method` / `url` / `dns.name` / `app` / `text` + `and`/`or`/`not` + 括号；文件模式走预算 FilterIndex，10k+ 包无明显卡顿
- **TCP 会话分析**：相对 Seq/Ack、Retransmission / Out-of-Order / Dup ACK 标记
- **TLS 1.3 解密**：消费 SSLKEYLOGFILE 派生 traffic secret，AES-128-GCM AEAD 解 ApplicationData
- **PCAPdroid 实时接入**：UDP Exporter 监听 + ForegroundService 保活 + 后启动场景的 linkType 启发式
- **PCAPdroid 扩展**：dump_extensions trailer 解析（uid / appname + CRC32）
- **外部 Intent 集成**：从 PCAPdroid 分享（ACTION_SEND application/cap）、文件管理器、或 `.pcap` 关联打开

## 使用

1. **从 PCAPdroid 分享**：在 PCAPdroid 抓包停止后，长按导出的 PCAP → 分享 → 选 PacketScope
2. **PCAPdroid 实时流**：在 PacketScope 输入端口（默认 1234）开始监听 → PCAPdroid Exporter UDP 模式指向 `127.0.0.1:1234`
3. **从文件管理器**：在文件 app 里点 `.pcap` 文件 → 系统弹出「打开方式」可选 PacketScope
4. **手动打开**：启动 PacketScope → 点「打开 PCAP 文件」→ 用 SAF 文件选择器
5. **TLS 1.3 解密**：把含 CLIENT_TRAFFIC_SECRET_0 / SERVER_TRAFFIC_SECRET_0 的 SSLKEYLOGFILE 通过「加载 keylog」入口选入，解密结果挂在每条 TLS layer 下

## Roadmap

| 版本 | 内容 | 状态 |
| --- | --- | --- |
| v0.1 | 项目骨架 | ✅ |
| v0.2 | PCAP 解析 + L2/L3/L4 dissector | ✅ |
| v0.3 | 三联视图 UI | ✅ |
| v0.4 | L7 解析：DNS / HTTP / TLS / QUIC | ✅ |
| v0.5 | 过滤表达式 | ✅ |
| v0.6 | PCAPdroid 文件互通：ACTION_VIEW / ACTION_SEND | ✅ |
| v0.7 | PCAPdroid UDP Exporter 实时接入 + ForegroundService | ✅ |
| v0.8a | TLS 1.3 AES-128-GCM 解密（消费 SSLKEYLOGFILE） | ✅ |
| v0.8b | TLS 1.2 / 其它 AEAD / QUIC Initial 解密 | ✅ |
| v0.8c | TCP 重组 + HTTP 跨 segment body 解析 | ✅ |
| v0.9 | lazy paging / mmap 大文件加载（拆 50MB → 500MB） | ✅ |
| v1.0 | 公开仓库收尾：licensing / CI / release / privacy / 文档 | ✅ |
| v1.1 | Frame.data 真正 lazy（mmap slice 按需读，单文件上限 1 GB） | ✅ |
| v2.0 | 多段 mmap 突破 2 GB + metadata 流式 dissect | ⏭️ |

## 构建

按项目规则**不在宿主机直接构建**，统一用 Docker：

```bash
docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$PWD":/work -w /work \
  -v "$HOME/.gradle-docker":/work/.gradle-cache \
  -e GRADLE_USER_HOME=/work/.gradle-cache \
  mingc/android-build-box:latest \
  ./gradlew assembleDebug
```

要点：

- **`-u "$(id -u):$(id -g)"`**：容器以宿主机用户身份跑，避免产出 root-owned 的 `.gradle/` / `app/build/` 让你下次 `./gradlew clean` 时权限报错。
- **GRADLE_USER_HOME** 指到一个宿主可写的目录（这里用 `~/.gradle-docker`），缓存依赖跨次构建复用。容器内 user home 不在 `/root` 时 Gradle 默认会去 `~/.gradle` 失败。

测试：

```bash
docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$PWD":/work -w /work \
  -v "$HOME/.gradle-docker":/work/.gradle-cache \
  -e GRADLE_USER_HOME=/work/.gradle-cache \
  mingc/android-build-box:latest \
  ./gradlew recordRoborazziDebug
```

会生成 `app/build/outputs/roborazzi/*.png` 截图基线，CI 用 `verifyRoborazziDebug` 比对。

## 静态分析

CI / PR 落地前跑：

```bash
./gradlew :app:lintDebug detekt :app:testDebugUnitTest checkVersionAlignment
```

- `lintDebug` — Android lint，资源 / API level / i18n 检查（baseline 见
  `app/lint-baseline.xml`）
- `detekt` — Kotlin 静态分析，风格 / 复杂度 / 反模式（baseline 见
  `config/detekt/detekt-baseline.xml`）
- `checkVersionAlignment` — 校验 `app/build.gradle.kts` 的 `versionName`
  与 README 的「当前状态：vX.Y.Z」行一致（review v0.6-round3 F-006）

baseline 内的旧问题作为债务渐进消减；新增问题 fail build。

详见 [`ARCHITECTURE.md`](ARCHITECTURE.md) §静态分析 +
[`CONTRIBUTING.md`](CONTRIBUTING.md) 提交前自检 checklist。

## 关联项目

- [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) — Android 上无 root 即可抓包的开源 app。PacketScope 设计目标之一是直接消费 PCAPdroid 导出的 `.pcap` / `.pcapng` 文件，并对接它的 [UDP Exporter API](https://github.com/emanuele-f/PCAPdroid/blob/master/docs/app_api.md) 实时接入。

## 反馈 / Issues

到 [GitHub Issues](https://github.com/Seryta/PacketScope/issues) 提。

## 许可

[MIT License](LICENSE) © 2026 Seryta

第三方依赖 license 摘要：[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)。

隐私政策：[PRIVACY.md](PRIVACY.md)。提审用 raw URL：
`https://raw.githubusercontent.com/Seryta/PacketScope/master/PRIVACY.md`。
