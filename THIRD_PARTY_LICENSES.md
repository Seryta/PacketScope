# Third-party Licenses

PacketScope 自身按 [MIT License](LICENSE) 发布。本文列出运行时打进 release
APK 的第三方依赖以及它们的 license，便于下游审计。

审计方法：跑 `./gradlew :app:dependencies --configuration releaseRuntimeClasspath`
得到 release 运行时依赖树，逐一对照上游仓库 license。审计日期：2026-05-17，
对应 `gradle/libs.versions.toml` HEAD。重大依赖升级时同步更新本文件。

## Release runtime（打进 APK）

| Component | Version | License | Source |
| --- | --- | --- | --- |
| Kotlin Standard Library | 2.0.21 | Apache 2.0 | https://github.com/JetBrains/kotlin |
| AndroidX Core (`androidx.core:core-ktx`) | 1.13.1 | Apache 2.0 | https://developer.android.com/jetpack/androidx/releases/core |
| AndroidX Lifecycle (`lifecycle-runtime-ktx`) | 2.8.7 | Apache 2.0 | https://developer.android.com/jetpack/androidx/releases/lifecycle |
| AndroidX Activity Compose | 1.9.3 | Apache 2.0 | https://developer.android.com/jetpack/androidx/releases/activity |
| AndroidX Compose UI / Graphics / Tooling Preview | (Compose BOM 2025.04.00 → 1.7.8) | Apache 2.0 | https://developer.android.com/jetpack/androidx/releases/compose |
| AndroidX Compose Material3 | 1.3.2 | Apache 2.0 | https://developer.android.com/jetpack/androidx/releases/compose-material3 |

所有 release 运行时依赖均为 Apache 2.0，跟 MIT 完全出站兼容；MIT 是
permissive license，可以接收 Apache 2.0 代码 + 重新分发不传染。

## Test-only（不进 APK）

仅 `testImplementation` 使用，**不打进 release artifact**：

| Component | Version | License | Source |
| --- | --- | --- | --- |
| JUnit 4 | 4.13.2 | EPL 1.0 | https://github.com/junit-team/junit4 |
| Robolectric | 4.14.1 | MIT | https://github.com/robolectric/robolectric |
| Roborazzi (core / compose / junit-rule) | 1.32.2 | Apache 2.0 | https://github.com/takahirom/roborazzi |
| AndroidX Test Runner | 1.6.1 | Apache 2.0 | https://developer.android.com/jetpack/androidx/releases/test |
| AndroidX Test Ext JUnit | 1.2.1 | Apache 2.0 | https://developer.android.com/jetpack/androidx/releases/test |
| detekt | 1.23.7 | Apache 2.0 | https://github.com/detekt/detekt |

JUnit 4 的 EPL 1.0 属 weak copyleft，但**只对 network 服务传染**——Android
本地测试 jar 静态分发无影响。且 JUnit 不入 release APK，对发版 license
合规性无影响。

## 平台 SDK

- Android SDK / Build Tools / Platform-Tools — [Android Software Development
  Kit License Agreement](https://developer.android.com/studio/terms)
- Google Play Services — 本项目**不依赖** Play Services，不需要 Play Services
  Terms 条款

## 协议 / Wire 标准（无版权）

PacketScope 实现以下公开协议 / 格式，**不复制任何第三方代码**：

- Classic PCAP / PCAPng file format — [tcpdump.org](https://wiki.wireshark.org/Development/LibpcapFileFormat)
- IPv4 / IPv6 / TCP / UDP / ICMP / DNS / HTTP / TLS / QUIC — IETF RFC
- TLS 1.3 / 1.2 key derivation — RFC 8446 / RFC 5246 / RFC 5288 / RFC 7905
- QUIC v1 Initial keys — RFC 9001
- NSS Key Log Format — [Mozilla NSS 公开文档](https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html)
- PCAPdroid `dump_extensions` trailer — PCAPdroid 项目公开的 wire 格式
  ([PCAPdroid Custom Extensions](https://emanuele-f.github.io/PCAPdroid/dump_extensions))

wire 格式属公开标准，不可版权；我们的实现是原创 Kotlin 代码，跟上游
（Wireshark / tcpdump / PCAPdroid 等）零代码共享。
