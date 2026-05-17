# Changelog

本文件按 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 1.1
规范记录 PacketScope 发版变更。版本号遵循 [Semver 2.0](https://semver.org)；
v0.x 阶段允许小版本含破坏性变更，进入 v1.0 后才严格遵守。

每个 release 标题对齐 `app/build.gradle.kts` 的 `versionName`，并与
README Roadmap 表 + `app/build.gradle.kts` `versionCode` 三处同步——
`./gradlew checkVersionAlignment` 守约定。

## [Unreleased]

### Added
- **True lazy `Frame.data`**（v1.1 LAZY-001~005）：mmap 路径下 Frame.data
  改成 `MmapBytes` 视图（`(parent ByteBuffer, offset, length)`），zero-copy
  访问。`FrameBytes` sealed interface 同时保留 `HeapBytes`（InputStream
  路径 / PCAPdroid UDP listener）实现，dissector signature 不动
- **`PcapHandle` 显式 mmap 生命周期**：`PcapLoader.Result.Success` 持
  handle，AppScreen 用 `DisposableEffect(handle)` 在 state 切换时显式
  unmap 旧 mmap，避免连续打开多个 PCAP 时 vmem 累积
- `MemoryProfileTest`：JVM 侧验证 mmap 路径 frame.data 是 MmapBytes 视图
  + heap 增量 < 文件 50%；QA_CHECKLIST §N.1 补真机 `dumpsys meminfo`
  流程

### Changed
- 单次加载体积上限 **500 MB → 1 GB**（lazy refactor 让 raw bytes 不再
  占 heap；2 GB 需要多段 mmap，留 v2.0）

## [0.9.0] - 2026-05-17

### Added
- **mmap-based PCAP reader** (`PcapMmapReader`)：用 `FileChannel.map`
  把整个 PCAP 文件映射到进程地址空间，OS 按需 paging，IO 不再走
  user-space buffer。中等 / 大 PCAP 加载更快、内存压力更低
- `PcapLoader` 加 mmap fast path：先 `openFileDescriptor(uri, "r")`
  拿 fd 走 mmap；provider 不支持时 fallback 回 `openInputStream` +
  `PcapReader`

### Changed
- 单次加载体积上限 50 MB → **500 MB**（mmap + heap 解析后 layers
  仍占堆，500 MB 是工程平衡点）
- README Roadmap v0.7 / v0.8a / v0.8b / v0.8c / v0.9 五个 milestone
  全部标 ✅

## [0.8c] - 2026-05-17

### Added
- **TCP 流重组**（`TcpReassembler` + `ReassembledFlow`）：按 4-tuple
  聚类 session，双向独立 byte stream，处理 SYN ISN / 重传 / 乱序 /
  overlap，给下游 HTTP body 解析与未来 Follow Stream "拼接视图" 共用
- **HTTP body 跨 segment 解析**（`HttpStreamPass`）：在重组后 stream
  上解 request / response 完整 message，支持 Content-Length / chunked
  Transfer-Encoding，自动按 Content-Encoding 走 gzip / deflate 解压

### Added (tests)
- `TcpReassemblerTest` 6 case 覆盖顺序 / 重传 / overlap / 双向 / 无 SYN
- `HttpStreamPassTest` 3 case 覆盖 Content-Length 跨 segment / gzip /
  chunked 三场景

## [0.8b] - 2026-05-17

### Added
- **TLS 1.2 解密**（`Tls12Decryptor` + `Tls12Prf`）：实现 RFC 5246 PRF
  (P_SHA256 / P_SHA384)，从 `CLIENT_RANDOM` 派生 master_secret 后展开
  key_block，按方向取 write_key + implicit_iv；AES-GCM (RFC 5288) +
  ChaCha20-Poly1305 (RFC 7905) 双模式 AEAD 解 ApplicationData
- **TLS 1.3 完整 cipher 集合**：补 `TLS_AES_256_GCM_SHA384` (0x1302)
  + `TLS_CHACHA20_POLY1305_SHA256` (0x1303)；`Hkdf` 拆 Hash enum
  (SHA256/SHA384) 支持不同 hash family
- **QUIC v1 Initial 解密**（`QuicInitialDecryptor` + `QuicInitialPass`）：
  RFC 9001 §5.2 从 client 第一个 Initial 包的 Destination CID 派生
  initial keys（不需要 SSLKEYLOGFILE），AES-128-ECB 去 header protection
  + AES-128-GCM 解 payload，浅 parse CRYPTO frame 揭出 ClientHello /
  ServerHello

### Added (tests)
- `Tls12DecryptorTest` 5 case：AES_128_GCM / AES_256_GCM_SHA384 /
  ChaCha20-Poly1305 / seq 自增 / auth 失败返回 null
- `Tls13DecryptorTest` +2 case：AES_256 + ChaCha20 roundtrip
- `QuicInitialDecryptorTest` 3 case：RFC 9001 A.1 DCID + manual
  minimal-packet roundtrip

### Changed
- `TlsDissector` 在 ServerHello 提取 32 字节 `server_random`（TLS 1.2
  派生 key_block 需要）
- `TlsDecryptionPass` 按 cipher 分流 TLS 1.3 traffic_secret 路径与
  TLS 1.2 master_secret 路径

## [0.8a] - 历史

### Added
- TLS 1.3 ApplicationData 解密（`TLS_AES_128_GCM_SHA256`）
- `SslKeyLogParser` / `KeyLogStore` / `TlsDecryptionPass` 流水线
- 「加载 keylog」入口接 SAF 文件

## [0.7] - 历史

### Added
- PCAPdroid UDP Exporter 实时接入
- `UdpExporterListener` foreground service 保活 + 后启动场景的 linkType
  启发式

## 历史版本

v0.1 / v0.2 / v0.3 / v0.4 / v0.5 / v0.6 见 README §Roadmap 表。这些
milestone 早于 CHANGELOG 引入（review v0.6-round7 F-005），未补回。
