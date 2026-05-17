# Changelog

本文件按 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 1.1
规范记录 PacketScope 发版变更。版本号遵循 [Semver 2.0](https://semver.org)；
v0.x 阶段允许小版本含破坏性变更，进入 v1.0 后才严格遵守。

每个 release 标题对齐 `app/build.gradle.kts` 的 `versionName`，并与
README Roadmap 表 + `app/build.gradle.kts` `versionCode` 三处同步——
`./gradlew checkVersionAlignment` 守约定。

## [Unreleased]

### Added
- 真机截图入库 `docs/screenshots/`（5 张 .jpg）+ fastlane phoneScreenshots
  双语副本：启动屏 / 包列表实时 / 帧详情 / 过滤语法 / 会话视图。
  README 双语 §Screenshots 段直接渲染 markdown 图片表
- README "Install directly" 段更新为 `PacketScope-<version>-release.apk`
  对齐 v1.1.0 起的 base.archivesName 命名

### Security
- 截图前置 PII 处理：帧详情 / 会话屏中真实私有 IP（局域网 +
  运营商 NAT 段）已用纯色矩形 redact；原图 staging 区
  `/images/` 入 `.gitignore` 永不入库，含 dotfile 列表的 payload 截图
  直接不入库

## [1.1.0] - 2026-05-17

### Added
- **True lazy `Frame.data`**（v1.1 round0 LAZY-001~005）：mmap 路径下
  Frame.data 改成 `MmapBytes` 视图（`(parent ByteBuffer, offset, length)`），
  zero-copy 访问；`FrameBytes` sealed interface 同时保留 `HeapBytes`
  实现给 InputStream 路径 / PCAPdroid UDP listener 用，dissector
  signature 不动。同等 PCAP 加载后 heap 占用预期下降 ~50%——raw bytes
  不再压堆，仅元数据 (layers / fields / FilterIndex) 留在堆上
- **`PcapHandle` 显式 mmap 生命周期**：`PcapLoader.Result.Success` 持
  handle，AppScreen 用 `DisposableEffect(handle)` 在 state 切换时显式
  触发 `reader.tryExplicitUnmap()`（reflection 调 `MappedByteBuffer.cleaner`），
  避免连续打开多个 PCAP 时 vmem 累积；reflection 失败时 fallback 到 GC
  + finalizer，跟 v0.9 之前一致不会更差
- **`ByteReader` FrameBytes 重载**（u8 / u16Be / u32Be）：pass 层
  （TcpReassembler / TcpSessionAnalyzer）直接吃 `frame.data` 读 2-4 字节，
  不需要 `asByteArray()` 整帧——lazy 收益的关键放大器
- `MemoryProfileTest` (v1.1 round1 F-004 扩展)：JVM 侧验证
  - mmap 路径 `frame.data is MmapBytes`（零拷贝视图）
  - InputStream 路径 `frame.data is HeapBytes`（对照路径行为不变）
  - mmap 加载 1.5 MB PCAP heap 增量 < 文件 50%
  - **Pipeline.process 后 Frame.data 仍持 MmapBytes 视图**（验 Pipeline
    内 asByteArray() 中间变量没意外泄漏进 Frame）
- `PcapHandleTest` (v1.1 round0 LAZY-003)：onClose 调一次 / 重复 close
  idempotent / 未 close 时不触发
- QA_CHECKLIST §N.1 大文件 + lazy mmap heap 档案段：真机 `adb shell
  dumpsys meminfo` 流程 + Dalvik / Native Heap 期望档案 + 1 GB / 5 个
  PCAP 连开的验收点
- ANDROID_PITFALLS §大文件 / mmap（3 条新 P-NN 入库）：
  - **P-20** 单 MappedByteBuffer 上限 `Int.MAX_VALUE` (~2.1 GB)，> 2 GB
    要多段 mmap
  - **P-21** `MappedByteBuffer` 无标准 unmap API，reflection + GC 兜底
  - **P-22** lazy mmap unmap 与背景线程读 frame.data 的 race（v1.1
    round1 F-001 已知风险点；任何未来加 LaunchedEffect 异步读 frame.data
    的 PR 必读）

### Changed
- 单次加载体积上限 **500 MB → 1 GB**（lazy refactor 让 raw bytes 不再
  占 heap；2 GB 需要多段 mmap，留 v2.0）
- README + README.zh-CN Roadmap 表：v1.0 ✅（公开仓库收尾）+ v1.1 ✅
  （lazy + 1 GB）+ v2.0 ⏭️（多段 mmap + metadata streaming）

### Fixed
- `PcapHandle.close()` 用 `AtomicBoolean.compareAndSet` 替原 `@Volatile` +
  check-then-set，保证 `onClose` 严格 exactly-once（v1.1 round1 F-002）
- `FrameFilter.Text` 支持 UTF-8 中文 payload：pattern 与 frame.data 走
  同一字节级表示（pattern.toByteArray(UTF-8) → ISO_8859_1 decode）
- 「关于」屏拦截系统手势返回 → onBack（与其它内嵌屏一致）
- 过滤语法 HelpItem 点击替换 query 后光标自动跳到末尾（用 TextFieldValue
  overload 显式控 selection）
- 过滤输入框（FilterBar + FilterHelpDialog）加 X 清除按钮（query 非空才显示）
- FilterHelpDialog IME action = Search，回车直接 dismiss 返回列表

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
