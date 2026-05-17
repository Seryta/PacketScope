# Privacy Policy / 隐私政策

Effective: 2026-05-17

## English

PacketScope is an offline PCAP (packet capture file) viewer for Android.
It pairs with [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) to
display captured network traffic in a Wireshark-style interface.

### What we collect

**Nothing.** PacketScope does not collect, log, transmit, or share any
personal data, usage analytics, crash reports, or telemetry to any server.

### What we access on your device

- **Files you explicitly open** (via system file picker, share intent,
  or ACTION_VIEW intent): the PCAP file you choose is read locally to
  parse and display packets. The file is not copied off your device.
- **TLS keylog file you explicitly load** (NSS Key Log Format): when you
  use the "Load keylog" feature, the keys are held in process memory
  only to decrypt visible TLS sessions. Clearing keylog or quitting the
  app drops them; nothing is persisted to disk.
- **Local UDP socket** (PCAPdroid live ingestion): when you enable
  "Listen for PCAPdroid", PacketScope binds a UDP socket on `127.0.0.1`
  to receive captured packets streamed from PCAPdroid. No data leaves
  your device.

### Permissions explained

- `INTERNET`: required by Android to bind a local UDP socket (even
  `127.0.0.1`). PacketScope does not make any outbound network
  connections.
- `FOREGROUND_SERVICE` + `FOREGROUND_SERVICE_DATA_SYNC`: required to
  keep the UDP listener alive in the background while you receive a
  capture stream.
- `POST_NOTIFICATIONS`: required to display the foreground service
  notification (Android 13+).

### Third-party services

None.

### Updates to this policy

Changes will be committed to this file in the repository. Material
changes will be noted in CHANGELOG.md.

### Contact

Report privacy concerns at
https://github.com/Seryta/PacketScope/issues.

---

## 简体中文

PacketScope 是一款 Android 离线 PCAP（抓包文件）查看器，与
[PCAPdroid](https://github.com/emanuele-f/PCAPdroid) 配合使用，以
Wireshark 风格界面展示抓到的网络流量。

### 我们收集什么

**什么都不收集。** PacketScope 不向任何服务器收集 / 记录 / 传输 / 共享
任何个人数据、使用统计、崩溃报告或遥测。

### 我们如何访问你设备上的数据

- **你主动打开的文件**（通过系统文件选择器、分享 intent、或
  ACTION_VIEW intent）：你选择的 PCAP 文件在本地读取以解析展示。文件
  不会离开你的设备。
- **你主动加载的 TLS keylog 文件**（NSS Key Log Format）：使用「加载
  keylog」功能时，密钥仅保留在进程内存中以解密当前可见的 TLS 会话。
  清除 keylog 或退出 app 即丢弃；不会持久化到磁盘。
- **本地 UDP socket**（PCAPdroid 实时接入）：开启「监听 PCAPdroid」时，
  PacketScope 在 `127.0.0.1` 绑定 UDP socket 接收 PCAPdroid 流式发送
  的抓包数据。**数据不出设备**。

### 权限说明

- `INTERNET`：Android 要求绑定任何 UDP socket（包括 `127.0.0.1`）必须
  有此权限。PacketScope 不发起任何出站网络连接。
- `FOREGROUND_SERVICE` + `FOREGROUND_SERVICE_DATA_SYNC`：让 UDP listener
  在后台保持存活，接收实时抓包流。
- `POST_NOTIFICATIONS`：Android 13+ 要求显式申请，用于显示 foreground
  service 通知。

### 第三方服务

无。

### 政策更新

变更将通过 commit 进入此文件。重大变更会在 CHANGELOG.md 中标注。

### 联系方式

隐私问题请通过
https://github.com/Seryta/PacketScope/issues 反馈。
