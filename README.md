**English** | [简体中文](README.zh-CN.md)

[![CI](https://github.com/Seryta/PacketScope/actions/workflows/ci.yml/badge.svg)](https://github.com/Seryta/PacketScope/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Seryta/PacketScope?include_prereleases)](https://github.com/Seryta/PacketScope/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Android API 26+](https://img.shields.io/badge/API-26%2B-green.svg)](https://android-arsenal.com/api?level=26)

# PacketScope

Android PCAP viewer. **Read-only — capture is delegated to PCAPdroid.**

Capture goes to mature tools like [PCAPdroid](https://github.com/emanuele-f/PCAPdroid);
PacketScope renders the captured traffic in a Wireshark-style three-pane
layout (frame list / protocol tree / hex) on Android.

## Why PacketScope vs X

- **vs Wireshark / Termshark**: the desktop build won't run on Android,
  and a terminal TUI is awkward on a phone. PacketScope is a native
  Compose UI designed for phone screens.
- **vs PCAPdroid alone**: PCAPdroid focuses on capture; its built-in
  viewer is lightweight. PacketScope is dedicated to Wireshark-style
  protocol tree + byte highlighting + filter expressions + Follow Stream
  analysis.
- **vs copy PCAP off to a desktop**: capture on phone, analyze on
  phone — no device switching.

## App language

English by default. Simplified Chinese is auto-selected when the system
locale is `zh-*`.

## Screenshots

> Pending real-device QA, see [`docs/screenshots/`](docs/screenshots/).

## Install directly

Download the latest `app-release.apk` from
[Releases](https://github.com/Seryta/PacketScope/releases) and enable
"Install from unknown sources". F-Droid repository inclusion is planned.

## Current status: v0.9.0 (≈ Roadmap v0.9)

Shipped:

- **PCAP parsing**: classic PCAP across four magic variants
  (LE/BE × micro/nano), Ethernet / Linux SLL v1+v2 / Raw IP
  (**PCAPng not yet supported**; the magic is recognized and a clear
  error is shown)
- **Protocol dissection**: IPv4 / IPv6 / ICMP / ICMPv6 / TCP / UDP /
  DNS / HTTP / TLS (with SNI) / QUIC long header; non-default ports
  fall back to per-dissector self-probes
- **Three-pane view**: frame list + protocol tree + hex with two-way
  highlighting (tap a field, the corresponding bytes light up)
- **Filter expressions**: `tcp` / `host` / `port` / `sni` /
  `http.host` / `http.path` / `http.method` / `url` / `dns.name` / `app`
  / `text` plus `and`/`or`/`not` with parentheses; file mode precomputes
  a `FilterIndex` so 10k+ packets stay responsive
- **TCP session analysis**: relative seq/ack, retransmission /
  out-of-order / duplicate ACK flagging
- **TCP reassembly + HTTP body parsing**: cross-segment HTTP request /
  response with Content-Length, chunked Transfer-Encoding, automatic
  gzip / deflate decompression
- **TLS decryption** (when an SSLKEYLOGFILE is provided):
  - TLS 1.2 AES-128/256-GCM and ChaCha20-Poly1305 (RFC 5288 / RFC 7905)
  - TLS 1.3 AES-128/256-GCM and ChaCha20-Poly1305 (RFC 8446)
- **QUIC v1 Initial decryption**: payload + CRYPTO frame extraction
  (RFC 9001 §5.2, no keylog needed)
- **PCAPdroid live ingestion**: UDP Exporter listener + ForegroundService
  + post-launch linkType heuristics
- **PCAPdroid extensions**: `dump_extensions` trailer parsing
  (uid / appname + CRC32)
- **External intent integration**: open via PCAPdroid share
  (`ACTION_SEND application/cap`), file manager, or `.pcap` association
- **Large files**: mmap-based reader with true lazy `Frame.data` (zero-copy
  views over the mapped buffer); file size limit **up to 1 GB**

## Usage

1. **Share from PCAPdroid**: after PCAPdroid finishes capturing,
   long-press the exported PCAP → Share → choose PacketScope
2. **PCAPdroid live stream**: in PacketScope, enter a port (default 1234)
   and start listening; configure PCAPdroid's UDP Exporter to
   `127.0.0.1:1234`
3. **From a file manager**: tap a `.pcap` file in your file app → choose
   PacketScope in the system "Open with" dialog
4. **Manual open**: launch PacketScope → "Open PCAP file" → pick via SAF
5. **TLS decryption**: load an SSLKEYLOGFILE containing
   `CLIENT_TRAFFIC_SECRET_0` / `SERVER_TRAFFIC_SECRET_0` (TLS 1.3) or
   `CLIENT_RANDOM` (TLS 1.2) via the "Load keylog" entry; decrypted
   payload attaches to each matching TLS layer

## Roadmap

| Version | Content | Status |
| --- | --- | --- |
| v0.1 | Project scaffold | ✅ |
| v0.2 | PCAP parsing + L2/L3/L4 dissectors | ✅ |
| v0.3 | Three-pane UI | ✅ |
| v0.4 | L7 dissectors: DNS / HTTP / TLS / QUIC | ✅ |
| v0.5 | Filter expressions | ✅ |
| v0.6 | PCAPdroid file interop: ACTION_VIEW / ACTION_SEND | ✅ |
| v0.7 | PCAPdroid UDP Exporter live ingestion + ForegroundService | ✅ |
| v0.8a | TLS 1.3 AES-128-GCM decryption (consume SSLKEYLOGFILE) | ✅ |
| v0.8b | TLS 1.2 / other AEADs / QUIC Initial decryption | ✅ |
| v0.8c | TCP reassembly + HTTP cross-segment body parsing | ✅ |
| v0.9 | Lazy paging / mmap large file load (50 MB → 500 MB) | ✅ |
| v1.0 | Public-ready hardening: licensing / CI / release / privacy / docs | ✅ |
| v1.1 | True lazy `Frame.data` (mmap slice on demand, 1 GB PCAP) | ✅ |
| v2.0 | Multi-segment mmap for > 2 GB PCAP + metadata streaming | ⏭️ |

## Build

Project rule: **never build directly on the host**. Use Docker:

```bash
docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$PWD":/work -w /work \
  -v "$HOME/.gradle-docker":/work/.gradle-cache \
  -e GRADLE_USER_HOME=/work/.gradle-cache \
  mingc/android-build-box:latest \
  ./gradlew assembleDebug
```

Key flags:

- **`-u "$(id -u):$(id -g)"`** — runs the container as your host user so
  `.gradle/` / `app/build/` are not produced root-owned and tripping up
  the next `./gradlew clean`.
- **`GRADLE_USER_HOME`** points to a host-writable directory
  (`~/.gradle-docker` here) so the dependency cache is reused across
  builds. The container's home is not `/root`, so Gradle's default
  `~/.gradle` would fail.

Roborazzi screenshot baseline:

```bash
docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$PWD":/work -w /work \
  -v "$HOME/.gradle-docker":/work/.gradle-cache \
  -e GRADLE_USER_HOME=/work/.gradle-cache \
  mingc/android-build-box:latest \
  ./gradlew recordRoborazziDebug
```

CI uses `verifyRoborazziDebug` to compare against the baseline in
`app/build/outputs/roborazzi/*.png`.

## Static analysis

Run before opening a PR:

```bash
./gradlew :app:lintDebug detekt :app:testDebugUnitTest checkVersionAlignment
```

- `lintDebug` — Android lint, resource / API level / i18n checks
  (baseline at `app/lint-baseline.xml`)
- `detekt` — Kotlin static analysis (baseline at
  `config/detekt/detekt-baseline.xml`)
- `checkVersionAlignment` — verifies `app/build.gradle.kts` `versionName`
  matches the README "Current status: vX.Y.Z" line (review
  v0.6-round3 F-006)

Existing baseline entries are debt to be drawn down incrementally; new
violations fail the build.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) §Static analysis and the
[`CONTRIBUTING.md`](CONTRIBUTING.md) pre-submit checklist for detail.

## Related projects

- [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) — open-source
  no-root packet capture on Android. PacketScope's design goal is to
  directly consume PCAPdroid's exported `.pcap` / `.pcapng` files and
  integrate with its [UDP Exporter API](https://github.com/emanuele-f/PCAPdroid/blob/master/docs/app_api.md)
  for live capture.

## Feedback / Issues

File at [GitHub Issues](https://github.com/Seryta/PacketScope/issues).

## License

[MIT License](LICENSE) © 2026 Seryta

Third-party dependency license summary: [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

Privacy policy: [PRIVACY.md](PRIVACY.md). Raw URL for store submission:
`https://raw.githubusercontent.com/Seryta/PacketScope/master/PRIVACY.md`
