# Security Policy

## Supported versions

Only the latest release is supported. Older versions may have known
issues fixed in newer releases — please upgrade before reporting.

## Reporting a vulnerability

**Do not file a public GitHub issue for security bugs.** Public disclosure
before a fix gives attackers a window to exploit unpatched users.

Please report security vulnerabilities by:

- **GitHub Private Vulnerability Reporting** (preferred):
  https://github.com/Seryta/PacketScope/security/advisories/new
- Or email the maintainer (see GitHub profile contact).

We will acknowledge within 7 days and aim to disclose / patch within 30
days. If your report requires longer coordination (e.g. cross-project
issue), we'll keep you updated on the timeline.

## Scope

The following are in scope for security reports:

- **PCAP parsing / decoder safety**: heap overflows, infinite loops on
  malformed input, integer overflow / underflow in length fields
- **TLS / QUIC decryption correctness**: incorrect key derivation, AEAD
  mishandling, IV reuse, padding oracle exposure
- **PCAPdroid UDP listener**: network-exposed even though bound to
  `127.0.0.1` — port hijacking, unauthorized cross-app injection on
  rooted device
- **SAF / Intent handler**: URI traversal, unintended file access via
  crafted Intent, scoped storage bypass
- **Privilege escalation** via ForegroundService / notification trampoline
  / FileProvider misconfiguration
- **Memory safety**: native crash leading to remote-controlled UI state
  (mmap region attacks)

## Out of scope

- Bugs in PCAPdroid itself — report to
  https://github.com/emanuele-f/PCAPdroid
- Issues requiring physical device access or pre-installed malware
- Theoretical attacks without a proof-of-concept on a real device
- DoS via legitimate-looking large PCAP (file size limit is 500 MB,
  expected behavior)
- Self-XSS / clickjacking in About screen browser links (mitigated by
  using the system browser via `Intent.ACTION_VIEW`)

## Coordinated disclosure

For high-severity issues affecting users in the wild, we prefer
coordinated disclosure: report → acknowledge → fix → release →
public advisory + credit (with reporter consent).

The maintainer will issue a GitHub Security Advisory after a fix is
shipped in a tagged release. CVE assignment is requested for issues
that meet severity criteria.

## Maintainer setup for this policy

To enable Private Vulnerability Reporting (required for the GitHub
link above to work):

1. Go to repository **Settings → Code security and analysis**
2. Under **Private vulnerability reporting**, click **Enable**

This is a one-time configuration; once enabled, the URL in this
document will be live.
