# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-16

First public release.

### Added
- **Android scanning**: manifest and resources (apktool), decompiled Java (jadx), signing
  (apksigner), native libraries, dependencies with a curated advisory list, trackers, hardcoded
  secrets, and data-flow rules over the decompiled code. Every finding points at a file and line and
  quotes the code.
- **iOS scanning**: `Info.plist` and App Transport Security, entitlements, provisioning profile,
  Mach-O protections, and function-level analysis of the machine code (the calls a function makes
  and the literals it holds). Functions are shown as readable pseudo-code and every finding quotes
  the lines that show it. App Store (FairPlay-encrypted) builds are detected and reported as unreadable.
- **Live map**: while a scan runs, the app's files are drawn as folders and walked as the scan reads
  them, for Android and iOS. A finished scan can be replayed on the same map.
- **Report**: a score and grade, one list of what to fix (a finding you mark as a false positive drops out of the score and the report),  OWASP MASVS and Mobile Top 10
  mapping, a remediation roadmap, PDF export (optionally password-protected), JSON and SARIF 2.1.0.
- **Triage and comparison**: confirm, mark false positive or accept risk with an expiry; compare
  two scans of the same app and track progress across builds.
- **Light, medium and dark themes**, with a vertical sidebar for the scan, report and audit screens.
- **Code explorer**: browse the decompiled sources with the lines a finding landed on marked.
- **Linux installer**: `scripts/install-linux.sh` installs the tools, builds, creates the service user,
  data directory and systemd service, and checks the result (Debian, Ubuntu, Fedora, RHEL families).
- **Self-hosting**: one container on one port (`docker compose up -d --build`), SQLite storage,
  accounts with scrypt-hashed passwords, rate limits, security headers, graceful shutdown, backup
  and restore tools, and `npm run doctor`.

### Notes
- The first account starts on the published default password (`admin` / `kavach`) unless
  `KAVACH_SAST_ADMIN_PASSWORD` is set. The console warns until it is changed.
- Static analysis only: the app is never run. Findings are leads to verify.

[0.1.0]: https://github.com/harshbhanushali/kavach-sast/releases/tag/v0.1.0
