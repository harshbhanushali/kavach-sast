# Kavach SAST guide

The full reference: running it, using it, what a scan reports, the API and the configuration.
For the short version, see the [README](../README.md).

- [Run it](#run-it)
- [Using it](#using-it)
- [What a scan reports](#what-a-scan-reports)
- [Findings and secrets](#findings-and-secrets)
- [Triage, progress and comparison](#triage-progress-and-comparison)
- [SARIF and CI](#sarif-and-ci)
- [API](#api)
- [Configuration and deployment](#configuration-and-deployment)
- [Development](#development)
- [Layout](#layout)
- [Limits](#limits)

## Run it

### Docker (one command)

```bash
docker compose up -d --build     # or: npm run docker
```

Open <http://localhost:8788> and sign in as `admin` / `kavach`. That is the published
default: the console warns until you change it from the account menu, and the server
says so in its log. To start with a password of your own instead, copy `.env.example`
to `.env` and set `KAVACH_SAST_ADMIN_PASSWORD` (10+ characters) before the first start.
The port is published on `127.0.0.1` only, so the default is not reachable from other
machines unless you choose to expose it; change it first if you do.

The image is about 2 GB because it carries everything a scan needs (JDK, `apktool`, `apksigner`, `jadx`, and
Chromium and `qpdf` for PDF export), runs on amd64 and arm64, and keeps scans,
triage and accounts in the `kavach-sast-data` volume, which survives
`docker compose down`. It listens on `127.0.0.1` only; to serve other machines put a
TLS proxy in front (see [DEPLOYMENT.md](../DEPLOYMENT.md)).

`npm run docker:logs` follows the logs and `npm run docker:down` stops it.

### Linux: one command

On Debian, Ubuntu, Fedora, RHEL and relatives (x86_64 or aarch64), from a checkout of this repository:

```bash
sudo ./scripts/install-linux.sh
```

It installs everything a scan needs (Node.js, a JDK, apktool, jadx, apksigner, qpdf and Chromium),
builds the console, creates a `kavach` service user, a data directory and a systemd service, starts it
on http://127.0.0.1:8788 and checks it. Pinned copies of the tools go under `/opt/kavach-tools`, so
nothing already on the machine is changed. Run it again to upgrade; your data and configuration stay.
Settings live in `/etc/kavach-sast.env`.

`./scripts/install-linux.sh --help` lists the options (`--port`, `--admin-password`, `--no-service`,
`--yes`, and others). apksigner comes from Google's Android build-tools, so the script asks you to accept
the [Android SDK licence](https://developer.android.com/studio/terms) first, or takes
`--accept-android-sdk-license`. Remove it with `sudo ./scripts/install-linux.sh --uninstall` (add
`--purge` to delete the data too).

### Without Docker, by hand

Needs Node.js 22.6 or newer.

```bash
npm install
npm run backend      # API on http://127.0.0.1:8788
npm run console      # console on http://localhost:5174 (development server)
```

Sign in as `admin` / `kavach`. It is the published default, in development and in a
production start alike, and the console warns until the password is changed from the
account menu. Change it before putting an instance on a shared network, or set
`KAVACH_SAST_ADMIN_PASSWORD` before the first start to skip the default. The static
development token exists only outside production. See [DEPLOYMENT.md](../DEPLOYMENT.md).

A full Android scan needs `apktool` and `apksigner` (and a JDK), and readable Java
needs `jadx`. Without `apktool` a scan still runs, but thinner: a sweep of the DEX
strings only. iOS needs nothing extra, because it is parsed in-process. PDF export
needs Chrome or Chromium (`KAVACH_CHROME` points at one), and password-protecting a
PDF also needs `qpdf`.

`npm run doctor` checks the machine for all of this, and for configuration, disk
space and the port. `curl http://127.0.0.1:8788/healthz` answers with booleans
only: the console, the API, the stored scans and the report deliberately never name
the programs behind the scan, since those are how the service is built, not part of
what a scan says about an app.

## Using it

The console has three screens. **Guide** walks through the five steps and ticks off
the ones you have done; **Scan** is where the work happens; **Audit** is the log of
who did what.

1. **Scan.** On the Scan screen choose an `.apk` or `.ipa` (up to 600 MB) and Run scan. A
   progress bar follows the stages. The upload is analysed and then deleted; what is
   kept is the report and the decompiled sources it points at.
2. **Read.** The scan opens on its Overview (score, grade, findings by severity,
   what the app is) with tabs for the detail. Open a finding to see why it matters,
   the evidence, the standards it maps to, how to fix it and how to check the fix.
   *Open in explorer* jumps to the exact line.
3. **Decide.** Mark each finding Confirmed, False positive, Accepted risk (with an
   expiry) or Fixed, with a reason. The score is recalculated from your decisions.
   A few findings are judgement calls the scanner cannot be sure of (a WebView, a stored
   preference); they sit in the same list. Until you confirm one it costs the score very little,
   and once confirmed it counts in full. Mark it a false positive and it stops counting and is
   left out of the exported report altogether, as if it had never been raised.
4. **Track.** Scan the next build of the same app and the decisions carry over,
   the Overview shows the trend, and Compare shows what changed.
5. **Hand over.** Export the PDF report (optionally password-protected) or SARIF.

### Apps

Every scan belongs to an app, and an app is a package name (Android) or bundle id
(iOS) on a platform. You do not have to register anything: a scan registers its own
app from the package name, named after the app's label, and the next scan of that
package joins it. The **App** menu in the sidebar then narrows the Scan history list
and Compare to one app; **Auto (from the scan)** shows everything. An app you pick
is used only if it really is the artifact's app; otherwise the scan is filed under
its own app, and the console says so. The **+** beside the app picker in the sidebar registers one by hand, for when you
want your own id or name.

## What a scan reports

**Android.** Manifest and component exposure (exported components, permissions,
debuggable, backup, cleartext), the network security config, signing (scheme,
certificate, validity), code and resources scanned for weak or misused crypto,
insecure storage, WebView, SQL and logging problems, native libraries (NX, PIE,
stack canary, RELRO, fortify), dependencies matched against a curated advisory list, and
secrets.

**iOS.** `Info.plist` and App Transport Security, entitlements, the provisioning
profile, privacy usage descriptions, Mach-O protections (PIE, stack canaries, ARC,
encryption), linked frameworks and libraries, and code rules run against the binary's
string table. On an unencrypted build the executable's machine code is also read, one
function at a time: which functions call which APIs and which literals they use. That is
how a finding can say "this challenge handler answers with the server trust and never
evaluates it", "this login function compares against a credential-looking literal", "this
call passes a hardcoded database key". It is a reader of calls and constants, not a
decompiler, and an App Store build is FairPlay-encrypted and cannot be read until it is
decrypted on a device (the report says so). The binary opens in the explorer as a readable
view of its header, symbols and strings, then each function analysed as pseudo-code (its
name, the calls it makes with the arguments the scanner could follow, the literals it
holds), and every finding quotes the lines that show it, as an Android finding quotes Java.

**Live map.** While a scan runs the console draws the app's files as folders and walks them
as the scan reads them, for Android and iOS alike, then plays any of it still on screen when
a short scan ends (an iOS scan takes a couple of seconds); "Show the report now" skips it.
The Replay tab plays a finished scan back on the same map.
**Both.**

- **Attack surface and trust:** what an attacker can reach, what the app trusts.
- **Hardening and security controls:** pinning, root/jailbreak detection, obfuscation,
  biometrics and the rest, each beside the known ways it is bypassed. The point is
  calibration, not reassurance.
- **Domains and trackers:** every host the app references and the privacy trackers it
  embeds. Nothing is contacted or looked up.
- **Your code or a library's:** each location is attributed, so the handful of
  findings in the app's own packages are separated from the many in the libraries
  it ships.
- **Standards:** each finding carries its CWE, OWASP MASVS control and OWASP Mobile
  Top 10 (2024) category, where one applies.
- **Explorer:** the original files, browsable and searchable. Findings point at
  those files, not at a derived copy. Binary originals (signing blocks, native
  libraries, Mach-O binaries, plists) open as decoded text, and a finding in smali is
  mapped to the Java it decompiles to.
- **How to verify:** what to do to confirm each result by hand.

There are 100 rules, grouped by area: code, storage, secrets, cryptography and
network.

## Findings and secrets

Secrets are found in three layers, from most to least certain:

1. **Recognisable credentials** (`backend/src/sast/secretFormats.ts`): about 50
   services whose tokens have a fixed prefix and shape (GitLab, npm, Shopify,
   Square, Mailchimp, Discord, Azure storage, GCP service accounts and so on), plus
   a username and password inside a URL. One table, one line per format; a test
   fails if a format is added without a sample.
2. **Credential-named variables.** An identifier containing a word such as `key`,
   `secret`, `token`, `password`, `iv` or `salt`, bound to a value random enough to
   be one (10+ characters, 3.2+ bits of entropy, a digit, not words joined by
   separators). This is what finds `static final String KEY = "..."`. It also reads
   `strings.xml` and manifest `meta-data`.
3. **Anonymous high-entropy literals**, reported as a finding to confirm, with
   hashes, UUIDs, identifiers, paths, MIME types and similar shapes left out.

A hardcoded key is reported at its declaration, not only where it is used. The
patterns are written from the token formats the issuing services document.

## Triage, progress and comparison

- **Carry-over.** Scanning an app that already has an earlier scan copies decisions
  on findings that have not changed, marked "carried forward". A finding that got
  worse (higher severity, more occurrences, or a location in a new file) goes back to
  open; `fixed` decisions and lapsed accepted risks are never carried. Each carry is
  written to the audit log, and re-reviewing a carried decision makes it that scan's
  own.
- **Progress.** The Compare view shows the score and findings by severity across every
  scan of the same package, what changed since the previous scan, and a button that
  compares the two newest.
- **Score.** 100 minus what the findings cost. Each severity has a ceiling on its
  cost and every finding after the first costs a little less (so five criticals score
  worse than one, and nothing runs out at zero); a finding in a bundled library
  counts a quarter as much as one in the app's own code; a critical in the app's own
  code keeps the grade at C or worse and a high keeps it at B or worse. Judgement-call findings not yet confirmed cost
  up to 4 and verified good practice earns up to 6. The formula and its reasons are in
  `scoreOf` (`backend/src/sast/types.ts`); scans stored under the older formula, which
  scored most apps 0, are rescored once when the database opens.
- **Compare** is per app. Pick an app, then two of its scans: baseline is what you
  had, candidate is what you are about to ship. It shows findings added, resolved,
  and changed in severity, plus changes in dependencies, permissions, trackers and
  hosts. Scans of different apps, or the same package on two platforms, cannot be
  compared, in the console or through `GET /v1/sast/compare`, which refuses them. An
  app with one scan is listed but needs a second.

## SARIF and CI

SARIF is a standard file format for static-analysis results. GitHub code scanning,
Azure DevOps and most CI systems read it, so a scan can show up as annotations on a
pull request. Kavach exports SARIF 2.1.0 from **Export SARIF** in the console or:

```bash
GET /v1/sast/scans/:scanId/sarif
```

False positives and live accepted risks are exported as *suppressions* with the
reviewer's reason, so other tools hide what the report hides.

A CI job can scan a build and fetch the result:

```bash
TOKEN=$(curl -s -H 'content-type: application/json' \
  -d '{"username":"admin","password":"..."}' https://kavach.example.com/v1/auth/login | jq -r .token)

SCAN=$(curl -s -H "Authorization: Bearer $TOKEN" -F artifact=@app-release.apk \
  https://kavach.example.com/v1/sast/scan | jq -r .scanId)

curl -s -H "Authorization: Bearer $TOKEN" \
  https://kavach.example.com/v1/sast/scans/$SCAN/sarif -o kavach.sarif
```

Scanning a build registers its app and carries earlier decisions forward, so a CI run
is also the next point on the app's trend.

## API

All routes need `Authorization: Bearer <token>` except those marked open. Tokens
come from `POST /v1/auth/login` and last 12 hours.

| Route | |
|---|---|
| `GET /healthz` | Open. Health, including a database check. |
| `GET /v1/auth/info`, `POST /v1/auth/login` | Open. |
| `POST /v1/auth/logout`, `GET /v1/auth/me`, `POST /v1/auth/password` | Session. |
| `GET /v1/apps`, `GET /v1/apps/:appId`, `POST /v1/apps` | Apps. |
| `GET /v1/sast/capability` | What this instance can do (full Android scan, PDF, upload limit). |
| `POST /v1/sast/scan` | Multipart upload (`artifact`, optional `appId`, `progressId`). Returns the scan. |
| `GET /v1/sast/progress/:progressId` | Stage and percent of a running scan. |
| `GET /v1/sast/scans[?appId=]` | History, newest first. |
| `GET /v1/sast/scans/:scanId` | One scan in full. `DELETE` removes it. |
| `GET /v1/sast/scans/:scanId/files`, `/search` | The original files, and code search. |
| `PUT /v1/sast/scans/:scanId/triage/:ruleId` | Record a decision. |
| `GET /v1/sast/scans/:scanId/sarif` | SARIF 2.1.0. |
| `GET /v1/sast/compare?baseline=&candidate=` | Diff of two scans of one app. |
| `POST /v1/sast/report/pdf` | Render the report as a PDF, optionally password-protected. |
| `GET /v1/audit` | The audit log. |

## Configuration and deployment

Configuration is environment variables, all optional, validated at startup with a
message that names a bad value. [`.env.example`](../.env.example) lists them with their
defaults.

[DEPLOYMENT.md](../DEPLOYMENT.md) is the guide for anything beyond your own machine:
requirements, HTTPS with Caddy or nginx (`deploy/`), the full variable reference,
capacity, security model, logs and health, backup and restore, upgrades and a
go-live checklist. [SECURITY.md](../SECURITY.md) covers reporting a vulnerability.

In short, a production start begins on the published default password unless you set
one (and says so until it is changed), limits concurrent scans and uploads, rate-limits
requests and sign-in failures, sends security headers and a restrictive
Content-Security-Policy, cleans up after itself, and shuts down gracefully, letting
running scans finish.

```bash
npm run doctor     # check this machine
npm run backup     # consistent copy of the live database
```

## Development

```bash
npm install
npm run backend    # API, with a development-only token and the admin/kavach account
npm run console    # Vite on :5174, proxying the API
npm run typecheck  # console type check
```

The backend is TypeScript run directly by Node's type stripping
(`--experimental-strip-types`), so it avoids syntax that needs a compile step, such
as constructor parameter properties. Storage is `node:sqlite`. CI
(`.github/workflows/ci.yml`) runs the tests, builds the image and smoke-tests it.

## Layout

- `backend/`: the Fastify server. `src/sast/` is the engine (the Android and iOS
  analysers, the rule catalog, secret detection, triage, comparison, SARIF and PDF
  rendering); `src/routes/` is the API; `src/` also holds configuration, limits,
  security headers, housekeeping and accounts.
- `console/`: the React app (Vite and Tailwind): Guide, Scan, Audit, and the report
  builder.
- `tools/`: `doctor` and `backup`.
- `deploy/`, `Dockerfile`, `docker-compose.yml`, `.github/`: packaging, TLS proxy
  configs and CI.

## Limits

- **One instance.** One process and one SQLite file; no clustering or high
  availability.
- **One role.** Anyone who can sign in can see and change everything.
- **Static analysis only.** The app is never run, so runtime behaviour (what is sent
  once it is live, what an obfuscated or packed app does when decrypted) is outside
  what a scan can see. Findings are leads to verify; the "How to verify" tab says how.
- **Bounded advisories.** The dependency check uses a curated list, not a live CVE
  feed, and says so in the report. Nothing is sent anywhere to look more up.
- **Secrets are in the report.** Findings quote the values they matched, so the
  database, backups and exported reports are as sensitive as the app itself.

Kavach SAST began as the static-analysis half of the larger Kavach project and runs
alongside it on different ports (backend `8788`, console `5174`).
