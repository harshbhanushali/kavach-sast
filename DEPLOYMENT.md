# Deploying Kavach SAST

One server process, one SQLite file, one port. This guide takes you from a clean
machine to a deployment you can leave running, and says plainly what it does not
do.

- [What you are deploying](#what-you-are-deploying)
- [Requirements](#requirements)
- [Quick start (Docker)](#quick-start-docker)
- [HTTPS and exposure](#https-and-exposure)
- [Configuration reference](#configuration-reference)
- [Security model](#security-model)
- [Capacity and limits](#capacity-and-limits)
- [Operating it](#operating-it): logs, health, backup and restore, upgrades, shutdown
- [Without Docker](#without-docker)
- [Go-live checklist](#go-live-checklist)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)

## What you are deploying

A Node.js server that serves the console and the API on one port, and runs scans
in worker threads. Uploaded artifacts are analysed and deleted; what is kept is
the findings and the decompiled sources they point at, in a SQLite file. There is
no external service, no outbound request, and nothing to configure beyond the
variables below.

It is a **single instance**: there is no clustering, and the database is a local
file. That is the right size for a team's security review, and it is the limit.

## Requirements

| | Minimum | Comfortable |
|---|---|---|
| CPU | 2 cores | 4 cores |
| Memory | 4 GB | 8 GB (large apps decompile to several GB) |
| Disk | 20 GB | 50 GB+ (scratch space for scans, plus the database) |
| Docker | Compose v2.24 or newer | |

The image runs on amd64 and arm64. Without Docker you also need Node.js 22.6+
(26 is what the image uses), a JDK 21, `apktool`, `apksigner` and `jadx` for
Android, and optionally Chrome/Chromium and `qpdf` for PDF export. `npm run
doctor` checks all of it.

## Quick start (Docker)

```bash
cp .env.example .env            # optional: set KAVACH_SAST_ADMIN_PASSWORD, limits, proxy
docker compose up -d --build
```

Open `http://localhost:8788`, sign in as `admin` / `kavach` (the published default),
and change the password from the account menu. Then verify the install:

```bash
docker compose exec kavach-sast npm run doctor
```

On first start the database is empty, so Kavach creates the `admin` account. If
`KAVACH_SAST_ADMIN_PASSWORD` is set (10+ characters) that is its password. If not, it
starts on the published default, `admin` / `kavach`, so a first run needs no setup.
**That password is public: it is in this repository.** The console shows a warning
until it is changed, the login page names it only while it is still active, and the
server logs a warning at every start. Change it before the instance is reachable by
anyone you do not trust. Setting `KAVACH_SAST_ADMIN_PASSWORD` later rotates an account
still on the default to that password at startup.

## HTTPS and exposure

By default the port is published on `127.0.0.1` only. Do not publish it to a
network as it is: sign-in credentials and reports would cross it in clear text.
Put a TLS proxy in front.

**Caddy (automatic certificates), included:**

```bash
# .env
KAVACH_SAST_TRUST_PROXY=1
KAVACH_SAST_HSTS=true
# edit the host name in deploy/Caddyfile, then:
docker compose -f docker-compose.yml -f deploy/docker-compose.proxy.yml up -d --build
```

Ports 80 and 443 must reach the machine. Kavach itself is then unpublished: only
the proxy can reach it.

**nginx:** see `deploy/nginx.conf.example`. The settings that matter are no
request buffering (uploads are large), long read timeouts (a scan holds its
request open), and forwarding `X-Forwarded-For` / `X-Forwarded-Proto`.

**`KAVACH_SAST_TRUST_PROXY`** must match the number of proxies in front. Left at 0
behind a proxy, every client looks like the proxy and rate limits apply to
everyone at once; set too high, a client can forge its own address.

## Configuration reference

All optional. Invalid values stop the server at startup with a message naming the
variable.

| Variable | Default | Meaning |
|---|---|---|
| `KAVACH_SAST_ADMIN_PASSWORD` | `kavach` (published default) | First administrator's password, used when the database is empty. 10+ characters. An account still on the default takes it at startup. |
| `PORT` | `8788` | Listen port. |
| `HOST` | `127.0.0.1` (`0.0.0.0` in the image) | Listen address. |
| `KAVACH_SAST_DB_PATH` | `backend/data/kavach-sast.db` (`/data/kavach-sast.db` in the image) | The database file. |
| `KAVACH_SAST_TRUST_PROXY` | `0` | Proxies in front (`1`-`10`), or `true` to trust the whole chain. |
| `KAVACH_SAST_HSTS` | `false` | Send `Strict-Transport-Security`. Set when served over HTTPS. |
| `KAVACH_SAST_MAX_SCANS` | `2` | Scans running at once. |
| `KAVACH_SAST_MAX_QUEUE` | `4` | Scans allowed to wait; beyond that, uploads are refused with `503` and `Retry-After`. |
| `KAVACH_SAST_SCAN_TIMEOUT_SEC` | `900` | A scan not finished by then is stopped. |
| `KAVACH_SAST_REQUESTS_PER_MINUTE` | `600` | API requests per client address per minute. |
| `KAVACH_SAST_LOGIN_FAILURES` | `20` | Failed sign-ins per address in five minutes before further attempts are refused. |
| `KAVACH_SAST_RETENTION_DAYS` | `0` | Delete scans older than this many days (`0` keeps them). |
| `KAVACH_SAST_SHUTDOWN_GRACE_SEC` | `60` | How long running scans get to finish after SIGTERM. |
| `KAVACH_SAST_LOG_LEVEL` | `info` | Log level in production. |
| `KAVACH_CHROME`, `KAVACH_QPDF` | auto | Paths to Chrome and `qpdf`, if not on the usual path. |
| `KAVACH_CHROME_NO_SANDBOX` | unset | `1` runs Chromium without its sandbox, for a host where it cannot start with one. Root always does. |

## Security model

What the deployment does for you, so you know what you are relying on.

**Accounts.** One role, one seeded account, on the published default until changed. Passwords are scrypt-hashed with a
per-password salt; sessions are random tokens held server-side and expire after
12 hours; changing a password ends every session for that account. A new password
must be at least 10 characters and not a published default.

**Brute force.** Sign-in failures are counted per username *and* per client
address, so changing the username does not reset the count. Lockouts are temporary (a few
minutes), so someone who knows the account name can delay a sign-in but not block it
for good. Failed sign-ins are written
to the audit log. All limits are in memory and reset on restart.

**Browser.** Every response carries `X-Content-Type-Options`, `X-Frame-Options:
DENY`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy` and
cross-origin isolation headers. The console is served with a Content-Security-Policy
that allows only its own origin (no inline script, no framing, no third-party
requests: the typefaces are bundled). API responses are `no-store`.

**Data.** Uploaded artifacts are streamed to a temporary directory and deleted when
the scan ends; working directories left by a crash are removed at startup and
hourly. What is kept is the report, the decompiled sources it references, triage
decisions and the audit log. Treat the database and every backup like the apps it
describes, and set `KAVACH_SAST_RETENTION_DAYS` if you do not need history.

**Container.** Runs as a non-root user with all capabilities dropped,
`no-new-privileges`, and memory and process limits.

**Not provided:** single sign-on, multiple roles, encryption of the database at
rest (use an encrypted volume), or a web application firewall.

## Capacity and limits

A scan decompiles an app into memory and onto disk, and a large one (a 180 MB
React Native app) needs several GB of each. `KAVACH_SAST_MAX_SCANS` is the knob:
raise it only with the memory to match, and raise `KAVACH_SAST_MEMORY_LIMIT` (the
container's cap, default 6 GB) with it. When the queue is full an upload is
refused *before* it is read, with `503` and `Retry-After`, so a busy server does
not first receive 600 MB. Uploads are limited to 600 MB.

## Operating it

**Logs.** JSON lines on stdout (`docker compose logs -f`), with request ids and
the `Authorization` header redacted, rotated by the compose file (5 x 20 MB).

**Health.** `GET /healthz` returns `200` with `{"ok":true,...}` when the database
answers and `503` otherwise. It is exempt from rate limiting. The image's
`HEALTHCHECK` uses it.

**Doctor.** `npm run doctor` (or `docker compose exec kavach-sast npm run doctor`)
checks the Node version, SQLite, configuration, data directory, free disk, the
port, and every tool a scan uses. It exits non-zero only for blockers.

**Backup.** Do not copy the `.db` file while the server runs: a half-written WAL
gives a corrupt backup. Use the built-in command, which takes a consistent copy
from the live database without stopping it and checks the copy:

```bash
docker compose exec kavach-sast npm run backup -- /data/backups
docker compose cp kavach-sast:/data/backups ./backups      # get it off the host
```

Schedule it (cron, a systemd timer) and keep copies somewhere else.

**Restore.**

```bash
docker compose down
docker run --rm -v kavach-sast_kavach-sast-data:/data -v "$PWD/backups:/backups" alpine \
  sh -c 'cp /backups/kavach-sast-<timestamp>.db /data/kavach-sast.db && rm -f /data/kavach-sast.db-wal /data/kavach-sast.db-shm'
docker compose up -d
```

The accounts and passwords come back with the data; no password is regenerated.

**Upgrade.** `git pull`, then `docker compose up -d --build`. Schema changes are
applied automatically at startup and are additive. Take a backup first. To roll
back, deploy the previous version and restore the backup.

**Shutdown.** `docker compose stop` sends SIGTERM: the server stops taking
requests, lets running scans finish (up to `KAVACH_SAST_SHUTDOWN_GRACE_SEC`),
checkpoints the database and exits `0`. The compose file's `stop_grace_period` is
longer than that, so Docker does not kill it first.

**Housekeeping** runs at startup and hourly: stale working directories, expired
sessions, scans past retention.

## Without Docker

### The install script (Linux)

On Debian, Ubuntu, Fedora, RHEL and relatives, `scripts/install-linux.sh` does all of the following
for you, and is the way to do it:

```bash
sudo ./scripts/install-linux.sh            # asks before it changes anything
sudo ./scripts/install-linux.sh --yes --accept-android-sdk-license --admin-password '...'
```

- Installs `unzip`, `qpdf` and Chromium with the system package manager.
- Installs pinned copies of Node.js, a JDK, apktool, jadx and apksigner under `/opt/kavach-tools`
  (the versions the Dockerfile pins). It does not touch the system's own Node or Java. Node.js and the
  JDK are checked against their published checksums.
- Builds the console and installs the server to `/opt/kavach-sast`, owned by root and read-only for the
  service.
- Creates the `kavach` system user, `/var/lib/kavach-sast` for the data, `/etc/kavach-sast.env` for
  settings (mode 640) and a hardened `kavach-sast.service` that starts on boot.
- Starts it, waits for `/healthz`, and renders a test PDF as the service user.

Run it again to upgrade: the program and tools are replaced, the data and `/etc/kavach-sast.env` are
kept. `--uninstall` removes the program, tools and service, and keeps the data unless you add `--purge`.
Where there is no systemd (a container, WSL), it installs a launcher instead:
`sudo -u kavach kavach-sast`.

apksigner is taken from Google's Android build-tools, which carry Google's SDK licence. The script
shows it and asks you to accept (or pass `--accept-android-sdk-license`); without that, apksigner is
skipped and signing schemes are reported as present rather than verified.

If the PDF check fails, Chromium cannot start with its sandbox as an unprivileged user (typical when
unprivileged user namespaces are disabled, as Ubuntu 24.04 does by default for some setups). Enable
them, or rerun with `--chromium-no-sandbox`, which sets `KAVACH_CHROME_NO_SANDBOX=1`. The report HTML
is sanitised and name resolution is switched off, but prefer fixing the host. Everything except PDF
export works either way.

### By hand

```bash
npm ci && npm run build
NODE_ENV=production KAVACH_SAST_ADMIN_PASSWORD=... npm start
```

A systemd unit, if you prefer to write your own:

```ini
[Unit]
Description=Kavach SAST
After=network.target

[Service]
User=kavach
WorkingDirectory=/opt/kavach-sast
Environment=NODE_ENV=production
EnvironmentFile=/etc/kavach-sast.env
ExecStart=/usr/bin/node --experimental-strip-types backend/src/server.ts
Restart=on-failure
TimeoutStopSec=90
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/kavach-sast /tmp
PrivateTmp=false

[Install]
WantedBy=multi-user.target
```

with `KAVACH_SAST_DB_PATH=/var/lib/kavach-sast/kavach-sast.db` in the env file.

## Go-live checklist

- [ ] Served over HTTPS (proxy), with `KAVACH_SAST_TRUST_PROXY` and `KAVACH_SAST_HSTS` set.
- [ ] The container port is not published to the network (only the proxy is).
- [ ] The administrator password is changed from the published default (`kavach`), and stored in a password manager.
- [ ] `docker compose exec kavach-sast npm run doctor` reports no blockers.
- [ ] A backup has been taken **and a restore has been tried** on a spare machine.
- [ ] Backups are scheduled and stored off this host.
- [ ] `KAVACH_SAST_MAX_SCANS` and the memory limit match the machine.
- [ ] Retention is decided (`KAVACH_SAST_RETENTION_DAYS`).
- [ ] The data volume is on an encrypted disk, if the apps are sensitive.
- [ ] Someone watches the logs, or `/healthz`.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| "configuration error: ... must be ..." at start | An environment variable has an invalid value; the message names it. |
| Everyone gets `429` | Behind a proxy without `KAVACH_SAST_TRUST_PROXY=1`: all clients share the proxy's address. |
| Upload fails at the proxy | The proxy's body limit or timeout is too low; see `deploy/`. |
| `503 ... busy with other scans` | `KAVACH_SAST_MAX_SCANS` scans are running and the queue is full. Retry, or raise the limits with the memory to match. |
| A scan is killed or "worker exited with code" | Out of memory. Raise `KAVACH_SAST_MEMORY_LIMIT`, or lower `KAVACH_SAST_MAX_SCANS`. |
| "the scan took too long" | Raise `KAVACH_SAST_SCAN_TIMEOUT_SEC`, or the artifact is unusually large. |
| "the database failed its integrity check" | Restore from a backup (above). |
| Lost the admin password | If the database is new, delete the volume and start again (the account is back on the default); otherwise restore a backup, or reset by removing the `admin` row with `sqlite3` and restarting: the account is re-created on the default, or on `KAVACH_SAST_ADMIN_PASSWORD` if set. |
| Scans are thin, or PDF export is unavailable | `npm run doctor` says which component is missing. |

## Limitations

- One instance; no high availability. The database is a local SQLite file.
- One role. Everyone who can sign in can see and change everything.
- Rate limits and lockouts are in memory and reset on restart.
- The Docker image is built and tested by CI (`.github/workflows/ci.yml`). Build it
  in your own environment once before relying on it, and run `npm run doctor` in it.
