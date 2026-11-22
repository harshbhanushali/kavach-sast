#!/usr/bin/env bash
#
# Kavach SAST: install on Linux, from a checkout of this repository.
#
#   sudo ./scripts/install-linux.sh                 interactive
#   sudo ./scripts/install-linux.sh --yes --accept-android-sdk-license
#   ./scripts/install-linux.sh --help
#
# What it does:
#   1. installs the system packages a scan needs (unzip, qpdf, Chromium for PDF export);
#   2. installs pinned copies of Node.js, a JDK, apktool, jadx and apksigner under
#      /opt/kavach-tools, so nothing it needs is taken from, or changes, the system's own Node or Java;
#   3. builds the console and installs the server to /opt/kavach-sast (read-only for the service);
#   4. creates a "kavach" service user, a data directory, /etc/kavach-sast.env, and a systemd
#      service that starts on boot (or a launcher script where there is no systemd);
#   5. starts it, checks it is healthy, and checks that PDF export works for the service user.
#
# It is safe to run again: it upgrades the program and the tools and keeps your data and your
# configuration. `--uninstall` removes it (and `--purge` also the data).
#
# Supported: Debian, Ubuntu and relatives (apt), Fedora, RHEL and relatives (dnf), on x86_64 and
# aarch64. Anything else: install the tools by hand (see DEPLOYMENT.md).

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---- versions: the ones the Dockerfile pins, which are the ones the scanner is tested with --------
dockerfile_arg() {
  local value=""
  [ -r "$REPO_DIR/Dockerfile" ] && value="$(awk -F= -v key="ARG $1" '$1 == key { print $2; exit }' "$REPO_DIR/Dockerfile")"
  printf '%s' "${value:-$2}"
}
APKTOOL_VERSION="$(dockerfile_arg APKTOOL_VERSION 3.0.3)"
JADX_VERSION="$(dockerfile_arg JADX_VERSION 1.5.6)"
ANDROID_CMDLINE_TOOLS="$(dockerfile_arg ANDROID_CMDLINE_TOOLS commandlinetools-linux-11076708_latest.zip)"
ANDROID_BUILD_TOOLS="$(dockerfile_arg ANDROID_BUILD_TOOLS 34.0.0)"
NODE_MAJOR="${KAVACH_NODE_MAJOR:-26}"
JDK_MAJOR="${KAVACH_JDK_MAJOR:-21}"

# ---- defaults --------------------------------------------------------------------------------------
TOOLS=/opt/kavach-tools
PREFIX=/opt/kavach-sast
DATA_DIR=/var/lib/kavach-sast
ENV_FILE=/etc/kavach-sast.env
SERVICE_USER=kavach
UNIT=/etc/systemd/system/kavach-sast.service
LAUNCHER=/usr/local/bin/kavach-sast
PORT=8788
BIND=127.0.0.1
ADMIN_PASSWORD=""
ASSUME_YES=0
WITH_SERVICE=1
WITH_PDF=1
ACCEPT_SDK_LICENSE=0
CHROMIUM_NO_SANDBOX=0
UNINSTALL=0
PURGE=0

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m  %s\n' "$*"; }
warn() { printf '    \033[33mwarn\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Install Kavach SAST on Linux.

Usage: sudo $0 [options]

  -y, --yes                       do not ask for confirmation
      --accept-android-sdk-license
                                  accept Google's Android SDK licence, needed to fetch apksigner
                                  (https://developer.android.com/studio/terms). Without it you
                                  are asked, or apksigner is skipped when running with --yes
      --prefix DIR                install the server here               (default $PREFIX)
      --data-dir DIR              database and scans live here          (default $DATA_DIR)
      --port N                    port to listen on                     (default $PORT)
      --bind ADDRESS              address to listen on                  (default $BIND; use a
                                  TLS proxy before listening on anything wider)
      --admin-password PASSWORD   password for the first account, 10+ characters. Without it the
                                  account starts on the published default (admin / kavach)
      --no-service                do not create a systemd service
      --no-pdf                    skip Chromium (PDF export will not work)
      --chromium-no-sandbox       run Chromium without its own sandbox, for hosts where it cannot
                                  start with it (unprivileged user namespaces disabled)
      --uninstall                 remove the service, the program and the tools; keep the data
      --purge                     with --uninstall, also remove data, configuration and the user
  -h, --help                      this text
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes) ASSUME_YES=1 ;;
    --accept-android-sdk-license) ACCEPT_SDK_LICENSE=1 ;;
    --prefix) PREFIX="${2:?--prefix needs a directory}"; shift ;;
    --data-dir) DATA_DIR="${2:?--data-dir needs a directory}"; shift ;;
    --port) PORT="${2:?--port needs a number}"; shift ;;
    --bind) BIND="${2:?--bind needs an address}"; shift ;;
    --admin-password) ADMIN_PASSWORD="${2:?--admin-password needs a value}"; shift ;;
    --no-service) WITH_SERVICE=0 ;;
    --no-pdf) WITH_PDF=0 ;;
    --chromium-no-sandbox) CHROMIUM_NO_SANDBOX=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
  shift
done

[ "$(uname -s)" = Linux ] || die "this installer is for Linux. On macOS, see docs/GUIDE.md (Without Docker)."
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port must be a number from 1 to 65535"
if [ -n "$ADMIN_PASSWORD" ]; then
  [ "${#ADMIN_PASSWORD}" -ge 10 ] || die "--admin-password must be at least 10 characters"
  case "$ADMIN_PASSWORD" in *"'"*|*$'\n'*) die "--admin-password must not contain a single quote or a newline" ;; esac
fi

# ---- root --------------------------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "run this as root (sudo was not found)"
  exec sudo bash "$0" "$@"
fi

confirm() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  [ -r /dev/tty ] || die "no terminal to ask on: rerun with --yes"
  local answer
  read -r -p "$1 [y/N] " answer </dev/tty
  [[ "$answer" =~ ^[Yy] ]]
}

have_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

# ---- uninstall ---------------------------------------------------------------------------------------
if [ "$UNINSTALL" -eq 1 ]; then
  say "Removing Kavach SAST"
  confirm "Remove the service, $PREFIX and $TOOLS?" || die "cancelled"
  if have_systemd; then
    systemctl disable --now kavach-sast.service 2>/dev/null || true
    rm -f "$UNIT"; systemctl daemon-reload || true
  fi
  rm -rf "$PREFIX" "$TOOLS" "$LAUNCHER"
  if [ "$PURGE" -eq 1 ]; then
    confirm "Also delete the data in $DATA_DIR, $ENV_FILE and the '$SERVICE_USER' user? This cannot be undone." || die "cancelled"
    rm -rf "$DATA_DIR" "$ENV_FILE"
    id "$SERVICE_USER" >/dev/null 2>&1 && userdel "$SERVICE_USER" 2>/dev/null || true
  else
    ok "kept $DATA_DIR and $ENV_FILE (use --purge to remove them)"
  fi
  ok "removed"
  exit 0
fi

# ---- sanity: run from a checkout ---------------------------------------------------------------------
grep -q '"name": "kavach-sast"' "$REPO_DIR/package.json" 2>/dev/null \
  || die "run this from a checkout of the repository: $REPO_DIR is not one"

# ---- platform ----------------------------------------------------------------------------------------
# shellcheck disable=SC1091
. /etc/os-release 2>/dev/null || die "cannot read /etc/os-release"
case " ${ID:-} ${ID_LIKE:-} " in
  *" debian "*|*" ubuntu "*) PM=apt ;;
  *" fedora "*|*" rhel "*|*" centos "*) PM=dnf ;;
  *) die "unsupported distribution (${PRETTY_NAME:-unknown}). Supported: Debian/Ubuntu (apt) and Fedora/RHEL (dnf). See DEPLOYMENT.md to install by hand." ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  NODE_ARCH=x64;   JDK_ARCH=x64 ;;
  aarch64|arm64) NODE_ARCH=arm64; JDK_ARCH=aarch64 ;;
  *) die "unsupported CPU architecture: $(uname -m)" ;;
esac

cat <<EOF

Kavach SAST installer
  system        ${PRETTY_NAME:-Linux} ($(uname -m)), package manager: $PM
  tools         $TOOLS  (Node.js $NODE_MAJOR, JDK $JDK_MAJOR, apktool $APKTOOL_VERSION, jadx $JADX_VERSION, apksigner)
  program       $PREFIX
  data          $DATA_DIR
  configuration $ENV_FILE
  listens on    $BIND:$PORT   service user: $SERVICE_USER   systemd service: $([ "$WITH_SERVICE" -eq 1 ] && echo yes || echo no)

It installs system packages (unzip, qpdf$([ "$WITH_PDF" -eq 1 ] && echo ', Chromium')) and downloads about 400 MB.

EOF
confirm "Continue?" || die "cancelled"

TMP="$(mktemp -d /tmp/kavach-install.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
trap 'die "failed at line $LINENO (command: $BASH_COMMAND)"' ERR

fetch() { curl -fsSL --retry 3 --retry-delay 2 -o "$2" "$1"; }

# Runs a command with its output kept out of the way, and shown only if it fails.
quiet() {
  local log="$TMP/quiet.log"
  if ! "$@" >"$log" 2>&1; then
    echo "--- output of: $*" >&2; tail -40 "$log" >&2
    return 1
  fi
}
export NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_FUND=false NPM_CONFIG_AUDIT=false
mkdir -p "$TOOLS/bin"

# ---- 1. system packages ------------------------------------------------------------------------------
say "Installing system packages"
if [ "$PM" = apt ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends ca-certificates curl tar gzip unzip qpdf libatomic1 fonts-liberation >/dev/null
  apt-get install -y -qq --no-install-recommends fonts-noto-core >/dev/null 2>&1 || true
else
  command -v curl >/dev/null 2>&1 || dnf install -y -q --setopt=install_weak_deps=False curl >/dev/null
  dnf install -y -q --setopt=install_weak_deps=False ca-certificates tar gzip unzip qpdf libatomic liberation-fonts >/dev/null
fi
ok "unzip, qpdf and fonts"

CHROME=""
if [ "$WITH_PDF" -eq 1 ]; then
  if [ "$PM" = apt ]; then
    apt-get install -y -qq --no-install-recommends chromium >/dev/null 2>&1 \
      || apt-get install -y -qq --no-install-recommends chromium-browser >/dev/null 2>&1 || true
  else
    dnf install -y -q --setopt=install_weak_deps=False chromium >/dev/null 2>&1 || true
  fi
  for candidate in /usr/bin/chromium /usr/bin/chromium-browser /usr/bin/google-chrome /usr/bin/google-chrome-stable; do
    [ -x "$candidate" ] && CHROME="$candidate" && break
  done
  if [ -n "$CHROME" ]; then ok "Chromium: $CHROME"
  else warn "Chromium could not be installed from this distribution's repositories, so PDF export will not work. Install Chrome or Chromium and set KAVACH_CHROME in $ENV_FILE."; fi
fi

# ---- 2. Node.js ---------------------------------------------------------------------------------------
say "Node.js $NODE_MAJOR"
NODE_INDEX="https://nodejs.org/dist/latest-v${NODE_MAJOR}.x"
fetch "$NODE_INDEX/SHASUMS256.txt" "$TMP/node.sums"
NODE_FILE="$(awk -v a="linux-$NODE_ARCH.tar.gz" '$2 ~ "^node-v[0-9.]+-" a "$" { print $2; exit }' "$TMP/node.sums")"
[ -n "$NODE_FILE" ] || die "no Node.js $NODE_MAJOR build for linux-$NODE_ARCH at $NODE_INDEX"
NODE_VERSION="${NODE_FILE#node-}"; NODE_VERSION="${NODE_VERSION%%-linux*}"
if [ -x "$TOOLS/node-$NODE_VERSION/bin/node" ]; then
  ok "$NODE_VERSION already installed"
else
  fetch "$NODE_INDEX/$NODE_FILE" "$TMP/$NODE_FILE"
  (cd "$TMP" && grep " $NODE_FILE\$" node.sums | sha256sum -c --status) || die "Node.js download failed its checksum"
  tar -xzf "$TMP/$NODE_FILE" -C "$TOOLS"
  rm -rf "$TOOLS/node-$NODE_VERSION"; mv "$TOOLS/${NODE_FILE%.tar.gz}" "$TOOLS/node-$NODE_VERSION"
  ok "$NODE_VERSION (checksum verified)"
fi
ln -sfn "$TOOLS/node-$NODE_VERSION" "$TOOLS/node"
for bin in node npm npx; do ln -sfn "$TOOLS/node/bin/$bin" "$TOOLS/bin/$bin"; done
export PATH="$TOOLS/bin:$PATH"

# ---- 3. JDK -------------------------------------------------------------------------------------------
say "JDK $JDK_MAJOR (Eclipse Temurin)"
fetch "https://api.adoptium.net/v3/assets/latest/$JDK_MAJOR/hotspot?architecture=$JDK_ARCH&image_type=jdk&os=linux&vendor=eclipse" "$TMP/jdk.json"
# The API names the download and its SHA-256; Node.js, installed above, reads the JSON.
read -r JDK_LINK JDK_SUM JDK_DIR < <(node -e 'const a = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))[0]; console.log(a.binary.package.link, a.binary.package.checksum, a.release_name)' "$TMP/jdk.json")
[ -n "$JDK_LINK" ] && [ -n "$JDK_SUM" ] && [ -n "$JDK_DIR" ] || die "could not find a JDK $JDK_MAJOR build for linux-$JDK_ARCH"
if [ ! -x "$TOOLS/$JDK_DIR/bin/java" ]; then
  fetch "$JDK_LINK" "$TMP/jdk.tar.gz"
  [ "$(sha256sum "$TMP/jdk.tar.gz" | awk '{print $1}')" = "$JDK_SUM" ] || die "JDK download failed its checksum"
  [ "$({ tar -tzf "$TMP/jdk.tar.gz" || true; } | awk -F/ 'NR == 1 { print $1 }')" = "$JDK_DIR" ] || die "unexpected layout in the JDK download"
  tar -xzf "$TMP/jdk.tar.gz" -C "$TOOLS"
  ok "$JDK_DIR (checksum verified)"
else
  ok "$JDK_DIR already installed"
fi
ln -sfn "$TOOLS/$JDK_DIR" "$TOOLS/jdk"
for bin in java keytool; do ln -sfn "$TOOLS/jdk/bin/$bin" "$TOOLS/bin/$bin"; done
export JAVA_HOME="$TOOLS/jdk"
export PATH="$TOOLS/bin:$PATH"

# ---- 4. apktool ---------------------------------------------------------------------------------------
say "apktool $APKTOOL_VERSION"
mkdir -p "$TOOLS/apktool"
if [ "$(cat "$TOOLS/apktool/.version" 2>/dev/null)" != "$APKTOOL_VERSION" ]; then
  fetch "https://raw.githubusercontent.com/iBotPeaches/Apktool/v$APKTOOL_VERSION/scripts/linux/apktool" "$TOOLS/apktool/apktool"
  fetch "https://github.com/iBotPeaches/Apktool/releases/download/v$APKTOOL_VERSION/apktool_$APKTOOL_VERSION.jar" "$TOOLS/apktool/apktool.jar"
  chmod +x "$TOOLS/apktool/apktool"
  echo "$APKTOOL_VERSION" > "$TOOLS/apktool/.version"
fi
ln -sfn "$TOOLS/apktool/apktool" "$TOOLS/bin/apktool"
apktool version >/dev/null 2>&1 || die "apktool did not run"
ok "$(apktool version 2>/dev/null | head -1)"

# ---- 5. jadx ------------------------------------------------------------------------------------------
say "jadx $JADX_VERSION"
if [ ! -x "$TOOLS/jadx-$JADX_VERSION/bin/jadx" ]; then
  fetch "https://github.com/skylot/jadx/releases/download/v$JADX_VERSION/jadx-$JADX_VERSION.zip" "$TMP/jadx.zip"
  rm -rf "$TOOLS/jadx-$JADX_VERSION"; mkdir -p "$TOOLS/jadx-$JADX_VERSION"
  unzip -q "$TMP/jadx.zip" -d "$TOOLS/jadx-$JADX_VERSION"
  chmod +x "$TOOLS/jadx-$JADX_VERSION/bin/jadx"
fi
ln -sfn "$TOOLS/jadx-$JADX_VERSION" "$TOOLS/jadx"
ln -sfn "$TOOLS/jadx/bin/jadx" "$TOOLS/bin/jadx"
jadx --version >/dev/null 2>&1 || die "jadx did not run"
ok "$(jadx --version 2>/dev/null | head -1)"

# ---- 6. apksigner -------------------------------------------------------------------------------------
say "apksigner (Android build-tools $ANDROID_BUILD_TOOLS)"
if [ -x "$TOOLS/apksigner/apksigner" ]; then
  ln -sfn "$TOOLS/apksigner/apksigner" "$TOOLS/bin/apksigner"
  ok "already installed"
else
  if [ "$ACCEPT_SDK_LICENSE" -ne 1 ]; then
    cat <<EOF
    apksigner comes from Google's Android build-tools, which are distributed under the Android
    Software Development Kit License Agreement: https://developer.android.com/studio/terms
    Only apksigner and its jar are kept; the rest of the SDK is discarded.
EOF
    if [ "$ASSUME_YES" -eq 1 ] || ! confirm "    Accept the licence and install apksigner?"; then
      warn "apksigner skipped: signing schemes will be reported as present rather than verified. Rerun with --accept-android-sdk-license to add it."
      ACCEPT_SDK_LICENSE=0
    else
      ACCEPT_SDK_LICENSE=1
    fi
  fi
  if [ "$ACCEPT_SDK_LICENSE" -eq 1 ]; then
    SDK="$TMP/sdk"; mkdir -p "$SDK/cmdline-tools"
    fetch "https://dl.google.com/android/repository/$ANDROID_CMDLINE_TOOLS" "$TMP/cmdline-tools.zip"
    unzip -q "$TMP/cmdline-tools.zip" -d "$SDK/cmdline-tools"
    mv "$SDK/cmdline-tools/cmdline-tools" "$SDK/cmdline-tools/latest"
    SDKMANAGER="$SDK/cmdline-tools/latest/bin/sdkmanager"
    printf 'y\n%.0s' $(seq 1 60) | "$SDKMANAGER" --sdk_root="$SDK" --licenses >/dev/null 2>&1 || true
    quiet "$SDKMANAGER" --sdk_root="$SDK" --install "build-tools;$ANDROID_BUILD_TOOLS"
    mkdir -p "$TOOLS/apksigner/lib"
    cp "$SDK/build-tools/$ANDROID_BUILD_TOOLS/apksigner" "$TOOLS/apksigner/apksigner"
    cp "$SDK/build-tools/$ANDROID_BUILD_TOOLS/lib/apksigner.jar" "$TOOLS/apksigner/lib/apksigner.jar"
    ln -sfn "$TOOLS/apksigner/apksigner" "$TOOLS/bin/apksigner"
    apksigner --version >/dev/null 2>&1 || die "apksigner did not run"
    ok "apksigner $(apksigner --version 2>/dev/null | head -1)"
  fi
fi

# ---- 7. build and install the program ---------------------------------------------------------------
say "Building Kavach SAST"
STAGE="$TMP/stage"; mkdir -p "$STAGE"
tar -C "$REPO_DIR" --exclude=node_modules --exclude=.git --exclude=console/dist --exclude=backend/data \
    --exclude=docs -cf - . | tar -C "$STAGE" -xf -
quiet bash -c "cd '$STAGE' && npm ci --loglevel=error && npm run build"
[ -f "$STAGE/console/dist/index.html" ] || die "the console did not build"
ok "console built"

say "Installing to $PREFIX"
have_systemd && systemctl stop kavach-sast.service 2>/dev/null || true
NEW="$PREFIX.new"; rm -rf "$NEW"; mkdir -p "$NEW/console" "$NEW/backend"
cp "$STAGE/package.json" "$STAGE/package-lock.json" "$NEW/"
cp "$STAGE/backend/package.json" "$NEW/backend/"
cp "$STAGE/console/package.json" "$NEW/console/"
quiet bash -c "cd '$NEW' && npm ci --omit=dev --workspace=kavach-sast-backend --loglevel=error"
cp -R "$STAGE/backend/src" "$NEW/backend/src"
cp -R "$STAGE/console/dist" "$NEW/console/dist"
cp -R "$STAGE/tools" "$NEW/tools"
for f in LICENSE NOTICE; do [ -f "$STAGE/$f" ] && cp "$STAGE/$f" "$NEW/"; done
chown -R root:root "$NEW"; chmod -R go-w "$NEW"
rm -rf "$PREFIX"; mv "$NEW" "$PREFIX"
ok "installed"

# ---- 8. user, data, configuration --------------------------------------------------------------------
say "Service user, data and configuration"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
  useradd --system --home-dir "$DATA_DIR" --no-create-home --shell "$NOLOGIN" "$SERVICE_USER"
  ok "created user '$SERVICE_USER'"
fi
mkdir -p "$DATA_DIR"
chown "$SERVICE_USER":"$(id -gn "$SERVICE_USER")" "$DATA_DIR"; chmod 750 "$DATA_DIR"

if [ -e "$ENV_FILE" ]; then
  ok "kept your existing $ENV_FILE (edit it to change settings; port, bind and password options were not applied)"
  # shellcheck disable=SC1090
  PORT="$( (set -a; . "$ENV_FILE"; echo "${PORT:-8788}") )"
else
  {
    echo "# Kavach SAST configuration. Written by scripts/install-linux.sh; edit freely, then:"
    echo "#   sudo systemctl restart kavach-sast"
    echo "# Every setting is explained in .env.example and DEPLOYMENT.md."
    echo "NODE_ENV=production"
    echo "HOST=$BIND"
    echo "PORT=$PORT"
    echo "KAVACH_SAST_DB_PATH=$DATA_DIR/kavach-sast.db"
    echo "JAVA_HOME=$TOOLS/jdk"
    echo "PATH=$TOOLS/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    [ -n "$CHROME" ] && echo "KAVACH_CHROME=$CHROME"
    [ "$CHROMIUM_NO_SANDBOX" -eq 1 ] && echo "KAVACH_CHROME_NO_SANDBOX=1"
    if [ -n "$ADMIN_PASSWORD" ]; then echo "KAVACH_SAST_ADMIN_PASSWORD='$ADMIN_PASSWORD'"
    else echo "# KAVACH_SAST_ADMIN_PASSWORD=   (unset: the first account starts on the published default, admin / kavach)"; fi
    echo "# KAVACH_SAST_MAX_SCANS=2"
    echo "# KAVACH_SAST_SCAN_TIMEOUT_SEC=900"
    echo "# KAVACH_SAST_RETENTION_DAYS=0"
  } > "$ENV_FILE"
  chown root:"$(id -gn "$SERVICE_USER")" "$ENV_FILE"; chmod 640 "$ENV_FILE"
  ok "wrote $ENV_FILE"
fi

# A launcher for hosts without systemd, and for running it by hand.
cat > "$LAUNCHER" <<EOF
#!/bin/sh
# Starts Kavach SAST in the foreground with the settings in $ENV_FILE. Run it as the service user:
#   sudo -u $SERVICE_USER kavach-sast
set -a
. $ENV_FILE
set +a
cd $PREFIX
exec $TOOLS/node/bin/node --experimental-strip-types backend/src/server.ts
EOF
chmod 755 "$LAUNCHER"

# ---- 9. service ---------------------------------------------------------------------------------------
BASE_URL="http://127.0.0.1:$PORT"
STARTED=0
if [ "$WITH_SERVICE" -eq 1 ] && have_systemd; then
  say "systemd service"
  cat > "$UNIT" <<EOF
[Unit]
Description=Kavach SAST
After=network.target

[Service]
User=$SERVICE_USER
WorkingDirectory=$PREFIX
EnvironmentFile=$ENV_FILE
ExecStart=$TOOLS/node/bin/node --experimental-strip-types backend/src/server.ts
Restart=on-failure
RestartSec=3
# Longer than KAVACH_SAST_SHUTDOWN_GRACE_SEC, so a running scan can finish when it is stopped.
TimeoutStopSec=90
LimitNOFILE=65536
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR
# Scans stage a decompiled copy of the app here; a private directory is removed on every stop.
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now kavach-sast.service >/dev/null 2>&1
  STARTED=1
elif [ "$WITH_SERVICE" -eq 1 ]; then
  warn "systemd is not running here, so no service was created. Start it with: sudo -u $SERVICE_USER kavach-sast"
fi

if [ "$STARTED" -eq 1 ]; then
  say "Waiting for it to start"
  healthy=0
  for _ in $(seq 1 40); do
    if curl -fsS "$BASE_URL/healthz" >/dev/null 2>&1; then healthy=1; break; fi
    sleep 1
  done
  if [ "$healthy" -eq 1 ]; then ok "healthy at $BASE_URL"
  else die "the service did not become healthy. See: journalctl -u kavach-sast -n 50 --no-pager"; fi
fi

# ---- 10. checks ---------------------------------------------------------------------------------------
say "Checks"
as_service() { runuser -u "$SERVICE_USER" -- "$@"; }
if [ -n "$CHROME" ]; then
  PDF_DIR="$(mktemp -d /tmp/kavach-pdfcheck.XXXXXX)"; chown "$SERVICE_USER" "$PDF_DIR"
  echo '<html><body><h1>Kavach SAST</h1><p>PDF export check</p></body></html>' > "$PDF_DIR/in.html"; chmod 644 "$PDF_DIR/in.html"
  CHROME_ARGS=(--headless=new --disable-gpu --no-first-run --user-data-dir="$PDF_DIR/profile" --print-to-pdf="$PDF_DIR/out.pdf")
  [ "$CHROMIUM_NO_SANDBOX" -eq 1 ] && CHROME_ARGS+=(--no-sandbox)
  as_service env HOME="$PDF_DIR" timeout 60 "$CHROME" "${CHROME_ARGS[@]}" "file://$PDF_DIR/in.html" >/dev/null 2>&1 || true
  if [ -s "$PDF_DIR/out.pdf" ]; then ok "PDF export works for the '$SERVICE_USER' user"
  else
    warn "Chromium could not render a PDF as the '$SERVICE_USER' user. This usually means unprivileged user namespaces are"
    warn "disabled (Ubuntu 24.04 restricts them). Enable them, or rerun with --chromium-no-sandbox to run Chromium"
    warn "without its own sandbox (the report HTML is sanitised and name resolution is disabled). Everything else works."
    warn "On Ubuntu, Chromium is a snap, which often cannot run for a system user: install Google Chrome's .deb instead and set KAVACH_CHROME in $ENV_FILE."
  fi
  rm -rf "$PDF_DIR"
fi
DOCTOR="$(as_service env -i PATH="$TOOLS/bin:/usr/bin:/bin" JAVA_HOME="$TOOLS/jdk" KAVACH_SAST_DB_PATH="$DATA_DIR/kavach-sast.db" \
  NODE_ENV=production sh -c "cd '$PREFIX' && node --experimental-strip-types tools/doctor.ts" 2>&1 || true)"
echo "$DOCTOR" | grep -E '\[ fail \]|blockers' | sed 's/^/    /' || true

# ---- done ---------------------------------------------------------------------------------------------
echo
say "Done"
if [ "$STARTED" -eq 1 ]; then
  echo "    Open  $BASE_URL"
else
  echo "    Start it:  sudo -u $SERVICE_USER kavach-sast      (then open $BASE_URL)"
fi
if [ -n "$ADMIN_PASSWORD" ]; then
  echo "    Sign in as  admin  with the password you gave."
else
  echo "    Sign in as  admin / kavach  (the published default), then change it from the account menu."
fi
echo "    Logs:      journalctl -u kavach-sast -f"
echo "    Settings:  $ENV_FILE   (restart after editing: sudo systemctl restart kavach-sast)"
echo "    Data:      $DATA_DIR   (back it up; see DEPLOYMENT.md)"
echo "    Upgrade:   pull the new version, run this script again"
echo "    Remove:    sudo $0 --uninstall [--purge]"
if [ "$BIND" != 127.0.0.1 ]; then
  echo
  warn "it listens on $BIND. Put a TLS proxy in front and change the default password before exposing it (DEPLOYMENT.md)."
fi
