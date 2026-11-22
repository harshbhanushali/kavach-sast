# syntax=docker/dockerfile:1
#
# Kavach SAST in one image, on one port.
#
# Everything the scanner shells out to is a JVM program (apktool, apksigner,
# jadx) or a plain Debian package (Chromium for PDF export, qpdf for password
# protection), so this image builds and runs natively on amd64 and arm64 alike.
# No emulation is needed on Apple Silicon.

ARG NODE_IMAGE=node:26-bookworm-slim
ARG JDK_IMAGE=eclipse-temurin:21-jdk

# Pinned so an image built next year is the image built today.
ARG APKTOOL_VERSION=3.0.3
ARG JADX_VERSION=1.5.6
ARG ANDROID_CMDLINE_TOOLS=commandlinetools-linux-11076708_latest.zip
ARG ANDROID_BUILD_TOOLS=34.0.0


# =============================================================================
# The JDK, taken from Temurin rather than Debian, which ships 17 on bookworm.
# =============================================================================
FROM ${JDK_IMAGE} AS jdk


# =============================================================================
# Production dependencies of the backend only.
# =============================================================================
FROM ${NODE_IMAGE} AS deps
WORKDIR /src
# Only the manifests, so this layer is cached until a dependency changes
# rather than on every source edit.
COPY package.json package-lock.json ./
COPY backend/package.json backend/
COPY console/package.json console/
RUN npm ci --omit=dev --workspace=kavach-sast-backend


# =============================================================================
# The console, built to static files the backend serves.
# =============================================================================
FROM ${NODE_IMAGE} AS console
WORKDIR /src
COPY package.json package-lock.json ./
COPY backend/package.json backend/
COPY console/package.json console/
RUN npm ci
COPY console ./console
RUN npm run build --workspace=kavach-sast-console


# =============================================================================
# apksigner, from Google's build-tools. It is a shell script around a jar, so
# unlike zipalign/aapt2 it is architecture independent. Only those two files
# are kept; the SDK that delivered them is thrown away with this stage.
# =============================================================================
FROM ${JDK_IMAGE} AS apksigner
ARG ANDROID_CMDLINE_TOOLS
ARG ANDROID_BUILD_TOOLS

ENV ANDROID_HOME=/opt/android-sdk
ENV PATH=${ANDROID_HOME}/cmdline-tools/latest/bin:${PATH}

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p ${ANDROID_HOME}/cmdline-tools \
 && curl -fsSL -o /tmp/tools.zip "https://dl.google.com/android/repository/${ANDROID_CMDLINE_TOOLS}" \
 && unzip -q /tmp/tools.zip -d ${ANDROID_HOME}/cmdline-tools \
 && mv ${ANDROID_HOME}/cmdline-tools/cmdline-tools ${ANDROID_HOME}/cmdline-tools/latest \
 && rm /tmp/tools.zip \
 && yes | sdkmanager --licenses > /dev/null \
 && sdkmanager --install "build-tools;${ANDROID_BUILD_TOOLS}" > /dev/null \
 && mkdir -p /opt/apksigner/lib \
 && cp ${ANDROID_HOME}/build-tools/${ANDROID_BUILD_TOOLS}/apksigner /opt/apksigner/apksigner \
 && cp ${ANDROID_HOME}/build-tools/${ANDROID_BUILD_TOOLS}/lib/apksigner.jar /opt/apksigner/lib/apksigner.jar


# =============================================================================
# Runtime.
# =============================================================================
FROM ${NODE_IMAGE} AS runtime
ARG APKTOOL_VERSION
ARG JADX_VERSION

COPY --from=jdk /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH=${JAVA_HOME}/bin:/opt/apksigner:${PATH}

COPY --from=apksigner /opt/apksigner /opt/apksigner

# chromium + fonts: PDF export. qpdf: password-protected PDFs.
# apktool and jadx are both JVM programs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl unzip ca-certificates chromium qpdf fonts-liberation fonts-noto-core \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL -o /usr/local/bin/apktool \
      https://raw.githubusercontent.com/iBotPeaches/Apktool/v${APKTOOL_VERSION}/scripts/linux/apktool \
 && curl -fsSL -o /usr/local/bin/apktool.jar \
      https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar \
 && chmod +x /usr/local/bin/apktool /usr/local/bin/apktool.jar \
 && curl -fsSL -o /tmp/jadx.zip \
      https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip \
 && mkdir -p /opt/jadx \
 && unzip -q /tmp/jadx.zip -d /opt/jadx \
 && rm /tmp/jadx.zip \
 && chmod +x /opt/jadx/bin/jadx \
 && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

# Chromium's own sandbox needs user namespaces, which Docker's default seccomp
# profile blocks, so as a non-root user it refuses to start. The container is
# the sandbox instead (non-root user, no capabilities, no-new-privileges: see
# docker-compose.yml), and Chromium is told so here. The report it renders is
# sanitised and name resolution is disabled (backend/src/sast/pdf.ts).
RUN printf '#!/bin/sh\nexec /usr/bin/chromium --no-sandbox --disable-dev-shm-usage "$@"\n' \
      > /usr/local/bin/kavach-chromium \
 && chmod +x /usr/local/bin/kavach-chromium

# Fail the build, not the first upload, if a tool did not land where the
# scanner will look for it.
RUN java -version 2>&1 | head -1 && apktool version && jadx --version && apksigner --version && qpdf --version | head -1

WORKDIR /app
COPY --from=deps    /src/node_modules ./node_modules
COPY --from=console /src/console/dist ./console/dist
COPY package.json LICENSE NOTICE ./
COPY backend ./backend
COPY tools ./tools

LABEL org.opencontainers.image.title="Kavach SAST" \
      org.opencontainers.image.description="Static analysis for Android and iOS apps, with a report you can hand over." \
      org.opencontainers.image.source="https://github.com/harshbhanushali/kavach-sast" \
      org.opencontainers.image.licenses="Apache-2.0"

# HOST matters: the default is 127.0.0.1, which inside a container means
# "reachable by nothing". NODE_ENV=production also turns off the static
# development token, so the only way in is a real sign-in.
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8788 \
    KAVACH_SAST_DB_PATH=/data/kavach-sast.db \
    KAVACH_SAST_CONSOLE_DIR=/app/console/dist \
    KAVACH_CHROME=/usr/local/bin/kavach-chromium

RUN mkdir -p /data && chown -R node:node /data /app
USER node
VOLUME /data
EXPOSE 8788

# Reports whether the scanner is actually ready, not merely that the process is up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8788)+'/healthz').then(r=>r.json()).then(h=>process.exit(h.ok&&h.scanning&&h.scanning.ready?0:1)).catch(()=>process.exit(1))"

# SIGTERM is the signal docker stop sends; the server finishes running scans before exiting.
STOPSIGNAL SIGTERM

CMD ["node", "--experimental-strip-types", "/app/backend/src/server.ts"]
