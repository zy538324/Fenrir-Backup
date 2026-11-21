# syntax=docker/dockerfile:1
#
# Fenrir-Backup management server.
#
#   docker build -t fenrir-server .
#   docker run -d -p 8443:8443 -v fenrir-data:/var/lib/fenrir-server fenrir-server
#
# The image contains the server, the web UI, the `fenrir-backup` CLI, the Linux
# agent for the image's own CPU architecture and the Windows agent
# (cross-compiled with MinGW; also used for Hyper-V hosts). macOS
# agents are built on a Mac (CI does this) and mounted in; see docs/DEPLOY.md.

# ---- web UI ----
FROM node:22-alpine AS ui
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/ ./
RUN npm run build

# ---- Rust binaries (static, musl) ----
FROM rust:1.97-alpine AS build
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p server -p agent -p cli \
 && case "$(uname -m)" in \
      x86_64)  triple=x86_64-unknown-linux-musl ;; \
      aarch64) triple=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;; \
    esac \
 && mkdir -p /out/agents/$triple \
 && cp target/release/fenrir-server target/release/fenrir-backup /out/ \
 && cp target/release/fenrir-backup-agent /out/agents/$triple/

# ---- Windows agent (also used on Hyper-V hosts), cross-compiled with MinGW ----
FROM ubuntu:24.04 AS windows
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates gcc gcc-mingw-w64-x86-64 libc6-dev \
 && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
COPY --from=rust:1.97-bookworm /usr/local/rustup /usr/local/rustup
COPY --from=rust:1.97-bookworm /usr/local/cargo /usr/local/cargo
RUN rustup target add x86_64-pc-windows-gnu
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p agent --target x86_64-pc-windows-gnu \
 && mkdir -p /out/agents/x86_64-pc-windows-msvc \
 && cp target/x86_64-pc-windows-gnu/release/fenrir-backup-agent.exe /out/agents/x86_64-pc-windows-msvc/

# ---- runtime ----
FROM alpine:3.22
RUN addgroup -S -g 10001 fenrir \
 && adduser -S -D -H -u 10001 -G fenrir fenrir \
 && mkdir -p /var/lib/fenrir-server \
 && chown fenrir:fenrir /var/lib/fenrir-server
COPY --from=build /out/fenrir-server /out/fenrir-backup /opt/fenrir/
COPY --from=build /out/agents /opt/fenrir/agents
COPY --from=windows /out/agents /opt/fenrir/agents
COPY --from=ui /ui/dist /opt/fenrir/ui
ENV FENRIR_DATA_DIR=/var/lib/fenrir-server \
    FENRIR_UI_DIR=/opt/fenrir/ui \
    FENRIR_AGENTS_DIR=/opt/fenrir/agents \
    FENRIR_LISTEN=0.0.0.0:8443 \
    PATH=/opt/fenrir:$PATH
VOLUME ["/var/lib/fenrir-server"]
EXPOSE 8443
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- --no-check-certificate https://127.0.0.1:8443/healthz >/dev/null 2>&1 \
   || wget -qO- http://127.0.0.1:8443/healthz >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/opt/fenrir/fenrir-server"]
