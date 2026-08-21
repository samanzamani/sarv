#!/usr/bin/env bash
# Sarv installer — builds/installs the binary, config, and systemd service.
set -euo pipefail

PREFIX=/usr/local/bin
CONFDIR=/etc/sarv
DATADIR=/var/lib/sarv

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

echo "==> Installing sarv"
if [[ -f ./sarv ]]; then
  install -m 0755 ./sarv "$PREFIX/sarv"
elif command -v go >/dev/null; then
  echo "    building from source"
  CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo dev)" -o "$PREFIX/sarv" ./cmd/sarv
else
  echo "No ./sarv binary and no Go toolchain found." >&2
  exit 1
fi

mkdir -p "$CONFDIR/rules.d" "$DATADIR"
chmod 750 "$DATADIR"

if [[ ! -f "$CONFDIR/config.yml" ]]; then
  echo "==> Writing default config to $CONFDIR/config.yml"
  cp "$(dirname "$0")/config.example.yml" "$CONFDIR/config.yml"
  chmod 600 "$CONFDIR/config.yml"
else
  echo "==> Keeping existing $CONFDIR/config.yml"
fi

# Increase inotify watch limit for large web roots (realtime monitoring).
if ! grep -q "fs.inotify.max_user_watches=1048576" /etc/sysctl.conf 2>/dev/null; then
  echo "==> Raising fs.inotify.max_user_watches to 1048576"
  echo "fs.inotify.max_user_watches=1048576" >> /etc/sysctl.conf
  sysctl -p >/dev/null || true
fi

echo "==> Installing systemd service"
install -m 0644 "$(dirname "$0")/sarv.service" /etc/systemd/system/sarv.service
systemctl daemon-reload

cat <<EOF

Sarv installed.

Next steps:
  1. Edit $CONFDIR/config.yml (scan paths, Telegram token/chat/proxy).
  2. (optional) Set a web panel password:   sarv web set-password
  3. Do an initial baseline scan:           sarv scan --full
  4. Enable realtime + scheduled scanning:  systemctl enable --now sarv
  5. Test alerts:                           sarv notify test

Commands: sarv scan | monitor | sites | syscheck | advise | report | quarantine | web
EOF
