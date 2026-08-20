#!/bin/bash
# agent-filter installer — macOS host mode.
#
# Installs the broker, panel, and Squid configuration on the Mac that hosts
# the agent VM. The VM's only network path is a QEMU guestfwd to Squid on
# 127.0.0.1:8888, so the whole stack runs as the normal Mac account: launchd
# user agents for broker and panel, brew services for Squid.
#
# Run with sudo from the normal Mac account: sudo ./macos/install-macos.sh
# Deliberately out of scope: brew installs (brew refuses root — the guide
# runs `brew install squid` first) and starting Squid (the guide runs
# `brew services restart squid` after this script).
set -euo pipefail

LIB=/usr/local/lib/agent-filter
ETC=/etc/approval-broker
VAR=/usr/local/var/agent-filter
VENV="$LIB/venv"
SRC="$(cd "$(dirname "$0")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo ./macos/install-macos.sh" >&2
  exit 1
fi
if [[ -z "${SUDO_USER:-}" || "$SUDO_USER" == "root" ]]; then
  echo "Run via sudo from the normal Mac account, not as a root login." >&2
  exit 1
fi
RUN_USER="$SUDO_USER"
RUN_UID="$(id -u "$RUN_USER")"

BREW_PREFIX="$(sudo -u "$RUN_USER" brew --prefix 2>/dev/null || echo /opt/homebrew)"
BREW_PY="$BREW_PREFIX/bin/python3"
if [[ ! -x "$BREW_PY" ]]; then
  echo "Homebrew python3 not found at $BREW_PY; run: brew install python" >&2
  exit 1
fi
# tomllib needs 3.11+; an old python@3.x keg can still own the python3 link.
if ! "$BREW_PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Homebrew python3 is older than 3.11; run: brew install python && brew link --overwrite python" >&2
  exit 1
fi
if [[ ! -x "$BREW_PREFIX/sbin/squid" && ! -x "$BREW_PREFIX/opt/squid/sbin/squid" ]]; then
  echo "Squid not found under $BREW_PREFIX; run: brew install squid" >&2
  exit 1
fi

echo "== Python virtual environment (argon2, idna)"
install -d -m 0755 "$LIB"
# Rebuild a venv left behind by an older interpreter.
if [[ -x "$VENV/bin/python3" ]] && \
   ! "$VENV/bin/python3" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
  rm -rf "$VENV"
fi
if [[ ! -x "$VENV/bin/python3" ]]; then
  "$BREW_PY" -m venv "$VENV"
fi
"$VENV/bin/pip" install --quiet --upgrade argon2-cffi idna

echo "== Code and helpers"
install -d -m 0755 "$LIB/approval_broker"
install -m 0644 "$SRC"/approval_broker/*.py "$LIB/approval_broker/"
install -m 0755 "$SRC/bin/acl-helper" "$LIB/acl-helper"
install -d -m 0755 /usr/local/bin
install -m 0755 "$SRC/bin/brokerctl" /usr/local/bin/brokerctl
# The stock shebang is /usr/bin/python3 — macOS ships 3.9 there, which lacks
# tomllib. Point both entry points at the venv's interpreter instead.
sed -i '' "1s|.*|#!$VENV/bin/python3|" "$LIB/acl-helper" /usr/local/bin/brokerctl

echo "== Data and configuration"
install -d -m 0755 "$ETC"
install -m 0644 "$SRC/data/tlds.txt" "$ETC/tlds.txt"
install -m 0644 "$SRC/data/blocked-domains.txt" "$ETC/blocked-domains.txt"
install -m 0644 "$SRC/data/starter-allowlist.txt" "$ETC/starter-allowlist.txt"
install -m 0644 "$SRC/data/host-mode-allowlist.txt" "$ETC/host-mode-allowlist.txt"
# Staged only: the default list is imported by an explicit panel action.
install -m 0644 "$SRC/data/default-allowlist.txt" "$ETC/default-allowlist.txt"
install -m 0644 "$SRC/data/public-suffix-list.dat" "$ETC/public-suffix-list.dat"

TAILSCALE_BIN=""
for candidate in /usr/local/bin/tailscale "$BREW_PREFIX/bin/tailscale" \
                 /Applications/Tailscale.app/Contents/MacOS/Tailscale; do
  [[ -x "$candidate" ]] && TAILSCALE_BIN="$candidate" && break
done
TAILSCALE_IP=""
if [[ -n "$TAILSCALE_BIN" ]]; then
  # As the login user: the App Store build's CLI locates the running
  # service per-uid and returns nothing when asked as root.
  TAILSCALE_IP="$(sudo -u "$RUN_USER" "$TAILSCALE_BIN" ip -4 2>/dev/null | head -n1 || true)"
fi
if [[ -z "$TAILSCALE_IP" ]]; then
  echo "Could not detect the Mac's Tailscale IPv4 (is Tailscale installed" >&2
  echo "and signed in?). The panel must bind that address, never 0.0.0.0." >&2
  exit 1
fi
sed "s/@TAILSCALE_IP@/$TAILSCALE_IP/" "$SRC/macos/config-macos.toml" \
  > "$ETC/config.toml"
chmod 0644 "$ETC/config.toml"

echo "== Dummy certificate for Squid's ssl-bump port"
# Required by the port syntax even in peek/splice mode; never presented to
# any client and signs nothing.
if [[ ! -f "$ETC/dummy-ca.pem" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -subj "/CN=agent-filter-dummy-never-used" \
    -keyout "$ETC/dummy-ca.key" -out "$ETC/dummy-ca.crt" 2>/dev/null
  cat "$ETC/dummy-ca.crt" "$ETC/dummy-ca.key" > "$ETC/dummy-ca.pem"
  rm "$ETC/dummy-ca.crt"
fi
# Squid runs as the normal Mac account (brew services), so that account must
# be able to read the file.
chown root:staff "$ETC/dummy-ca.pem" "$ETC/dummy-ca.key"
chmod 0640 "$ETC/dummy-ca.pem" "$ETC/dummy-ca.key"

echo "== Database and allowlists"
install -d -m 0700 -o "$RUN_USER" -g staff "$VAR"
sudo -u "$RUN_USER" PYTHONPATH="$LIB" "$VENV/bin/python3" - <<'PYEOF'
from approval_broker import config, db
conn = db.open_db(config.load().get("paths", "db"))
conn.close()
PYEOF
sudo -u "$RUN_USER" /usr/local/bin/brokerctl load-starter "$ETC/starter-allowlist.txt"
sudo -u "$RUN_USER" /usr/local/bin/brokerctl load-starter "$ETC/host-mode-allowlist.txt"
chmod 0600 "$VAR/broker.db"

echo "== Squid configuration"
if [[ -f "$BREW_PREFIX/etc/squid.conf" && ! -f "$BREW_PREFIX/etc/squid.conf.orig" ]]; then
  cp "$BREW_PREFIX/etc/squid.conf" "$BREW_PREFIX/etc/squid.conf.orig"
fi
install -m 0644 -o "$RUN_USER" -g admin "$SRC/macos/squid-macos.conf" \
  "$BREW_PREFIX/etc/squid.conf"

echo "== launchd user agents (broker, panel)"
LA_DIR="/Users/$RUN_USER/Library/LaunchAgents"
install -d -m 0755 -o "$RUN_USER" -g staff "$LA_DIR"
for name in com.agent-filter.broker com.agent-filter.panel; do
  install -m 0644 -o "$RUN_USER" -g staff "$SRC/macos/$name.plist" "$LA_DIR/$name.plist"
done
# Loading needs the user's GUI login session; over SSH with no console
# login there is none — the agents then simply load at the next login.
if launchctl print "gui/$RUN_UID" >/dev/null 2>&1; then
  for name in com.agent-filter.broker com.agent-filter.panel; do
    launchctl bootout "gui/$RUN_UID" "$LA_DIR/$name.plist" 2>/dev/null || true
    launchctl bootstrap "gui/$RUN_UID" "$LA_DIR/$name.plist"
  done
else
  echo "No GUI login session for $RUN_USER: broker and panel will start at the next console login."
fi

echo
echo "Installed. Next steps (setup guide):"
echo "  1. brokerctl set-password"
echo "  2. brew services restart squid"
echo "  3. Open http://$TAILSCALE_IP:9120 and log in."
echo "Broker and panel start at login (KeepAlive); Squid via brew services."
echo "Until you log in to the Mac after a reboot, the VM has no egress —"
echo "that is fail-closed, not broken."
