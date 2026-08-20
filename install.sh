#!/bin/bash
# agent-filter installer (spec section 16 deliverable 5).
#
# Creates the broker account, directories, permissions, and database; loads
# the starter allowlist; configures Squid; detects the Tailscale IPv4 for the
# panel; enables the units. Deliberately out of scope: firewall rules, DNS
# changes, and activating the agent's proxy environment — the setup guide
# performs those at its cutover step (guide section 17.4).
set -euo pipefail

LIB=/usr/local/lib/agent-filter
ETC=/etc/approval-broker
LIBDATA=/var/lib/approval-broker
LOGDIR=/var/log/approval-broker
SHARE=/usr/local/share/agent-filter
SRC="$(cd "$(dirname "$0")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo ./install.sh" >&2
  exit 1
fi

# The agent account must already exist — the socket units grant it access by
# name, and the guide creates it in section 9. Fail now, before writing
# anything, rather than half-way through.
if ! getent group agent >/dev/null; then
  echo "Required group 'agent' does not exist; create it first (guide sec. 9)." >&2
  exit 1
fi

echo "== Packages"
apt-get update
apt-get install -y --no-upgrade squid-openssl python3-idna python3-argon2

# squid-openssl creates the 'proxy' account, needed by the acl socket unit and
# squid.conf ownership below. Confirm before any state is mutated.
if ! getent group proxy >/dev/null; then
  echo "The 'proxy' account was not created by squid install; aborting." >&2
  exit 1
fi

echo "== broker account"
if ! id broker >/dev/null 2>&1; then
  adduser --system --group --home "$LIBDATA" --no-create-home \
    --shell /usr/sbin/nologin broker
fi

echo "== Directories and permissions"
install -d -m 0755 "$ETC" "$LIB" "$SHARE"
install -d -m 0700 -o broker -g broker "$LIBDATA" "$LOGDIR"

echo "== Code and helpers"
install -d -m 0755 "$LIB/approval_broker"
install -m 0644 "$SRC"/approval_broker/*.py "$LIB/approval_broker/"
install -m 0755 "$SRC/bin/acl-helper" "$LIB/acl-helper"
install -m 0755 "$SRC/bin/brokerctl" /usr/local/bin/brokerctl

echo "== Data and configuration"
install -m 0644 "$SRC/data/tlds.txt" "$ETC/tlds.txt"
install -m 0644 "$SRC/data/blocked-domains.txt" "$ETC/blocked-domains.txt"
install -m 0644 "$SRC/data/starter-allowlist.txt" "$ETC/starter-allowlist.txt"
# Staged only: the default list is imported by an explicit panel action,
# never at install time.
install -m 0644 "$SRC/data/default-allowlist.txt" "$ETC/default-allowlist.txt"
install -m 0644 "$SRC/data/public-suffix-list.dat" "$ETC/public-suffix-list.dat"

TAILSCALE_IP="$(tailscale ip -4 2>/dev/null | head -n1 || true)"
if [[ -z "$TAILSCALE_IP" ]]; then
  echo "Could not detect a Tailscale IPv4 (is tailscaled up?)." >&2
  echo "The panel must bind the Tailscale address, never 0.0.0.0." >&2
  exit 1
fi
sed "s/@TAILSCALE_IP@/$TAILSCALE_IP/" "$SRC/config/config.toml" \
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
# Squid loads tls-cert after dropping to the proxy user, so the file must be
# readable by that account or the ssl-bump port fails to open.
chgrp proxy "$ETC/dummy-ca.pem" "$ETC/dummy-ca.key"
chmod 0640 "$ETC/dummy-ca.pem" "$ETC/dummy-ca.key"

echo "== Database and starter allowlist"
sudo -u broker PYTHONPATH="$LIB" python3 - <<'PYEOF'
from approval_broker import config, db
conn = db.open_db(config.load().get("paths", "db"))
conn.close()
PYEOF
sudo -u broker PYTHONPATH="$LIB" /usr/local/bin/brokerctl \
  load-starter "$ETC/starter-allowlist.txt"
# sqlite honours the creating process's umask; enforce the spec's 0600 rather
# than leaving the database group/other-readable.
chmod 0600 "$LIBDATA/broker.db"

echo "== Staged agent proxy environment (NOT activated; guide section 17.4)"
install -m 0644 "$SRC/share/agent-proxy.sh" "$SHARE/agent-proxy.sh"

echo "== Squid"
if [[ -f /etc/squid/squid.conf && ! -f /etc/squid/squid.conf.orig ]]; then
  cp /etc/squid/squid.conf /etc/squid/squid.conf.orig
fi
install -m 0644 "$SRC/squid/squid.conf" /etc/squid/squid.conf

echo "== systemd units"
install -m 0644 "$SRC"/systemd/*.service "$SRC"/systemd/*.socket \
  /etc/systemd/system/
install -m 0644 "$SRC/tmpfiles/approval-broker.conf" \
  /etc/tmpfiles.d/approval-broker.conf
systemd-tmpfiles --create /etc/tmpfiles.d/approval-broker.conf
systemctl daemon-reload
systemctl enable --now approval-broker-submit.socket approval-broker-acl.socket
systemctl enable --now approval-broker.service approval-panel.service
systemctl restart squid

echo
echo "Installed. Next steps (setup guide section 14.5):"
echo "  1. sudo brokerctl set-password"
echo "  2. sudo ufw allow in on tailscale0 proto tcp to any port 9120"
echo "  3. Open http://$TAILSCALE_IP:9120 from a trusted device."
echo "The agent's egress is NOT redirected yet; that happens at guide"
echo "section 17.4 (firewall rules, DNS change, proxy environment)."
