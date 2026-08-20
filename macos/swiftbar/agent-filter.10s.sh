#!/bin/bash
# SwiftBar menu for the agent VM and the agent-filter firewall (host mode).
#
# Shows only what is installed — a Mac with no VM, no firewall, or neither
# renders a reduced menu instead of errors. Icon: 🟢 VM running behind a
# healthy filter · ⏸ enforcement paused · 🟡 VM running but firewall down
# (agent offline, fail closed) · ⚪ VM stopped. A number after the icon is
# the count of approvals waiting in the panel.
#
# Install (guide, "menu-bar switch"): copy into SwiftBar's plugin folder.
# The 10s in the filename is SwiftBar's refresh interval.

VMDIR="$HOME/VirtualMachines/agent-1"
PIDFILE="$VMDIR/agent-1.pid"
LIB=/usr/local/lib/agent-filter
DB=/usr/local/var/agent-filter/broker.db
CONF=/etc/approval-broker/config.toml
DAEMON=/Library/LaunchDaemons/local.qemu.agent-1.plist
BREW=/opt/homebrew/bin/brew
CTL=/usr/local/bin/brokerctl
ME_UID="$(/usr/bin/id -u)"

vm_installed() { [[ -x "$VMDIR/start-agent-1.sh" ]]; }
vm_running()   { [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }
fw_installed() { [[ -d "$LIB" ]]; }
squid_up()     { /usr/bin/pgrep -qx squid; }
broker_up()    { /usr/bin/pgrep -qf approval_broker.broker; }
panel_up()     { /usr/bin/pgrep -qf approval_broker.panel; }

# ---- actions (the menu re-invokes this script with an argument) ----------
case "${1:-}" in
  vm-start) exec "$VMDIR/start-agent-1.sh" ;;
  vm-stop)  exec "$VMDIR/stop-agent-1.sh" ;;
  fw-start)
    "$BREW" services start squid
    for n in broker panel; do
      /bin/launchctl enable "gui/$ME_UID/com.agent-filter.$n"
      /bin/launchctl bootstrap "gui/$ME_UID" \
        "$HOME/Library/LaunchAgents/com.agent-filter.$n.plist" 2>/dev/null \
        || /bin/launchctl kickstart "gui/$ME_UID/com.agent-filter.$n"
    done
    exit 0 ;;
  fw-stop)
    "$BREW" services stop squid
    for n in broker panel; do
      /bin/launchctl bootout "gui/$ME_UID/com.agent-filter.$n" 2>/dev/null
      /bin/launchctl disable "gui/$ME_UID/com.agent-filter.$n"
    done
    exit 0 ;;
  pause-15)  exec "$CTL" pause 15 ;;
  pause-60)  exec "$CTL" pause 60 ;;
  pause-off) exec "$CTL" pause off ;;
  resume)    exec "$CTL" resume ;;
  vm-boot-on)
    exec /usr/bin/osascript -e \
      'do shell script "launchctl enable system/local.qemu.agent-1" with administrator privileges' ;;
  vm-boot-off)
    exec /usr/bin/osascript -e \
      'do shell script "launchctl disable system/local.qemu.agent-1" with administrator privileges' ;;
esac

# ---- state ---------------------------------------------------------------
PENDING=""
PAUSED=0
if fw_installed && [[ -r "$DB" ]]; then
  PENDING="$(/usr/bin/sqlite3 "$DB" \
    "SELECT COUNT(*) FROM requests WHERE status='pending'" 2>/dev/null)"
  PVAL="$(/usr/bin/sqlite3 "$DB" \
    "SELECT value FROM settings WHERE key='enforcement_paused_until'" 2>/dev/null)"
  NOW="$(/bin/date +%s)"
  if [[ "$PVAL" == "off" ]]; then PAUSED=1
  elif [[ "$PVAL" =~ ^[0-9]+$ && "$PVAL" -gt "$NOW" ]]; then PAUSED=1; fi
fi

FW_OK=0
if fw_installed && squid_up && broker_up && panel_up; then FW_OK=1; fi

if vm_running; then
  if [[ "$PAUSED" == 1 ]]; then ICON="⏸"
  elif [[ "$FW_OK" == 1 || ! -d "$LIB" ]]; then ICON="🟢"
  else ICON="🟡"; fi
else
  ICON="⚪"
fi
if [[ -n "$PENDING" && "$PENDING" != "0" ]]; then
  echo "$ICON $PENDING"
else
  echo "$ICON"
fi
echo "---"

# ---- VM section ----------------------------------------------------------
if vm_installed; then
  if vm_running; then
    echo "VM agent-1: running"
    echo "Shut down cleanly | bash=\"$0\" param1=vm-stop terminal=false refresh=true"
  else
    echo "VM agent-1: stopped"
    echo "Start | bash=\"$0\" param1=vm-start terminal=false refresh=true"
  fi
  if [[ -f "$DAEMON" ]]; then
    echo "VM autostart at Mac boot | size=11"
    echo "-- Enable | bash=\"$0\" param1=vm-boot-on terminal=false refresh=true"
    echo "-- Disable | bash=\"$0\" param1=vm-boot-off terminal=false refresh=true"
  fi
  echo "---"
fi

# ---- firewall section ----------------------------------------------------
if fw_installed; then
  s="✗"; b="✗"; p="✗"
  squid_up && s="✓"; broker_up && b="✓"; panel_up && p="✓"
  echo "Firewall: squid $s · broker $b · panel $p"
  if [[ "$PAUSED" == 1 ]]; then
    echo "⚠ Enforcement is PAUSED"
    echo "Resume enforcement | bash=\"$0\" param1=resume terminal=false refresh=true"
  else
    echo "Pause enforcement | size=11"
    echo "-- 15 minutes | bash=\"$0\" param1=pause-15 terminal=false refresh=true"
    echo "-- 60 minutes | bash=\"$0\" param1=pause-60 terminal=false refresh=true"
    echo "-- Until turned back on | bash=\"$0\" param1=pause-off terminal=false refresh=true"
  fi
  if [[ -n "$PENDING" && "$PENDING" != "0" ]]; then
    echo "$PENDING approval(s) waiting"
  fi
  PANEL_IP="$(/usr/bin/awk -F'"' '/^bind_ip/ {print $2}' "$CONF" 2>/dev/null)"
  [[ -n "$PANEL_IP" ]] && echo "Open approval panel | href=http://$PANEL_IP:9120"
  echo "Open Hermes dashboard | href=http://127.0.0.1:9119"
  if [[ "$FW_OK" == 1 ]]; then
    echo "Stop firewall (also stops autostart) | bash=\"$0\" param1=fw-stop terminal=false refresh=true"
  else
    echo "Start firewall (runs now + at login) | bash=\"$0\" param1=fw-start terminal=false refresh=true"
  fi
elif vm_installed; then
  echo "Firewall: not installed | href=https://github.com/mezimm/agent-filter"
fi

if ! vm_installed && ! fw_installed; then
  echo "Nothing installed yet | href=https://github.com/mezimm/agent-filter"
fi
