# macOS host mode

Runs the whole agent-filter stack — Squid, broker, panel — on the Mac that
hosts the agent VM, instead of inside the VM. Used by the root-agent setup
guide (`mac-qemu-tailscale-setup-guide-acl--root.md`), where the VM's only
network path is a QEMU `guestfwd` to Squid on the Mac's `127.0.0.1:9188`:

```text
VM (any privilege, even root)
  -> QEMU user network, restrict=on          (only forwarded paths exist)
  -> guestfwd 10.0.2.100:8888 -> Mac 127.0.0.1:9188 (Squid)
  -> broker allowlist check -> public Internet
```

Because the enforcement point is QEMU on the Mac, nothing inside the VM —
including root — can bypass, disable, or reconfigure the filter. A VM that
stops using the proxy simply loses all egress: fail closed.

## Differences from the Linux in-VM install

- Everything runs as the normal Mac account: broker and panel as launchd
  user agents, Squid via `brew services`. No `broker` system account.
- Python comes from a venv built on Homebrew python3 (`/usr/bin/python3` is
  3.9 and lacks `tomllib`); the installer rewrites the `acl-helper` and
  `brokerctl` shebangs to the venv interpreter.
- The panel binds the **Mac's** Tailscale IPv4 (port 9120). The VM cannot
  reach it: its only route is the guestfwd to Squid, and Squid refuses
  CONNECT to tailnet and private ranges.
- State lives in `/usr/local/var/agent-filter/` (database, decision log,
  sockets); reference files in `/etc/approval-broker/` as on Linux.
- `data/host-mode-allowlist.txt` is loaded in addition to the starter list:
  in host mode the whole VM, including root's `apt`, rides the proxy, so the
  Ubuntu HTTPS mirrors must be allowlisted.
- Broker and panel start at login, not boot. Until the Mac account logs in
  after a reboot, the VM has no egress — fail closed by design.

## Install

Prerequisites: Homebrew, and Tailscale installed and signed in on the Mac
(the installer bakes the Mac's Tailscale IPv4 into the panel config).

```bash
brew install squid python
sudo ./macos/install-macos.sh
brokerctl set-password
brew services restart squid
```

## Update

```bash
git pull
sudo ./macos/install-macos.sh
brew services restart squid
```

Idempotent: allowlist, queue, decision log, and panel password live in the
database and survive; schema upgrades run automatically at service start.
One caveat: re-running the installer re-loads the starter and host-mode
lists, which restores any of their entries you had revoked in the panel —
re-revoke those afterwards.
