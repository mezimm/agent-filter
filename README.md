# agent-filter

A firewall for an AI agent's Internet access. The agent reaches only destinations you approved; everything else is refused on the spot and queued on a private web page, where one click allows or denies it.

## Why

An AI agent is a program that works on its own — it browses, downloads, and calls services while you do something else. If it is tricked, or simply goes wrong, it can send whatever it can read to anywhere on the Internet. agent-filter narrows "anywhere" to a list you control: every destination named, logged, and revocable. And if any part of the filter is down, the agent gets nothing — failure closes the door, never opens it.

## How it works

Three small programs run on your Mac:

- **The proxy** (Squid) — the checkpoint. Every connection the agent makes must pass through it and name the site it wants.
- **The broker** — the decision-maker. It keeps your approved list and answers every request: allowed or not.
- **The panel** — your controls. A private web page where refused destinations wait for your yes or no, reachable only from your own devices through [Tailscale](https://tailscale.com), a free service that links your devices into a private network.

One thing agent-filter cannot do alone: the agent's machine must be wired so this proxy is its *only* path to the Internet. The setup guide does that part (course material — links here soon). Without that wiring, the filter stands beside an open door.

## What's in the box

- A pre-installed default list, plus an optional ~2,500-host catalog in fifteen loadable groups — package registries, model providers, documentation — each host with a one-line description, so day one is not fifty prompts.
- Approvals with expiry (once / session / 24 hours / permanent) and one-click revoke.
- A pause switch for install bursts: open the gate 15 or 60 minutes, everything still logged.
- Export, paste-import (refused lines are listed with reasons), and a confirm-guarded erase.
- A red warning when a wildcard would approve strangers' sites (`*.github.io` and friends).
- Every decision stamped in an activity log a five-minute monthly review can read.
- A panel that fits a phone: approve from wherever you are, and a login lasts 30 days across panel restarts.

## Install

On the Mac that hosts the agent's virtual machine. You need [Homebrew](https://brew.sh) and Tailscale signed in; details in [macos/README.md](macos/README.md).

```bash
brew install squid python
git clone https://github.com/mezimm/agent-filter
cd agent-filter
sudo ./macos/install-macos.sh
brokerctl set-password
brew services restart squid
```

The installer prints the panel's address at the end — open it, log in with the password you just set, and load the **catalog** (whole, or just the groups you need).

A Linux, inside-the-VM variant also ships: `sudo ./install.sh` with the `systemd/` units.

## Update

From the folder you cloned:

```bash
git pull
sudo ./macos/install-macos.sh
brew services restart squid
```

Your approvals, panel password, and logs live in a database that survives updates. One caveat: updating re-adds any starter or default entries you had revoked — revoke them again afterwards.

## Design

Security software a stranger is asked to trust should be readable. This is Python's standard library plus two small dependencies (`idna`, `argon2`). The panel is plain server-rendered HTML with zero JavaScript, so text an attacker may have written renders inert. Storage is one SQLite file. Every failure denies; nothing ever "temporarily allows".
