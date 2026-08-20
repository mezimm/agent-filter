# agent-filter

An egress approval broker for an untrusted AI agent on an Ubuntu VM: a Squid
filtering proxy, a broker daemon holding a destination allowlist and request
queue, and a web panel where a human approves or denies destinations.

Built from `approval-broker-spec.md`. Installed and verified by the companion
setup guide (`mac-qemu-tailscale-setup-guide--no-root.md`, sections 14.5 and
17.4). The firewall rules, DNS change, and proxy-environment activation are
deliberately **not** performed here — the guide does those at its cutover step.

## Technology choices

**Python 3 standard library, plus exactly two Debian-packaged dependencies**
(`python3-idna` for IDNA 2008 hostname encoding, `python3-argon2` for panel
password hashing). This is security-critical code a student is asked to trust:
a small dependency tree and readable logic beat framework convenience. The web
panel is server-rendered HTML with **zero JavaScript** — the rationale text it
displays was, in the threat model, written by the attacker, so the page is
inert by construction and a strict CSP backstops template mistakes. Storage is
SQLite in WAL mode: single file, atomic, no server process. The proxy is the
distro's `squid-openssl` with an `external_acl_type` helper, so CONNECT
parsing and HTTP edge cases stay out of this codebase.

## Layout

```
approval_broker/validation.py   shared hostname validation — the one routine
approval_broker/broker.py       decision engine behind both unix sockets
approval_broker/panel.py        web panel (Tailscale IP:9120, own login)
approval_broker/db.py           SQLite schema and operations
bin/acl-helper                  Squid external ACL helper (fail-closed)
bin/brokerctl                   set-password, load-starter
squid/squid.conf                CONNECT-only proxy on 127.0.0.1:8888
systemd/                        service + socket units (socket units own the
                                spec's socket modes: submit 0620 broker:agent,
                                acl 0660 broker:proxy)
data/                           IANA TLD snapshot, Public Suffix List
                                snapshot, blocked domains, starter list,
                                optional default list (~2400 hosts)
install.sh                      the guide's entry point (sudo ./install.sh)
macos/                          host mode: the whole stack on the Mac that
                                hosts the VM (see macos/README.md)
tests/                          python3 -m unittest discover -s tests
```

## Configuration

`/etc/approval-broker/config.toml` (root-owned, read-only to `broker`) — every
key is documented in the file; missing keys fall back to the same defaults
compiled into `config.py`, so a truncated config cannot loosen a limit.
`install.sh` writes the VM's Tailscale IPv4 into `panel.bind_ip`.

## Behavioural notes

- **Fail closed, everywhere.** Broker down, database unreadable, helper
  timeout, unparseable input — all deny. Squid's `ttl=0` keeps every decision
  live, so expiry and revocation apply at decision time with no sweeper.
- **Denials are visible.** A denied destination answers `DENIED_BY_ADMIN`
  with the operator's typed reason, and stays denied on resubmit until the
  operator changes their mind (manual add). No internals ever leave the
  process: fixed reason codes and fixed text only.
- **`domain.com` also admits `www.domain.com`, and only that.** Implemented
  as two literal rows at insert time, only when the entry has exactly two
  labels; for multi-part public suffixes (`example.co.uk`) add the `www` row
  explicitly if wanted.
- **Wildcards** can only be typed in the panel, always through the typed
  confirmation dialog, defaulting to 24-hour expiry. Agent-submitted patterns
  are auto-rejected and never reach the queue.
- **Wildcards on Public Suffix List zones trigger a prominent alarm, and
  confirming past it is an operator override.** A base that is a PSL zone
  (`*.github.io`, `*.co.uk`) or contains one (`*.amazonaws.com` spans
  `s3.amazonaws.com`) gets an unmissable red warning at the top of the
  dialog: strangers provably register names there, so the wildcard approves
  the open Internet. The choice stays with the operator — cancel is offered
  first, and a confirmed approval is stamped `PSL-ZONE OVERRIDE (zone)` in
  the decision log where the monthly review will see it. Exact hostnames are
  never judged by the PSL — a project's own page under a shared zone stays
  legal. Parsed from the shipped snapshot with a built-in fallback of the
  worst zones when the file is missing.
- **Blocked domains** (`tailscale.com`, `ts.net`, `tailscale.io`) are refused
  from every path and are never shown with an approve control.
- **The default list is opt-in, exact, and bulk-revocable.** The panel's Add
  page can import `default-allowlist.txt` — a curated set of roughly 2,400
  documentation, registry, reference, open-data, and news hosts, every one a
  single-organisation domain judged by the stranger-signup rule (curation
  rules and deliberate exclusions are documented in the file itself). It is
  never loaded automatically, contains no wildcards (the importer refuses
  them), passes the same validation and blocked-domain gate as every other
  path, imports all-or-nothing, re-imports idempotently, and can be removed
  as one action from the same page. Entries carry source `default` so they
  stay distinguishable in the allowlist and activity views.
- **The proxy also denies by address.** Even for an allowlisted name, a CONNECT
  whose destination resolves into a loopback, link-local, RFC1918, or
  CGNAT/tailnet range is refused (`squid.conf` `to_internal`), so DNS rebinding
  cannot turn an approved hostname into a path to the VM's own services or the
  LAN. This is the only layer that covers loopback.
- **`once` spans one real connection.** It survives both proxy helper phases of
  a single connection, is spent on the second, is never spent by a submission,
  and still carries a short expiry backstop.
- **No SNI, no connection.** A TLS ClientHello without SNI cannot be verified
  by name, so it is terminated. Modern clients all send SNI.
- **Proxy decision logs are coalesced.** Identical repeated proxy allow/deny
  events within a few seconds collapse to one row, so a reconnect flood cannot
  fill the append-only decision log; distinct destinations are still recorded.

## Integration caveats (verify on the VM)

- The SNI check relies on Squid accepting an external (slow) ACL in
  `ssl_bump splice`. Verify on the target's packaged Squid with the guide's
  section 14.5 smoke test plus: CONNECT for an allowlisted host carrying an
  SNI for a non-allowlisted host must be terminated. If the packaged build
  refuses the configuration, document the residual gap rather than removing
  the check (spec section 5).
- The `ssl-bump` port syntax requires a certificate argument even in
  peek/splice mode; `install.sh` generates a throwaway self-signed one that
  is never presented to any client.
- The SNI check requires the *reached* name to be allowlisted. A client that
  CONNECTs to allowlisted host A with an SNI for allowlisted host B reaches
  B — still an approved destination, which is the property that matters.

## Operations

- **Backup:** include `/var/lib/approval-broker/` (database) and
  `/var/log/approval-broker/` (decision log) in the guide's cold off-VM
  backups (guide section 21.3).
- **Log rotation:** the text decision log rotates by size (`[log]` in
  config.toml, default 1 MiB × 5). The SQLite `decisions` table is
  append-only by design; prune only by conscious operator action.
- **Upgrade:** `git pull`, rerun `sudo ./install.sh` (idempotent; preserves
  the database, config, and dummy certificate), then re-run the guide's
  section 17.4 verification battery.
- **TLD list refresh:** replace `/etc/approval-broker/tlds.txt` with the
  current `https://data.iana.org/TLD/tlds-alpha-by-domain.txt` during the
  guide's monthly review if desired; restart `approval-broker`.
- **Public Suffix List refresh:** replace
  `/etc/approval-broker/public-suffix-list.dat` with the current
  `https://publicsuffix.org/list/public_suffix_list.dat` (MPL-2.0) on the
  same cadence; restart `approval-panel`.

## Tests

```
python3 -m unittest discover -s tests
```

Covers the spec section 15 suite: the validation evasion table, wildcard
paths, queue and rate limits, panel security (CSP, CSRF, escaping,
unauthenticated refusal), fail-closed (broker down, unresponsive broker,
corrupt database), and the end-to-end submit → approve → allow → deny →
expire flow. The Squid-level SNI behaviour is integration-verified on the VM
(see caveats above).
