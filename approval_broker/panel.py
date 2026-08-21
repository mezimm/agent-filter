"""Approval panel: the human side of the broker (spec section 11).

Server-rendered HTML with zero JavaScript — the rationale shown on these pages
was written, in the threat model, by the attacker, so the page must be inert.
Everything dynamic is escaped; a strict CSP backstops template mistakes.

Binds the VM's Tailscale IPv4 only, with its own argon2 login: network
reachability is not authorisation.
"""

import hmac
import html
import ipaddress
import os
import subprocess
import http.cookies
import http.server
import secrets
import threading
import time
import urllib.parse
from datetime import datetime, timezone

from . import config, db, validation

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
except ImportError:  # surfaced as a setup error at login, never a crash
    PasswordHasher = None

SESSION_COOKIE = "panel_session"
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 60

CSS = """
:root {
  color-scheme: light dark;
  --bg: #f3f5f8; --surface: #ffffff; --surface-2: #f7f8fa;
  --text: #17202a; --muted: #5b6673; --line: #d8dee6;
  --accent: #1f5fbf; --accent-soft: #e6eefc;
  --ok: #1b7f3b; --ok-soft: #e4f5e9;
  --danger: #b3261e; --danger-soft: #fdecea; --danger-deep: #7a1711;
  --purple: #6f3cc7; --purple-soft: #efe7fc;
  --shadow: 0 1px 2px rgba(16, 24, 40, .06), 0 1px 3px rgba(16, 24, 40, .04);
  --radius: 10px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1419; --surface: #171d25; --surface-2: #1d242e;
    --text: #e6eaf0; --muted: #9aa6b5; --line: #2b3541;
    --accent: #7aa7ef; --accent-soft: #1b2a44;
    --ok: #4fbf73; --ok-soft: #14301d;
    --danger: #ff7b72; --danger-soft: #3a1815;
    --purple: #b693f5; --purple-soft: #2a1f45;
    --shadow: none;
  }
}

* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
a { color: var(--accent); }
h1 { font-size: 1.5rem; line-height: 1.25; margin: 0 0 1rem; }
h2 { font-size: 1.1rem; line-height: 1.3; margin: 0 0 .6rem; }
p { margin: 0 0 .8rem; }
p:last-child { margin-bottom: 0; }
code { font-size: .9em; background: var(--surface-2); padding: .05em .3em;
       border-radius: 4px; }
.wrap { max-width: 64rem; margin: 0 auto; padding: 1.25rem 1rem 4rem; }

/* -- header / navigation ------------------------------------------------- */
.top { background: var(--surface); border-bottom: 1px solid var(--line); }
.top-inner {
  max-width: 64rem; margin: 0 auto; padding: .6rem 1rem;
  display: flex; flex-wrap: wrap; align-items: center; gap: .5rem 1rem;
}
.brand { font-weight: 800; letter-spacing: .01em; text-decoration: none;
         color: var(--text); font-size: 1.05rem; }
.brand span { color: var(--accent); }
nav { display: flex; gap: .25rem; flex: 1 1 auto; overflow-x: auto;
      scrollbar-width: none; }
nav::-webkit-scrollbar { display: none; }
nav a {
  display: inline-flex; align-items: center; gap: .4rem;
  padding: .45rem .85rem; border-radius: 999px; text-decoration: none;
  color: var(--muted); font-weight: 600; white-space: nowrap;
}
nav a:hover { background: var(--surface-2); color: var(--text); }
nav a.active { background: var(--accent-soft); color: var(--accent); }
nav .count {
  background: var(--danger); color: #fff; border-radius: 999px;
  font-size: .72rem; line-height: 1; padding: .25em .55em; font-weight: 700;
}
.logout { margin-left: auto; }
@media (min-width: 640px) {
  .top { position: sticky; top: 0; z-index: 10; }
}
@media (max-width: 639px) {
  .top-inner { padding: .5rem .75rem; }
  .brand { order: 1; }
  .logout { order: 2; }
  nav { order: 3; flex-basis: 100%; margin: 0 -.75rem; padding: 0 .75rem; }
}

/* -- cards and blocks ---------------------------------------------------- */
.card {
  background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--radius); box-shadow: var(--shadow);
  padding: 1.1rem 1.2rem; margin: 0 0 1rem;
}
.card > h2:first-child, .card > h1:first-child { margin-top: 0; }
.meta { color: var(--muted); font-size: .875rem; }
.empty { color: var(--muted); text-align: center; padding: 2.5rem 1rem; }
.host { font-size: 1.25rem; font-weight: 700; overflow-wrap: anywhere;
        margin: 0 0 .25rem; }
.pattern { font-weight: 600; overflow-wrap: anywhere; }
.untrusted {
  border: 2px solid var(--danger); background: var(--danger-soft);
  border-radius: 8px; padding: .7rem .85rem; margin: .8rem 0;
}
.untrusted .label { display: block; color: var(--danger); font-weight: 700;
                    font-size: .72rem; letter-spacing: .06em; }
.untrusted pre { margin: .4rem 0 0; white-space: pre-wrap;
                 overflow-wrap: anywhere; font-size: .9rem; }
.badge { display: inline-block; padding: .1rem .5rem; border-radius: 999px;
         font-size: .72rem; font-weight: 700; letter-spacing: .04em;
         vertical-align: middle; }
.wildcard { background: var(--purple-soft); color: var(--purple); }
.warn { border: 2px solid var(--danger); background: var(--surface);
        border-radius: var(--radius); padding: 1.2rem; }
.banner { background: var(--danger-deep); color: #fff; padding: .75rem 1rem;
          border-radius: var(--radius); font-weight: 600; margin: 0 0 1rem; }
.danger {
  border: 3px solid var(--danger-deep); background: #b3261e; color: #fff;
  padding: 1rem 1.2rem; border-radius: var(--radius); margin: 0 0 1.2rem;
}
.danger .danger-title { margin: 0 0 .6rem; font-size: 1.1rem; font-weight: 800;
                        text-transform: uppercase; letter-spacing: .08em; }
.danger a { color: #fff; font-weight: 700; }
.danger button { background: #fff; color: #b3261e; border-color: #fff; }
.error { background: var(--danger-soft); color: var(--danger);
         border: 1px solid var(--danger); border-radius: 8px;
         padding: .7rem .9rem; font-weight: 600; margin: 0 0 1rem; }
details { border-top: 1px solid var(--line); padding: .6rem 0; }
details:last-child { padding-bottom: 0; }
summary { cursor: pointer; padding: .3rem 0; }
summary::marker { color: var(--muted); }
.hosts { overflow-wrap: anywhere; }

/* -- forms ---------------------------------------------------------------- */
input[type=text], input[type=password], select, textarea {
  font: inherit; color: var(--text); background: var(--surface);
  border: 1px solid var(--line); border-radius: 8px;
  padding: .55rem .7rem; min-height: 2.6rem; width: 100%; max-width: 100%;
}
textarea { min-height: 8rem; font-family: ui-monospace, Menlo, monospace;
           font-size: .9rem; }
input:focus, select:focus, textarea:focus, button:focus-visible {
  outline: 2px solid var(--accent); outline-offset: 1px;
}
button {
  font: inherit; font-weight: 600; cursor: pointer;
  min-height: 2.6rem; padding: .5rem 1rem; border-radius: 8px;
  border: 1px solid var(--line); background: var(--surface); color: var(--text);
}
button:hover { background: var(--surface-2); }
.btn-primary { background: var(--accent); border-color: var(--accent);
               color: #fff; }
.btn-primary:hover { filter: brightness(1.08); background: var(--accent); }
.btn-approve { background: #1b7f3b; border-color: #1b7f3b; color: #fff; }
.btn-approve:hover { background: #1b7f3b; filter: brightness(1.1); }
.btn-deny { background: transparent; border-color: var(--danger);
            color: var(--danger); }
.btn-deny:hover { background: var(--danger-soft); }
.btn-ghost { background: transparent; border-color: transparent;
             color: var(--muted); }
.btn-ghost:hover { background: var(--surface-2); color: var(--text); }
.btn-small { min-height: 2rem; padding: .25rem .7rem; font-size: .875rem; }
.field { display: flex; flex-direction: column; gap: .3rem; }
.field > span { font-size: .8rem; font-weight: 600; color: var(--muted); }
.field small { font-weight: 400; }
.row { display: flex; flex-wrap: wrap; gap: .7rem; align-items: flex-end; }
.row > .field { flex: 1 1 12rem; }
.row > .field.narrow { flex: 0 1 11rem; }
.row > button { flex: 0 0 auto; }
.stack { display: flex; flex-direction: column; gap: .8rem; }
.choices { display: flex; flex-wrap: wrap; gap: .4rem 1.2rem; }
.choices label { display: inline-flex; align-items: center; gap: .45rem;
                 cursor: pointer; }
.actions { display: flex; flex-wrap: wrap; gap: .6rem; align-items: center; }
/* Deny comes first in the DOM (Enter in the reason box must deny, never
   approve); the column is reversed so Approve still reads first. */
.decide { display: flex; flex-direction: column-reverse; gap: .7rem;
          margin-top: .8rem; }
@media (max-width: 639px) {
  .row > *, .row > .field.narrow, .actions > button { flex: 1 1 100%; }
  .row > button, .actions > button { width: 100%; }
}
@media (pointer: coarse) {
  button, input[type=text], input[type=password], select { min-height: 2.8rem; }
}

/* -- login ---------------------------------------------------------------- */
.login { max-width: 24rem; margin: 8vh auto 0; }
.login h1 { margin-bottom: .2rem; }
.login form { margin-top: 1.2rem; }
.login button { width: 100%; margin-top: .8rem; }

/* -- tables ---------------------------------------------------------------- */
.table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch;
              margin: 0 0 1rem; }
table { border-collapse: collapse; width: 100%; background: var(--surface);
        border: 1px solid var(--line); border-radius: var(--radius);
        box-shadow: var(--shadow); }
th, td { text-align: left; padding: .6rem .75rem; vertical-align: top;
         border-bottom: 1px solid var(--line); font-size: .92rem; }
th { font-size: .72rem; text-transform: uppercase; letter-spacing: .06em;
     color: var(--muted); font-weight: 700; background: var(--surface-2); }
tr:last-child td { border-bottom: 0; }
td.cell-actions { text-align: right; white-space: nowrap; }
td.cell-actions form { display: inline; }
@media (max-width: 719px) {
  table.collapse, table.collapse tbody { display: block; }
  table.collapse thead { display: none; }
  table.collapse tr { display: block; padding: .4rem .9rem; }
  table.collapse tr + tr { border-top: 1px solid var(--line); }
  table.collapse td { display: grid; grid-template-columns: 6.5rem 1fr;
                      gap: .6rem; border: 0; padding: .3rem 0; }
  table.collapse td::before { content: attr(data-label); font-size: .7rem;
    text-transform: uppercase; letter-spacing: .06em; color: var(--muted);
    font-weight: 700; padding-top: .2rem; }
  table.collapse td.cell-actions { display: block; text-align: left;
                                   padding-top: .5rem; }
  table.collapse td.cell-actions::before { display: none; }
  table.collapse td:empty { display: none; }
}

/* -- pager / filters -------------------------------------------------------- */
.pager { display: flex; flex-wrap: wrap; gap: .5rem 1rem; align-items: center;
         justify-content: space-between; margin: 0 0 1rem; }
.pager a { font-weight: 600; text-decoration: none; }
.filters .row { align-items: flex-end; }
.toolbar { display: flex; flex-wrap: wrap; gap: .6rem; margin: 0 0 1rem; }
"""

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(title)s</title>
<link rel="stylesheet" href="/style.css"></head>
<body>%(nav)s
<main class="wrap">%(banner)s
%(body)s
</main></body></html>"""

WILDCARD_DIALOG = """
%(psl_alert)s
<div class="warn">
<h1>%(pattern)s &mdash; approve every subdomain?</h1>
<p>This approves every name under <strong>%(base)s</strong>, including ones
that don't exist yet.</p>
<p><strong>Can a stranger sign up and get their own name here?</strong> If yes,
you're approving them too. Anyone could host a server at
<strong>whatever.%(base)s</strong> and your agent would be allowed to reach it.</p>
<p>Services like this include hosting platforms, cloud storage, and tunnelling
providers. Safe wildcards are ones where a single company owns every
subdomain &mdash; a vendor's own API or package registry.</p>
</div>
<div class="card">
<h2>Safer: add the exact hostname instead</h2>
<p class="meta">If you're not certain, enter the exact hostname instead:</p>
<form method="post" action="/add" class="row">
<input type="hidden" name="csrf" value="%(csrf)s">
<label class="field"><span>Hostname</span>
<input type="text" name="pattern" placeholder="host.%(base)s"
 autocapitalize="none" autocorrect="off" spellcheck="false"></label>
<button name="mode" value="exact" class="btn-primary">Add the exact hostname</button>
</form>
</div>
<div class="card">
<h2>Or approve the wildcard</h2>
<form method="post" action="/add-confirm" class="stack">
<input type="hidden" name="csrf" value="%(csrf)s">
<input type="hidden" name="pattern" value="%(pattern)s">
<label class="field"><span>Type <strong>%(base)s</strong> to confirm</span>
<input type="text" name="typed" autocomplete="off" autocapitalize="none"
 autocorrect="off" spellcheck="false"></label>
<div class="field"><span>Expiry</span>
<div class="choices">
<label><input type="radio" name="scope" value="24h" checked> 24 hours</label>
<label><input type="radio" name="scope" value="permanent"> permanent</label>
</div>
<p class="meta">24 hours is the default &mdash; wildcards are usually added
under pressure, and urgency is exactly when permanent decisions should not
be made. Permanent is the deliberate second choice.</p></div>
<div class="actions"><button class="btn-deny">Approve wildcard</button></div>
</form>
</div>
"""


def _fmt_ts(ts):
    if ts is None:
        return "never"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def esc(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def _table(headers, rows):
    """A table that collapses into labelled cards on narrow screens: each
    cell carries its column header as data-label for the stylesheet to show.
    Cells arrive as already-escaped HTML; an empty header marks the actions
    column, which gets no label."""
    head = "".join("<th>%s</th>" % esc(h) for h in headers)
    out = ['<div class="table-wrap"><table class="collapse"><thead><tr>%s'
           "</tr></thead><tbody>" % head]
    for cells in rows:
        out.append("<tr>" + "".join(
            '<td data-label="%s"%s>%s</td>'
            % (esc(h), ' class="cell-actions"' if not h else "", cell)
            for h, cell in zip(headers, cells)
        ) + "</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def _strong(value):
    """A host/pattern cell; empty stays empty so the stacked layout can
    hide the row instead of printing a label with nothing after it."""
    return '<span class="pattern">%s</span>' % esc(value) if value else ""


def _muted(value):
    return '<span class="meta">%s</span>' % esc(value) if value else ""


NAV_LINKS = (("/", "Pending"), ("/allowlist", "Allowlist"),
             ("/activity", "Activity"), ("/add", "Add"))


class PanelApp:
    """Request-independent core, shared by the HTTP handler and the tests."""

    def __init__(self, cfg: config.Config, conn=None):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.conn = conn if conn is not None else db.open_db(cfg.get("paths", "db"))
        self.tlds = validation.load_tlds(cfg.get("paths", "tld_list"))
        self.blocked = validation.load_blocked(cfg.get("paths", "blocked_domains"))
        self.psl = validation.load_psl(cfg.get("paths", "public_suffix_list"))
        db.merge_www_rows(self.conn, self.psl)
        self.textlog = db.TextLog(
            cfg.get("paths", "decisions_log"),
            cfg.get("log", "rotate_bytes"),
            cfg.get("log", "keep"),
        )
        self.login_failures = []

    # -- auth ------------------------------------------------------------

    def check_password(self, password: str) -> bool:
        if PasswordHasher is None:
            return False
        stored = db.get_setting(self.conn, "panel_password_hash")
        if not stored:
            return False
        try:
            PasswordHasher().verify(stored, password)
            return True
        except VerifyMismatchError:
            return False
        except Exception:
            return False

    def login_locked_out(self) -> bool:
        cutoff = time.time() - LOGIN_LOCKOUT_SECONDS
        self.login_failures = [t for t in self.login_failures if t > cutoff]
        return len(self.login_failures) >= LOGIN_MAX_FAILURES

    def session_seconds(self) -> int:
        """Login lifetime; the cookie's Max-Age and the stored expiry agree."""
        return int(self.cfg.get("panel", "session_hours") * 3600)

    def new_session(self) -> str:
        """Sessions persist in the database (hashed) so a panel restart or a
        reboot does not sign every device out mid-month; a fixed expiry from
        login, not sliding, so a stolen cookie has a known last day."""
        token = secrets.token_urlsafe(32)
        with self.lock:
            ts = db.now()
            db.create_session(
                self.conn, token, secrets.token_urlsafe(32), ts,
                ts + self.session_seconds(),
            )
        return token

    def session_for(self, token):
        if not token:
            return None
        return db.get_session(self.conn, token, db.now())

    def drop_session(self, token):
        if token:
            with self.lock:
                db.delete_session(self.conn, token)

    # -- expiry mapping (spec section 11.6) ------------------------------

    def scope_expiry(self, scope, ts):
        if scope == "once":
            # A backstop so an approved-but-never-used 'once' grant cannot sit
            # in the allowlist forever showing "Expires: never"; consumption
            # normally retires it first.
            return ts + 3600
        if scope == "session":
            return ts + self.cfg.get("scopes", "session_hours") * 3600
        if scope == "24h":
            return ts + 86400
        if scope == "permanent":
            return None
        raise ValueError("unknown scope")

    # -- operations ------------------------------------------------------

    def decide(self, req_id, action, scope, reason):
        with self.lock:
            ts = db.now()
            req = db.get_request(self.conn, req_id)
            if req is None or req["status"] != "pending":
                return "request is no longer pending"
            if action == "approve":
                if scope not in ("once", "session", "24h", "permanent"):
                    return "unknown scope"
                db.add_allowlist(
                    self.conn, req["host"], "exact", req["port"], "operator",
                    scope, self.scope_expiry(scope, ts), "approval",
                )
                db.decide_request(self.conn, req_id, "approved", "operator",
                                  reason, ts)
                db.log_event(self.conn, self.textlog, ts, "human_decision",
                             req["host"], req["port"], "operator", "ALLOWED",
                             "approved scope=%s" % scope)
                return None
            if action == "deny":
                db.decide_request(self.conn, req_id, "denied", "operator",
                                  reason, ts)
                db.log_event(self.conn, self.textlog, ts, "human_decision",
                             req["host"], req["port"], "operator",
                             "DENIED_BY_ADMIN", "denied")
                return None
            return "unknown action"

    def psl_conflict(self, base):
        """(kind, zone) when a wildcard base is or spans a Public Suffix List
        zone, else None. Drives the prominent dialog warning and the override
        marker in the decision log; the choice itself stays with the operator."""
        return validation.wildcard_psl_conflict(base, self.psl)

    def manual_add(self, pattern, scope, note=None):
        """Add an exact entry, or signal that the wildcard dialog is needed.
        Returns (status, data): ('added', ids) | ('wildcard', base) | ('error', msg).
        """
        with self.lock:
            ts = db.now()
            try:
                kind, base = validation.classify_pattern(pattern, self.tlds)
            except validation.ValidationError as exc:
                return "error", "rejected: %s" % exc.code
            if kind == "exact":
                # www.X and X are one entry; store the bare form (wildcard
                # bases are never folded — that would change their scope).
                base = validation.canonical_host(base, self.psl)
            if validation.is_blocked(base, self.blocked):
                db.log_event(self.conn, self.textlog, ts, "manual_add", base,
                             443, "operator", "DOMAIN_PERMANENTLY_BLOCKED",
                             "refused")
                return "error", "rejected: DOMAIN_PERMANENTLY_BLOCKED"
            if kind == "wildcard":
                return "wildcard", base
            if scope not in ("once", "session", "24h", "permanent"):
                return "error", "unknown scope"
            ids = db.add_allowlist(
                self.conn, base, "exact", 443, "operator", scope,
                self.scope_expiry(scope, ts), "manual", db.clean_note(note),
            )
            db.log_event(self.conn, self.textlog, ts, "manual_add", base, 443,
                         "operator", "ALLOWED", "exact scope=%s" % scope)
            return "added", ids

    def confirm_wildcard(self, pattern, typed, scope):
        """Complete the section 8.3 dialog: typed base must match exactly."""
        with self.lock:
            ts = db.now()
            try:
                kind, base = validation.classify_pattern(pattern, self.tlds)
            except validation.ValidationError as exc:
                return "rejected: %s" % exc.code
            if kind != "wildcard":
                return "not a wildcard"
            if validation.is_blocked(base, self.blocked):
                return "rejected: DOMAIN_PERMANENTLY_BLOCKED"
            if (typed or "").strip().lower() != base:
                return "typed domain does not match — type %s exactly" % base
            if scope not in ("24h", "permanent"):
                return "wildcards allow only 24h or permanent"
            db.add_allowlist(
                self.conn, base, "wildcard", 443, "operator", scope,
                self.scope_expiry(scope, ts), "manual",
            )
            # A wildcard on or spanning a PSL zone was approved past the
            # prominent warning: the decision is the operator's, so stamp it
            # where the monthly review will see it.
            conflict = validation.wildcard_psl_conflict(base, self.psl)
            detail = "wildcard scope=%s" % scope
            if conflict:
                detail += " PSL-ZONE OVERRIDE (%s)" % conflict[1]
            db.log_event(self.conn, self.textlog, ts, "manual_add", base, 443,
                         "operator", "ALLOWED", detail)
            return None

    def revoke(self, entry_id):
        with self.lock:
            ts = db.now()
            row = self.conn.execute(
                "SELECT pattern, port FROM allowlist WHERE id = ?", (entry_id,)
            ).fetchone()
            if row is None:
                return
            db.revoke_entry(self.conn, entry_id, ts)
            db.log_event(self.conn, self.textlog, ts, "revoke", row["pattern"],
                         row["port"], "operator", None, "entry %d" % entry_id)

    def import_text(self, text):
        """Operator-pasted list import: adds what is missing, never replaces,
        and reports every refused line with its reason."""
        with self.lock:
            result = db.import_user_text(
                self.conn, text, self.tlds, self.blocked, self.psl, "operator"
            )
            db.log_event(
                self.conn, self.textlog, db.now(), "list_import", None, None,
                "operator", None,
                "IMPORT: added %d, already present %d, rejected %d"
                % (result["added"], result["present"], len(result["rejected"])),
            )
            return result

    def export_text(self):
        with self.lock:
            lines = db.export_lines(self.conn, db.now())
        return "\n".join(
            ["# agent-filter allowlist export",
             "# format: host port  # description",
             "# wildcards re-import only through the panel's Add dialog"]
            + lines
        ) + "\n"

    def erase_all_entries(self):
        """Revoke every active entry, every source; returns the count. The
        rows and the decision log keep the history, and the Add page's
        load buttons restore the shipped lists afterwards."""
        with self.lock:
            ts = db.now()
            count = db.erase_all(self.conn, ts)
            db.log_event(self.conn, self.textlog, ts, "erase_all", None, None,
                         "operator", None,
                         "ERASE ALL: %d entries revoked" % count)
            return count

    def active_total(self):
        return db.count_allowlist(self.conn, db.now())

    # -- default list (optional bulk import) -----------------------------

    def default_list_counts(self):
        """(hosts in the shipped file or None if absent, active imported)."""
        path = self.cfg.get("paths", "default_allowlist")
        try:
            with open(path, "r", encoding="utf-8") as fh:
                available = sum(
                    1 for line in fh if line.split("#", 1)[0].strip()
                )
        except OSError:
            available = None
        active = db.active_count_by_source(self.conn, "default", db.now())
        return available, active

    def import_defaults(self):
        """Import the shipped default list; None on success, error text on
        failure. The file passes the same validation and blocked-domain gate
        as every other path, and a re-import only adds what is missing."""
        with self.lock:
            ts = db.now()
            path = self.cfg.get("paths", "default_allowlist")
            try:
                added, skipped = db.import_list_file(
                    self.conn, path, self.tlds, self.blocked, self.psl,
                    "operator", "default", "default list",
                )
            except OSError:
                return "no default list file is installed at %s" % path
            except ValueError as exc:
                return "default list rejected: %s" % exc
            db.log_event(self.conn, self.textlog, ts, "default_import", None,
                         None, "operator", "ALLOWED",
                         "added=%d skipped=%d" % (added, skipped))
            return None

    def load_shipped(self):
        """Re-load the staged default lists — the panel's recovery path
        after an erase. Returns (added, error)."""
        with self.lock:
            base = os.path.dirname(self.cfg.get("paths", "default_allowlist"))
            added = 0
            for name in ("starter-allowlist.txt", "host-mode-allowlist.txt"):
                path = os.path.join(base, name)
                if not os.path.exists(path):
                    continue
                try:
                    n, _ = db.import_list_file(
                        self.conn, path, self.tlds, self.blocked, self.psl,
                        "operator", "starter", None,
                    )
                except (OSError, ValueError) as exc:
                    return added, str(exc)
                added += n
            db.log_event(self.conn, self.textlog, db.now(), "shipped_load",
                         None, None, "operator", None,
                         "default lists reloaded: %d added" % added)
            return added, None

    def catalog_groups(self):
        """The catalog's group layer, or [] if the file is absent."""
        path = self.cfg.get("paths", "default_allowlist")
        try:
            return db.parse_catalog_groups(path, self.tlds, self.blocked,
                                           self.psl)
        except OSError:
            return []

    def import_catalog_group(self, index):
        with self.lock:
            groups = self.catalog_groups()
            if not 0 <= index < len(groups):
                return "unknown catalog group"
            title, entries = groups[index]
            added, _ = db.import_entries(self.conn, entries, "operator",
                                         "default")
            db.log_event(self.conn, self.textlog, db.now(), "default_import",
                         None, None, "operator", None,
                         "catalog group %r: %d added" % (title, added))
            return None

    def remove_defaults(self):
        with self.lock:
            ts = db.now()
            removed = db.revoke_by_source(self.conn, "default", ts)
            db.log_event(self.conn, self.textlog, ts, "default_remove", None,
                         None, "operator", None, "removed=%d" % removed)

    PAUSE_MINUTES = (15, 60)

    def pause_enforcement(self, minutes):
        """Open the proxy gate; error text or None. `minutes` is 15, 60, or
        None for the operator's off switch — off until explicitly resumed.
        The every-page banner and the ENFORCEMENT PAUSE log stamp (checked by
        the monthly review) are what keep a forgotten switch visible."""
        if minutes is not None and minutes not in self.PAUSE_MINUTES:
            return "unknown pause duration"
        with self.lock:
            ts = db.now()
            if minutes is None:
                db.set_setting(self.conn, "enforcement_paused_until", "off")
                detail = "ENFORCEMENT PAUSE indefinite (off until resumed)"
            else:
                until = ts + minutes * 60
                db.set_setting(self.conn, "enforcement_paused_until", str(until))
                detail = "ENFORCEMENT PAUSE %dm until %d" % (minutes, until)
            db.log_event(self.conn, self.textlog, ts, "enforcement_pause",
                         None, None, "operator", "ALLOWED", detail)
        return None

    def resume_enforcement(self):
        with self.lock:
            ts = db.now()
            db.set_setting(self.conn, "enforcement_paused_until", "0")
            db.log_event(self.conn, self.textlog, ts, "enforcement_resume",
                         None, None, "operator", None, "enforcement resumed")

    def pending_count(self):
        return self.conn.execute(
            "SELECT COUNT(*) AS n FROM requests WHERE status = 'pending'"
        ).fetchone()["n"]

    def compromise_banner(self):
        trips = self.conn.execute(
            "SELECT COUNT(*) AS n FROM decisions WHERE event = 'rate_limit_trip'"
            " AND detail = 'auto_rejects' AND ts > ?",
            (db.now() - 86400,),
        ).fetchone()["n"]
        if trips:
            return (
                '<p class="banner">Auto-reject budget exhausted in the last 24h.'
                " Something as the agent is probing the boundary at machine"
                " speed — treat this as a compromise signal and review recent"
                " activity.</p>"
            )
        return ""


class Handler(http.server.BaseHTTPRequestHandler):
    app: PanelApp = None
    server_version = "approval-panel"
    sys_version = ""

    # -- plumbing --------------------------------------------------------

    def log_message(self, *args):
        pass

    def _headers(self, status=200, extra=None, content_type="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; form-action 'self';"
            " base-uri 'none'; frame-ancestors 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()

    def _nav(self):
        current = urllib.parse.urlparse(self.path).path
        pending = self.app.pending_count()
        links = []
        for href, label in NAV_LINKS:
            count = (' <span class="count">%d</span>' % pending
                     if href == "/" and pending else "")
            links.append(
                '<a href="%s"%s>%s%s</a>'
                % (href, ' class="active" aria-current="page"'
                   if href == current else "", label, count)
            )
        return (
            '<header class="top"><div class="top-inner">'
            '<a class="brand" href="/">agent<span>-</span>filter</a>'
            "<nav>%s</nav>"
            '<form method="post" action="/logout" class="logout">'
            '<input type="hidden" name="csrf" value="%s">'
            '<button class="btn-ghost btn-small">Log out</button></form>'
            "</div></header>" % ("".join(links), esc(self._csrf()))
        )

    def _page(self, body, status=200, nav=True, title="Approval panel"):
        navigation = self._nav() if nav else ""
        banner = self.app.compromise_banner() if nav else ""
        if nav:
            state = db.pause_state(self.app.conn)
            if state == -1 or state > db.now():
                deadline = ("turned back on" if state == -1
                            else esc(_fmt_ts(state)))
                banner += (
                    '<div class="danger"><p class="danger-title">Allowlist'
                    " enforcement is %s</p><p>Until %s every valid"
                    " destination is allowed and logged. Blocked domains stay"
                    " refused; denied requests keep queueing for review.</p>"
                    '<form method="post" action="/resume">'
                    '<input type="hidden" name="csrf" value="%s">'
                    "<button>Resume enforcement now</button></form></div>"
                    % ("OFF" if state == -1 else "paused",
                       deadline, esc(self._csrf()))
                )
        self._headers(status)
        self.wfile.write(
            (PAGE % {"nav": navigation, "banner": banner, "body": body,
                     "title": esc(title)}).encode()
        )

    def _session(self):
        cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get(SESSION_COOKIE)
        return self.app.session_for(morsel.value if morsel else None)

    def _csrf(self):
        session = self._session()
        return session["csrf"] if session else ""

    def _form(self, cap=65536):
        try:
            length = min(int(self.headers.get("Content-Length", 0) or 0), cap)
        except ValueError:
            length = 0
        data = self.rfile.read(length).decode("utf-8", "replace")
        return {
            k: v[0] for k, v in urllib.parse.parse_qs(data, keep_blank_values=True).items()
        }

    @staticmethod
    def _int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _require_auth(self):
        if self._session() is None:
            self._headers(303, {"Location": "/login"})
            return False
        return True

    def _require_csrf(self, form):
        session = self._session()
        supplied = form.get("csrf", "")
        if session is None or not hmac.compare_digest(session["csrf"], supplied):
            self._page("<p class='error'>Bad or missing CSRF token.</p>", 403)
            return False
        return True

    # -- GET -------------------------------------------------------------

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/style.css":
            self._headers(200, content_type="text/css")
            self.wfile.write(CSS.encode())
            return
        if path == "/login":
            self._login_page()
            return
        if not self._require_auth():
            return
        if path == "/":
            self._pending_page()
        elif path == "/allowlist":
            self._allowlist_page(
                urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            )
        elif path == "/activity":
            self._activity_page()
        elif path == "/add":
            self._add_page()
        elif path == "/export":
            data = self.app.export_text().encode("utf-8")
            self._headers(200, {
                "Content-Disposition":
                    'attachment; filename="agent-filter-allowlist.txt"',
            }, content_type="text/plain; charset=utf-8")
            self.wfile.write(data)
        else:
            self._page('<p class="error">Not found.</p>', 404, title="Not found")

    def _login_page(self, error=""):
        body = (
            '<div class="login"><div class="card">'
            "<h1>Approval panel</h1>"
            '<p class="meta">agent-filter &middot; reachable only over your'
            " tailnet</p>%s"
            '<form method="post" action="/login">'
            '<label class="field"><span>Password</span>'
            '<input type="password" name="password" autofocus'
            ' autocomplete="current-password"></label>'
            '<button class="btn-primary">Log in</button></form>'
            "</div></div>"
            % ('<p class="error">%s</p>' % esc(error) if error else "")
        )
        self._page(body, nav=False, title="Log in — Approval panel")

    def _pending_page(self):
        rows = db.pending_requests(self.app.conn)
        cards = []
        for row in rows:
            rationale = (
                '<div class="untrusted"><span class="label">UNTRUSTED INPUT'
                " &mdash; written by the agent</span><pre>%s</pre></div>"
                % esc(row["rationale"])
                if row["rationale"]
                else '<p class="meta">no rationale supplied</p>'
            )
            cards.append(
                '<article class="card"><h2 class="host">%s:%d</h2>'
                '<p class="meta">origin %s &middot; first seen %s &middot;'
                " asked %d time(s)</p>%s"
                '<form method="post" action="/decide" class="decide">'
                '<input type="hidden" name="csrf" value="%s">'
                '<input type="hidden" name="req_id" value="%d">'
                '<div class="row">'
                '<label class="field"><span>Deny reason <small>(optional,'
                " shown to the agent)</small></span>"
                '<input type="text" name="reason" placeholder="e.g. not for'
                ' this project"></label>'
                '<button name="action" value="deny" class="btn-deny">Deny'
                "</button></div>"
                '<div class="row">'
                '<label class="field narrow"><span>Scope</span>'
                '<select name="scope">'
                '<option value="once">once</option>'
                '<option value="session">session</option>'
                '<option value="24h" selected>24h</option>'
                '<option value="permanent">permanent</option></select></label>'
                '<button name="action" value="approve" class="btn-approve">'
                "Approve</button></div>"
                "</form></article>"
                % (
                    esc(row["host"]), row["port"], esc(row["origin"]),
                    _fmt_ts(row["first_seen"]), row["count"], rationale,
                    esc(self._csrf()), row["id"],
                )
            )
        self._page(
            "<h1>Pending requests</h1>"
            + ("".join(cards)
               or '<div class="card empty">Queue is empty. Nothing is'
                  " waiting for a decision.</div>"),
            title="Pending — Approval panel",
        )

    PAGE_SIZES = (50, 100, 250, 500)

    def _allowlist_page(self, params=None):
        params = params or {}
        q = params.get("q", [""])[0].strip().lower()[:253]
        try:
            size = int(params.get("size", ["50"])[0])
        except ValueError:
            size = 50
        if size not in self.PAGE_SIZES:
            size = 50
        try:
            page = max(1, int(params.get("page", ["1"])[0]))
        except ValueError:
            page = 1
        src = params.get("src", [""])[0]
        if src not in ("", "default", "starter", "user"):
            src = ""
        ts = db.now()
        total = db.count_allowlist(self.app.conn, ts, q or None, src or None)
        pages = max(1, -(-total // size))
        page = min(page, pages)
        rows = db.list_allowlist(
            self.app.conn, ts, q=q or None, limit=size,
            offset=(page - 1) * size, src=src or None
        )

        def link(target):
            return "/allowlist?" + urllib.parse.urlencode(
                {"q": q, "size": size, "page": target, "src": src}
            )

        src_options = "".join(
            '<option value="%s"%s>%s</option>'
            % (v, " selected" if v == src else "", label)
            for v, label in (
                ("", "all origins"), ("starter", "default list"),
                ("default", "catalog"), ("user", "added by you"),
            )
        )
        controls = (
            '<form method="get" action="/allowlist" class="card filters">'
            '<div class="row">'
            '<label class="field"><span>Filter</span>'
            '<input type="text" name="q" value="%s" placeholder="pattern or'
            ' description" autocapitalize="none" autocorrect="off"></label>'
            '<label class="field narrow"><span>Origin</span>'
            '<select name="src">%s</select></label>'
            '<label class="field narrow"><span>Per page</span>'
            '<select name="size">%s</select></label>'
            '<button class="btn-primary">Apply</button></div></form>'
            % (
                esc(q),
                src_options,
                "".join(
                    '<option value="%d"%s>%d</option>'
                    % (s, " selected" if s == size else "", s)
                    for s in self.PAGE_SIZES
                ),
            )
        )
        nav_parts = ['<span class="meta">%d matching entr%s &middot; page %d'
                     " of %d</span>" % (total, "y" if total == 1 else "ies",
                                        page, pages)]
        steps = []
        if page > 1:
            steps.append(
                '<a href="%s">&laquo; Previous</a>' % esc(link(page - 1))
            )
        if page < pages:
            steps.append('<a href="%s">Next &raquo;</a>' % esc(link(page + 1)))
        if steps:
            nav_parts.append("<span>%s</span>" % " &nbsp;&middot;&nbsp; ".join(steps))
        pager = '<div class="pager">%s</div>' % "".join(nav_parts)

        origin_label = {"default": "catalog", "starter": "default",
                        "manual": "you", "approval": "you (approved)"}
        table_rows = []
        for row in rows:
            flag = ' <span class="badge wildcard">WILDCARD</span>' \
                if row["kind"] == "wildcard" else ""
            table_rows.append((
                '<span class="pattern">%s</span>%s' % (esc(row["pattern"]), flag),
                esc(row["kind"]),
                str(row["port"]),
                _muted(row["note"]),
                esc(row["scope"]),
                _fmt_ts(row["expires_at"]),
                esc(origin_label.get(row["source"], row["source"])),
                '<form method="post" action="/revoke">'
                '<input type="hidden" name="csrf" value="%s">'
                '<input type="hidden" name="entry_id" value="%d">'
                '<button class="btn-deny btn-small">Revoke</button></form>'
                % (esc(self._csrf()), row["id"]),
            ))
        body = ["<h1>Active allowlist</h1>", controls, pager]
        if table_rows:
            body.append(_table(
                ("Pattern", "Kind", "Port", "Description", "Scope",
                 "Expires", "Origin", ""), table_rows,
            ))
            body.append(pager)
        else:
            body.append('<div class="card empty">No entries match.</div>')
        body.append(self._list_tools_section())
        self._page("".join(body), title="Allowlist — Approval panel")

    def _activity_page(self):
        rows = db.recent_events(self.app.conn)
        grouped = {}
        lines = []
        for row in rows:
            if row["event"] == "auto_reject":
                key = (row["host"] or "-", row["reason_code"])
                grouped[key] = grouped.get(key, 0) + 1
            else:
                lines.append(row)
        body = ["<h1>Recent activity</h1>"]
        if grouped:
            body.append(
                "<h2>Auto-rejections</h2><p class='meta'>These never reach the"
                " queue. A burst — variations circling one domain, or odd"
                " encodings — is an attacker feeling out the boundary, not"
                " normal work.</p>"
            )
            body.append(_table(
                ("Host", "Code", "Count"),
                [('<span class="pattern">%s</span>' % esc(host), esc(code),
                  str(count))
                 for (host, code), count in sorted(grouped.items())],
            ))
        body.append("<h2>Events</h2>")
        if lines:
            body.append(_table(
                ("Time", "Event", "Host", "Code", "Detail"),
                [(_fmt_ts(row["ts"]), esc(row["event"]),
                  _strong(row["host"]), esc(row["reason_code"]),
                  _muted(row["detail"]))
                 for row in lines[:100]],
            ))
        else:
            body.append('<div class="card empty">No events yet.</div>')
        self._page("".join(body), title="Activity — Approval panel")

    def _psl_alert(self, base):
        """The prominent warning shown when a wildcard base is or spans a
        Public Suffix List zone. Advisory by design: the operator may still
        confirm, and doing so is recorded as an override."""
        conflict = self.app.psl_conflict(base)
        if conflict is None:
            return ""
        kind, zone = conflict
        if kind == "suffix":
            lead = ("<strong>%s is a public registration zone.</strong>"
                    % esc(zone))
        else:
            lead = ("<strong>This wildcard spans the public registration"
                    " zone %s.</strong>" % esc(zone))
        return (
            '<div class="danger">'
            '<p class="danger-title">Stop &mdash; read this first</p>'
            "<p>%s Unrelated strangers provably register their own names"
            " there; the Public Suffix List exists to record exactly that."
            " Approving this wildcard is equivalent to allowing the open"
            " Internet: an attacker can mint a fresh name in this zone and"
            " point a tunnel relay at it.</p>"
            '<p><a href="/add">Cancel and add exact hostnames instead</a>.'
            " If you confirm below anyway, the decision is yours and is"
            " recorded in the activity log as an override.</p></div>" % lead
        )

    def _add_page(self, error=""):
        body = (
            "<h1>Add to allowlist</h1>%s"
            '<div class="card">'
            "<p class='meta'>Judge every wildcard by one question: can a"
            " stranger sign up and get their own name under this domain?"
            " If yes, approving the wildcard approves them too.</p>"
            '<form method="post" action="/add" class="stack">'
            '<input type="hidden" name="csrf" value="%s">'
            '<label class="field"><span>Hostname</span>'
            '<input type="text" name="pattern" autocapitalize="none"'
            ' autocorrect="off" spellcheck="false" inputmode="url"'
            ' placeholder="host.example.com or *.example.com"></label>'
            '<label class="field"><span>Description <small>(optional)</small>'
            '</span><input type="text" name="note" maxlength="255"'
            ' placeholder="one line on what this host is"></label>'
            '<div class="row"><label class="field narrow"><span>Scope</span>'
            '<select name="scope">'
            '<option value="once">once</option>'
            '<option value="session">session</option>'
            '<option value="24h">24h</option>'
            '<option value="permanent" selected>permanent</option></select>'
            '</label><button class="btn-primary">Add</button></div>'
            "</form></div>"
            % ('<p class="error">%s</p>' % esc(error) if error else "",
               esc(self._csrf()))
        )
        self._page(
            body + self._default_list_section() + self._pause_section(),
            title="Add — Approval panel",
        )

    def _pause_section(self):
        return (
            '<div class="card"><h2>Pause enforcement</h2>'
            "<p class='meta'>Opens the gate to every valid destination for a"
            " fixed window — for install bursts that would otherwise mean"
            " approving hosts under pressure. The firewall stays up, every"
            " destination is still logged, blocked domains stay refused, and"
            " denied requests keep queueing for review afterwards. A banner"
            " shows on every page until the window ends; the monthly review"
            " checks the log for pause stamps.</p>"
            '<form method="post" action="/pause" class="stack">'
            '<input type="hidden" name="csrf" value="%s">'
            '<div class="choices">'
            '<label><input type="radio" name="minutes" value="15" checked>'
            " 15 minutes</label>"
            '<label><input type="radio" name="minutes" value="60">'
            " 60 minutes</label>"
            '<label><input type="radio" name="minutes" value="off">'
            " off until turned back on</label></div>"
            '<div class="actions"><button class="btn-deny">Pause</button>'
            "</div></form></div>"
            % esc(self._csrf())
        )

    def _import_result_page(self, result):
        body = [
            "<h1>Import finished</h1>",
            '<div class="card"><p>Added <strong>%d</strong> &middot; already'
            " present <strong>%d</strong> &middot; rejected <strong>%d"
            "</strong>.</p>"
            % (result["added"], result["present"], len(result["rejected"])),
        ]
        if result["rejected"]:
            body.append(
                "<p class='meta'>Nothing existing was touched. Each rejected"
                " line and the reason:</p></div>"
            )
            body.append(_table(
                ("Line", "Entry", "Reason"),
                [(str(lineno), '<span class="pattern">%s</span>' % esc(entry),
                  esc(reason))
                 for lineno, entry, reason in result["rejected"]],
            ))
        else:
            body.append("</div>")
        body.append('<p><a href="/allowlist">Back to the allowlist</a></p>')
        self._page("".join(body), title="Import — Approval panel")

    def _list_tools_section(self):
        return (
            '<div class="card"><h2>Export, import, erase</h2>'
            "<p class='meta'><a href=\"/export\">Export the current list"
            "</a> as plain text: one entry per line with its description."
            " To import, paste a list below — one <code>host [port]"
            " [# description]</code> per line. Importing only <strong>adds"
            "</strong>: nothing existing is replaced or removed. To replace"
            " the list, use Erase first, then import. Refused lines"
            " (wildcards, blocked or invalid hosts) are reported with"
            " reasons, not silently dropped.</p>"
            '<form method="post" action="/import" class="stack">'
            '<input type="hidden" name="csrf" value="%s">'
            '<textarea name="text" rows="6" autocapitalize="none"'
            ' autocorrect="off" spellcheck="false"'
            ' placeholder="api.example.com 443  # example service"></textarea>'
            '<div class="actions"><button class="btn-primary">Import</button>'
            "</div></form>"
            '<form method="post" action="/erase" class="actions">'
            '<input type="hidden" name="csrf" value="%s">'
            '<button class="btn-deny">Erase the entire allowlist&hellip;'
            "</button><span class='meta'>asks for confirmation first</span>"
            "</form></div>"
            % (esc(self._csrf()), esc(self._csrf()))
        )

    def _default_list_section(self):
        available, active = self.app.default_list_counts()
        groups = self.app.catalog_groups()
        csrf = esc(self._csrf())
        body = [
            '<div class="card"><h2>Shipped lists</h2>'
            "<p class='meta'><strong>Default list</strong> — the handful of"
            " hosts this guide's own flows need, loaded automatically at"
            " install (origin &ldquo;default&rdquo;). After an erase, this"
            " button is the restore; it only adds what is missing.</p>"
            '<form method="post" action="/load-shipped" class="toolbar">'
            '<input type="hidden" name="csrf" value="%s">'
            "<button>Load the default list</button></form>" % csrf,
            "<p class='meta'><strong>Catalog</strong> — a curated set of"
            " documentation, package-registry, reference, and open-data"
            " hosts an agent commonly needs to read. Exact hostnames only —"
            " no wildcards — each judged by the stranger-signup rule, each"
            " with a one-line description. Load it whole, or open a group"
            " to see its domains and load just that group (origin"
            " &ldquo;catalog&rdquo;). Loading only adds what is missing;"
            " revoke any entry individually, or the whole catalog.</p>",
        ]
        if available is None:
            body.append(
                "<p class='meta'>No catalog file is installed;"
                " rerun the installer to stage it.</p>"
            )
        else:
            body.append(
                '<form method="post" action="/import-defaults" class="toolbar">'
                '<input type="hidden" name="csrf" value="%s">'
                "<button>Load the whole catalog (%d hosts)</button>"
                "</form>" % (csrf, available)
            )
        if active:
            body.append(
                '<form method="post" action="/remove-defaults" class="toolbar">'
                '<input type="hidden" name="csrf" value="%s">'
                '<button class="btn-deny">Remove all catalog entries'
                " (%d active)</button></form>" % (csrf, active)
            )
        for i, (title, entries) in enumerate(groups):
            hosts = " &middot; ".join(
                esc(h if p == 443 else "%s %d" % (h, p))
                for h, p, _ in entries
            )
            body.append(
                "<details><summary><strong>%s</strong> &mdash; %d hosts"
                "</summary>"
                '<form method="post" action="/import-catalog-group"'
                ' class="toolbar">'
                '<input type="hidden" name="csrf" value="%s">'
                '<input type="hidden" name="group" value="%d">'
                '<button class="btn-small">Load this group</button></form>'
                "<p class='meta hosts'>%s</p></details>"
                % (esc(title), len(entries), csrf, i, hosts)
            )
        body.append("</div>")
        return "".join(body)

    # -- POST ------------------------------------------------------------

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        # A pasted allowlist import can legitimately exceed the normal cap.
        form = self._form(1048576 if path == "/import" else 65536)
        if path == "/login":
            self._do_login(form)
            return
        if not self._require_auth():
            return
        if not self._require_csrf(form):
            return
        if path == "/logout":
            cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            morsel = cookie.get(SESSION_COOKIE)
            self.app.drop_session(morsel.value if morsel else None)
            self._headers(303, {"Location": "/login", "Set-Cookie":
                          "%s=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/"
                          % SESSION_COOKIE})
        elif path == "/decide":
            error = self.app.decide(
                self._int(form.get("req_id")), form.get("action", ""),
                form.get("scope", ""), form.get("reason") or None,
            )
            if error:
                self._page("<p class='error'>%s</p>" % esc(error), 400)
            else:
                self._headers(303, {"Location": "/"})
        elif path == "/add":
            status, data = self.app.manual_add(
                form.get("pattern", ""), form.get("scope", "permanent"),
                form.get("note", ""),
            )
            if status == "added":
                self._headers(303, {"Location": "/allowlist"})
            elif status == "wildcard":
                self._page(
                    WILDCARD_DIALOG
                    % {
                        "pattern": esc("*." + data),
                        "base": esc(data),
                        "csrf": esc(self._csrf()),
                        "psl_alert": self._psl_alert(data),
                    }
                )
            else:
                self._add_page(error=data)
        elif path == "/add-confirm":
            error = self.app.confirm_wildcard(
                form.get("pattern", ""), form.get("typed", ""),
                form.get("scope", "24h"),
            )
            if error:
                self._page("<p class='error'>%s</p>" % esc(error), 400)
            else:
                self._headers(303, {"Location": "/allowlist"})
        elif path == "/load-shipped":
            added, error = self.app.load_shipped()
            if error:
                self._add_page(error=error)
            else:
                self._headers(303, {"Location": "/allowlist"})
        elif path == "/import-catalog-group":
            error = self.app.import_catalog_group(self._int(form.get("group")))
            if error:
                self._add_page(error=error)
            else:
                self._headers(303, {"Location": "/allowlist"})
        elif path == "/import-defaults":
            error = self.app.import_defaults()
            if error:
                self._add_page(error=error)
            else:
                self._headers(303, {"Location": "/allowlist"})
        elif path == "/remove-defaults":
            self.app.remove_defaults()
            self._headers(303, {"Location": "/allowlist"})
        elif path == "/revoke":
            self.app.revoke(self._int(form.get("entry_id")))
            self._headers(303, {"Location": "/allowlist"})
        elif path == "/import":
            result = self.app.import_text(form.get("text", ""))
            self._import_result_page(result)
        elif path == "/erase":
            total = self.app.active_total()
            self._page(
                '<div class="danger">'
                '<p class="danger-title">Erase the entire allowlist?</p>'
                "<p>This revokes all %d active entries — defaults, starter,"
                " and everything you added. The agent then reaches nothing"
                " until entries are approved again. The activity log keeps"
                " the history, and the Add page's <strong>load</strong>"
                " buttons restore the shipped lists afterwards.</p>"
                '<p><a href="/allowlist">Cancel</a></p></div>'
                '<form method="post" action="/erase-confirm" class="actions">'
                '<input type="hidden" name="csrf" value="%s">'
                '<button class="btn-deny">Erase all %d entries</button></form>'
                % (total, esc(self._csrf()), total),
                title="Erase — Approval panel",
            )
        elif path == "/erase-confirm":
            self.app.erase_all_entries()
            self._headers(303, {"Location": "/allowlist"})
        elif path == "/pause":
            minutes = form.get("minutes", "")
            error = self.app.pause_enforcement(
                None if minutes == "off" else self._int(minutes)
            )
            if error:
                self._page("<p class='error'>%s</p>" % esc(error), 400)
            else:
                self._headers(303, {"Location": "/add"})
        elif path == "/resume":
            self.app.resume_enforcement()
            self._headers(303, {"Location": "/add"})
        else:
            self._page('<p class="error">Not found.</p>', 404, title="Not found")

    def _do_login(self, form):
        if PasswordHasher is None:
            self._login_page("argon2 is not installed; run the installer.")
            return
        if not db.get_setting(self.app.conn, "panel_password_hash"):
            self._login_page("No password set. Run: sudo brokerctl set-password")
            return
        # The correct password always wins: the lockout throttles wrong
        # guesses but must never let an attacker spamming failures lock the
        # operator out of the panel at the moment approvals matter. argon2 is
        # slow and the panel is reachable only over the tailnet, so guessing
        # is already impractical.
        if self.app.check_password(form.get("password", "")):
            self.app.login_failures.clear()
            token = self.app.new_session()
            # Max-Age makes the cookie outlive the browser tab; without it
            # phones forget the login every time the browser is closed.
            self._headers(303, {
                "Location": "/",
                "Set-Cookie": "%s=%s; Max-Age=%d; HttpOnly; SameSite=Strict;"
                " Path=/" % (SESSION_COOKIE, token, self.app.session_seconds()),
            })
            return
        self.app.login_failures.append(time.time())
        if self.app.login_locked_out():
            self._login_page("Too many failed attempts; wait a minute.")
        else:
            self._login_page("Wrong password.")


# Where the tailscale CLI may live; PATH first, then the platform spots.
TS_CLI_CANDIDATES = (
    "tailscale",
    "/usr/local/bin/tailscale",
    "/opt/homebrew/bin/tailscale",
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    "/usr/bin/tailscale",
    "/usr/sbin/tailscale",
)

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def resolve_bind_ip(value, runner=subprocess.run):
    """Turn the configured panel.bind_ip into a concrete address.

    The literal "auto" asks the tailscale CLI for the machine's current
    Tailscale IPv4 at every service start, so the panel follows the node
    across re-authentications and IP changes with no config edit. The
    result must be a CGNAT (100.64/10) address — anything else means the
    CLI answered with something that is not a tailnet address, and binding
    it could expose the panel; fail loudly instead. Literal addresses pass
    through and keep the historical checks in serve()."""
    if value != "auto":
        return value
    last_error = None
    for candidate in TS_CLI_CANDIDATES:
        try:
            proc = runner(
                [candidate, "ip", "-4"],
                capture_output=True, text=True, timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode != 0:
            continue
        ip = (proc.stdout or "").strip().splitlines()
        ip = ip[0].strip() if ip else ""
        if not ip:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            # Not an address at all: the macOS App Store CLI prints a
            # sentence such as "The Tailscale GUI failed to start" with exit
            # status 0 when the app is not running. That is "no answer yet",
            # not a wrong address, so keep looking and say so below.
            last_error = ip
            continue
        if addr in _CGNAT:
            return ip
        raise SystemExit(
            "panel.bind_ip auto: %r from the tailscale CLI is not a"
            " Tailscale (100.64/10) address; refusing to bind it" % ip
        )
    hint = (" (the CLI said: %r)" % last_error) if last_error else ""
    raise SystemExit(
        "panel.bind_ip auto: no tailscale CLI answered with an address%s;"
        " is the Tailscale app running and signed in? (retrying via the"
        " service manager is expected until it is)" % hint
    )


def serve(cfg=None):
    cfg = cfg or config.load()
    bind_ip = resolve_bind_ip(cfg.get("panel", "bind_ip"))
    # Refuse loopback or an unset address: the panel is worthless if the agent
    # can reach it, and a config that failed to record the Tailscale IP must
    # not silently degrade to 127.0.0.1.
    if not bind_ip or bind_ip.startswith("127.") or bind_ip in ("::1", "0.0.0.0"):
        raise SystemExit(
            "panel.bind_ip must be the machine's Tailscale IPv4 or"
            " \"auto\", not %r; check /etc/approval-broker/config.toml"
            % bind_ip
        )
    Handler.app = PanelApp(cfg)
    server = http.server.ThreadingHTTPServer(
        (bind_ip, cfg.get("panel", "port")), Handler
    )
    server.serve_forever()


if __name__ == "__main__":
    serve()
