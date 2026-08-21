"""SQLite storage: allowlist, request queue, append-only decision log.

One writer discipline: callers serialise writes with their own lock; WAL mode
lets the panel and broker share the file. The decisions table is append-only —
there is deliberately no update or delete helper for it.
"""

import hashlib
import os
import sqlite3
import time

from . import validation

# Shared between SCHEMA and the CHECK-constraint rebuild in _migrate; the two
# must stay identical or a rebuilt table diverges from a fresh one.
ALLOWLIST_TABLE = """
CREATE TABLE IF NOT EXISTS allowlist (
  id INTEGER PRIMARY KEY,
  pattern TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('exact', 'wildcard')),
  port INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  expires_at INTEGER,
  scope TEXT NOT NULL DEFAULT 'permanent',
  source TEXT NOT NULL CHECK (source IN ('approval', 'manual', 'starter', 'default')),
  note TEXT,
  -- group_id links rows added together (a bare domain and its www twin) so
  -- revoke acts on the whole approval, not half of it.
  group_id INTEGER,
  -- a 'once' entry is retired by stamping consumed_at, not by mutating
  -- expires_at, so a single connection can pass both helper phases before
  -- the grant is spent.
  consumed_at INTEGER
);
"""

SCHEMA = ALLOWLIST_TABLE + """
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  rationale TEXT,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  origin TEXT NOT NULL CHECK (origin IN ('agent_submitted', 'proxy_denied')),
  status TEXT NOT NULL CHECK
    (status IN ('pending', 'approved', 'denied', 'auto_rejected', 'expired')),
  decided_at INTEGER,
  decided_by TEXT,
  decision_reason TEXT
);
CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  event TEXT NOT NULL,
  host TEXT,
  port INTEGER,
  actor TEXT NOT NULL,
  reason_code TEXT,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS panel_sessions (
  -- SHA-256 of the cookie token, never the token itself: a copy of this
  -- file must not be a bag of live logins.
  token_hash TEXT PRIMARY KEY,
  csrf TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_requests_hostport ON requests (host, port);
CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions (ts);
"""


def now() -> int:
    return int(time.time())


# One-line entry descriptions live in the allowlist `note` column.
MAX_NOTE_CHARS = 255


def clean_note(text):
    """Sanitize a one-line description: printable, trimmed, capped.
    Empty or whitespace-only becomes None."""
    if not text:
        return None
    text = _printable(str(text)).strip()
    return text[:MAX_NOTE_CHARS].strip() or None


# Nullable columns added to `allowlist` after the first release. CREATE TABLE
# IF NOT EXISTS never alters an existing table, so a database from an earlier
# install would be missing these; every query that names them would then throw
# and the broker would fail closed on *every* decision (BROKER_UNAVAILABLE)
# after an in-place upgrade. _migrate adds any that are absent.
_ALLOWLIST_ADDED_COLUMNS = {
    "group_id": "INTEGER",
    "consumed_at": "INTEGER",
}


_ALLOWLIST_COLUMN_ORDER = (
    "id, pattern, kind, port, created_at, created_by, expires_at,"
    " scope, source, note, group_id, consumed_at"
)


def _migrate(conn: sqlite3.Connection) -> None:
    existing = {row[1] for row in conn.execute("PRAGMA table_info(allowlist)")}
    for name, coltype in _ALLOWLIST_ADDED_COLUMNS.items():
        if name not in existing:
            # name/coltype are code constants, never user input.
            conn.execute("ALTER TABLE allowlist ADD COLUMN %s %s" % (name, coltype))
    conn.commit()
    # The source CHECK gained 'default' after the first release. SQLite cannot
    # alter a CHECK in place, so a table whose stored definition lacks the
    # quoted value is rebuilt once, after the column adds above so the copy
    # can name every current column. Every legacy source value is still valid
    # under the new constraint.
    stored = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'allowlist'"
    ).fetchone()
    if stored and "'default'" not in stored[0]:
        copy = (
            "INSERT INTO allowlist (%(cols)s) SELECT %(cols)s FROM allowlist_old;"
            % {"cols": _ALLOWLIST_COLUMN_ORDER}
        )
        conn.executescript(
            "BEGIN;"
            "ALTER TABLE allowlist RENAME TO allowlist_old;"
            + ALLOWLIST_TABLE + copy +
            "DROP TABLE allowlist_old;"
            "COMMIT;"
        )


def open_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript(SCHEMA)
        _migrate(conn)
    except sqlite3.OperationalError as exc:
        # Startup creates any table this version added, so a database the
        # service account cannot write stops the service here instead of at
        # the first approval. Name the file and the likely cause: the fix is
        # ownership, not code, and an unhandled traceback hides that.
        raise SystemExit(
            "cannot open the database %s for writing (%s). The broker and"
            " panel must be able to write it and its -wal/-shm siblings —"
            " on macOS as your login account, on Linux as the broker"
            " account; check their ownership and permissions." % (path, exc)
        )
    return conn


class TextLog:
    """Size-rotated plain-text mirror of the decisions table."""

    def __init__(self, path: str, rotate_bytes: int, keep: int):
        self.path = path
        self.rotate_bytes = rotate_bytes
        self.keep = keep

    def append(self, line: str):
        try:
            if (
                os.path.exists(self.path)
                and os.path.getsize(self.path) >= self.rotate_bytes
            ):
                for i in range(self.keep - 1, 0, -1):
                    src = "%s.%d" % (self.path, i)
                    if os.path.exists(src):
                        os.replace(src, "%s.%d" % (self.path, i + 1))
                os.replace(self.path, self.path + ".1")
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            # The database row is the durable record; a log-file failure must
            # not turn into a denial-of-decision.
            pass


def _printable(value):
    """Attacker-influenced strings (hostnames, details) must not be able to
    forge log lines or emit terminal control sequences."""
    return "".join(
        ch if 32 <= ord(ch) <= 126 else "?" for ch in str(value)
    )


def log_event(conn, textlog, ts, event, host, port, actor, code, detail=""):
    host = _printable(host) if host is not None else None
    detail = _printable(detail) if detail else detail
    conn.execute(
        "INSERT INTO decisions (ts, event, host, port, actor, reason_code, detail)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ts, event, host, port, actor, code, detail),
    )
    conn.commit()
    if textlog is not None:
        textlog.append(
            "%d %s host=%s port=%s actor=%s code=%s %s"
            % (ts, event, host or "-", port or "-", actor, code or "-", detail)
        )


def add_allowlist(
    conn, pattern, kind, port, created_by, scope, expires_at, source, note=None
):
    """Insert one entry and return its ids (a one-element list).

    Exact patterns must arrive already folded through
    validation.canonical_host(): www.X and X are one equivalence class,
    stored in the bare form. The fold happens at the trust boundaries — the
    broker sockets, panel input, and list import — never here.
    """
    ts = now()
    cur = conn.execute(
        "INSERT INTO allowlist (pattern, kind, port, created_at, created_by,"
        " expires_at, scope, source, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (pattern, kind, port, ts, created_by, expires_at, scope, source, note),
    )
    ids = [cur.lastrowid]
    # Rows from one add share a group_id (the first row's id) so revoke can
    # retire the whole approval; adds are single-row today, but historical
    # databases carry multi-row groups.
    conn.execute(
        "UPDATE allowlist SET group_id = ? WHERE id = ?", (ids[0], ids[0])
    )
    conn.commit()
    return ids


def import_list_file(conn, path, tlds, blocked, psl, created_by, source, note):
    """Bulk-load a shipped "host [port]" list as permanent exact entries.

    Every line is validated before anything is inserted, so a bad file can
    never half-import: a wildcard, a blocked domain, or an invalid hostname
    raises ValueError naming the line. Hosts are folded through
    validation.canonical_host, so a www.X line and an X line are one entry.
    Lines whose (pattern, port) already has an active entry are skipped,
    which makes a re-import idempotent. Wildcards are refused by design —
    they stay a per-entry human ceremony in the panel, never a bulk load.
    Returns (added, skipped).
    """
    entries = []
    para = []       # consecutive comment lines form one description
    section = None
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            stripped = raw.strip()
            if not stripped:
                para = []
                continue
            if stripped.startswith("#"):
                # The comment paragraph nearest above an entry describes it —
                # the shipped lists are organised exactly so. Whole paragraph,
                # not its last line: a wrapped sentence must not truncate.
                text = stripped.lstrip("#").strip().strip("-").strip()
                if text and not text.startswith("="):
                    para.append(text)
                continue
            if para:
                section = " ".join(para)
                para = []
            body, _, inline = stripped.partition("#")
            parts = body.split()
            desc = clean_note(inline.strip()) or clean_note(section) \
                or clean_note(note)
            if validation.looks_like_wildcard(parts[0]):
                raise ValueError(
                    "line %d: wildcards cannot be bulk-imported" % lineno
                )
            try:
                host = validation.normalize_hostname(parts[0], tlds)
            except validation.ValidationError as exc:
                raise ValueError("line %d: %s" % (lineno, exc.code))
            host = validation.canonical_host(host, psl)
            try:
                port = int(parts[1]) if len(parts) > 1 else 443
            except ValueError:
                raise ValueError("line %d: bad port" % lineno)
            if validation.is_blocked(host, blocked):
                raise ValueError(
                    "line %d: %s is permanently blocked" % (lineno, host)
                )
            entries.append((host, port, desc))
    return import_entries(conn, entries, created_by, source)


def parse_catalog_groups(path, tlds, blocked, psl):
    """The catalog's group layer: '# == Title' super-headers partition the
    file's sections into ~15 loadable groups. Returns
    [(title, [(host, port, desc), ...]), ...]; entries are validated and
    canonicalised exactly as import_list_file would."""
    groups = []
    para = []
    section = None
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            stripped = raw.strip()
            if not stripped:
                para = []
                continue
            if stripped.startswith("#"):
                text = stripped.lstrip("#").strip()
                if text.startswith("="):
                    title = text.strip("=").strip()
                    if title:
                        groups.append((title, []))
                    continue
                text = text.strip("-").strip()
                if text:
                    para.append(text)
                continue
            if para:
                section = " ".join(para)
                para = []
            if not groups:
                groups.append(("Ungrouped", []))
            body, _, inline = stripped.partition("#")
            parts = body.split()
            desc = clean_note(inline.strip()) or clean_note(section)
            if validation.looks_like_wildcard(parts[0]):
                continue
            try:
                host = validation.normalize_hostname(parts[0], tlds)
            except validation.ValidationError:
                continue
            host = validation.canonical_host(host, psl)
            try:
                port = int(parts[1]) if len(parts) > 1 else 443
            except ValueError:
                continue
            if validation.is_blocked(host, blocked):
                continue
            groups[-1][1].append((host, port, desc))
    return [g for g in groups if g[1]]


def import_entries(conn, entries, created_by, source):
    """Insert validated (host, port, desc) entries as permanent exact rows;
    shared by full-file and per-group imports. Returns (added, skipped)."""
    ts = now()
    added = skipped = 0
    for host, port, desc in entries:
        exists = conn.execute(
            "SELECT id, note, source FROM allowlist"
            " WHERE pattern = ? AND port = ?"
            " AND consumed_at IS NULL"
            " AND (expires_at IS NULL OR expires_at > ?)",
            (host, port, ts),
        ).fetchone()
        if exists:
            skipped += 1
            # Shipped rows carry machinery descriptions: a re-import may
            # correct them. A row the operator created keeps their words —
            # only an empty description is ever filled in.
            machinery = exists["source"] in ("starter", "default")
            if desc and (not exists["note"]
                         or (machinery and desc != exists["note"])):
                conn.execute("UPDATE allowlist SET note = ? WHERE id = ?",
                             (desc, exists["id"]))
                conn.commit()
            continue
        add_allowlist(conn, host, "exact", port, created_by, "permanent",
                      None, source, desc)
        added += 1
    return added, skipped


def import_user_text(conn, text, tlds, blocked, psl, created_by):
    """Lenient import of an operator-pasted list: "host [port] [# description]"
    per line. Unlike the shipped-list loader, a bad line never aborts the
    import — it lands in the returned rejection list with its reason, so the
    operator sees exactly what was refused and why. Wildcards are refused by
    design (the Add dialog is their only path); nothing existing is replaced.
    Returns {"added": n, "present": n, "rejected": [(lineno, entry, reason)]}.
    """
    ts = now()
    added = present = 0
    rejected = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        body, _, inline = stripped.partition("#")
        parts = body.split()
        if not parts:
            continue
        token = parts[0]
        desc = clean_note(inline.strip())
        if validation.looks_like_wildcard(token):
            rejected.append((lineno, token,
                             "wildcards are added one at a time through the"
                             " Add form's confirmation dialog"))
            continue
        try:
            host = validation.normalize_hostname(token, tlds)
        except validation.ValidationError as exc:
            rejected.append((lineno, token, "invalid hostname (%s)" % exc.code))
            continue
        host = validation.canonical_host(host, psl)
        port = 443
        if len(parts) > 1:
            try:
                port = int(parts[1])
            except ValueError:
                rejected.append((lineno, token, "bad port %r" % parts[1]))
                continue
            if not 1 <= port <= 65535:
                rejected.append((lineno, token, "bad port %d" % port))
                continue
        if validation.is_blocked(host, blocked):
            rejected.append((lineno, host, "permanently blocked domain"))
            continue
        row = conn.execute(
            "SELECT id, note FROM allowlist WHERE pattern = ? AND port = ?"
            " AND consumed_at IS NULL"
            " AND (expires_at IS NULL OR expires_at > ?)",
            (host, port, ts),
        ).fetchone()
        if row:
            present += 1
            if desc and not row["note"]:
                conn.execute("UPDATE allowlist SET note = ? WHERE id = ?",
                             (desc, row["id"]))
        else:
            add_allowlist(conn, host, "exact", port, created_by, "permanent",
                          None, "manual", desc)
            added += 1
    conn.commit()
    return {"added": added, "present": present, "rejected": rejected}


def erase_all(conn, ts):
    """Expire every active allowlist entry, every source; returns the count.
    A revoke, not a delete: the rows and the decision log keep the history,
    and Load defaults can restore the shipped lists afterwards."""
    cur = conn.execute(
        "UPDATE allowlist SET expires_at = ?"
        " WHERE (expires_at IS NULL OR expires_at > ?)",
        (ts, ts),
    )
    conn.commit()
    return cur.rowcount


def export_lines(conn, ts):
    """The active allowlist as portable text: "pattern port  # description".
    Wildcards are included for completeness; re-importing them goes through
    the Add dialog, never a bulk load."""
    rows = conn.execute(
        "SELECT pattern, kind, port, note FROM allowlist"
        " WHERE (expires_at IS NULL OR expires_at > ?)"
        " AND consumed_at IS NULL ORDER BY pattern, port",
        (ts,),
    ).fetchall()
    out = []
    for r in rows:
        pat = ("*." + r["pattern"]) if r["kind"] == "wildcard" else r["pattern"]
        line = "%s %d" % (pat, r["port"])
        if r["note"]:
            line += "  # " + r["note"]
        out.append(line)
    return out


def revoke_by_source(conn, source, ts):
    """Expire every active entry with the given source; returns the count.
    Bulk removal is what keeps a thousand-entry import reviewable."""
    cur = conn.execute(
        "UPDATE allowlist SET expires_at = ? WHERE source = ?"
        " AND (expires_at IS NULL OR expires_at > ?)",
        (ts, source, ts),
    )
    conn.commit()
    return cur.rowcount


def active_count_by_source(conn, source, ts):
    return conn.execute(
        "SELECT COUNT(*) AS n FROM allowlist WHERE source = ?"
        " AND consumed_at IS NULL"
        " AND (expires_at IS NULL OR expires_at > ?)",
        (source, ts),
    ).fetchone()["n"]


def active_match(conn, host, port, ts, consume=False):
    """Return the matching active entry or None. Expiry is evaluated here, at
    decision time — a lapsed entry never works because no sweeper has run.

    A scope='once' entry is spent only when consume=True, which the proxy sets
    on the final (SNI) check of a connection — never on the submission path and
    never on the first (CONNECT) check, so one real connection passes both
    helper phases before the grant is retired.
    """
    rows = conn.execute(
        "SELECT * FROM allowlist WHERE port = ? AND consumed_at IS NULL"
        " AND (expires_at IS NULL OR expires_at > ?)"
        " ORDER BY CASE kind WHEN 'exact' THEN 0 ELSE 1 END, id",
        (port, ts),
    ).fetchall()
    for row in rows:
        if validation.matches(row["kind"], row["pattern"], host):
            if consume and row["scope"] == "once":
                conn.execute(
                    "UPDATE allowlist SET consumed_at = ? WHERE id = ?",
                    (ts, row["id"]),
                )
                conn.commit()
            return row
    return None


def revoke_entry(conn, entry_id, ts):
    """Revoke the whole approval the entry belongs to: rows added together
    share a group and die together (historical databases carry www-twin
    groups from before the canonical fold)."""
    row = conn.execute(
        "SELECT group_id FROM allowlist WHERE id = ?", (entry_id,)
    ).fetchone()
    group = row["group_id"] if row and row["group_id"] is not None else None
    if group is None:
        conn.execute(
            "UPDATE allowlist SET expires_at = ? WHERE id = ?"
            " AND (expires_at IS NULL OR expires_at > ?)",
            (ts, entry_id, ts),
        )
    else:
        conn.execute(
            "UPDATE allowlist SET expires_at = ? WHERE group_id = ?"
            " AND (expires_at IS NULL OR expires_at > ?)",
            (ts, group, ts),
        )
    conn.commit()


def merge_www_rows(conn, psl):
    """One-time upgrade: fold pre-canonicalization 'www.' exact rows into
    their bare domain (see validation.canonical_host). A twin whose bare
    form already exists at the same port is deleted — the bare row carries
    the approval; a lone www row is renamed in place, keeping its expiry,
    scope, and group. Idempotent: a folded database has nothing to do.
    Wildcard rows are never touched."""
    rows = conn.execute(
        "SELECT id, pattern, port FROM allowlist"
        " WHERE kind = 'exact' AND pattern LIKE 'www.%'"
    ).fetchall()
    for row in rows:
        target = validation.canonical_host(row["pattern"], psl)
        if target == row["pattern"]:
            continue
        dup = conn.execute(
            "SELECT 1 FROM allowlist WHERE pattern = ? AND port = ?"
            " AND kind = 'exact' AND id != ?",
            (target, row["port"], row["id"]),
        ).fetchone()
        if dup:
            conn.execute("DELETE FROM allowlist WHERE id = ?", (row["id"],))
        else:
            conn.execute(
                "UPDATE allowlist SET pattern = ? WHERE id = ?",
                (target, row["id"]),
            )
    conn.commit()


# Panel filter buckets: shipped lists by their own source; everything the
# operator added by hand or approved from the queue is "user".
_SRC_FILTERS = {
    "default": ("source = 'default'", []),
    "starter": ("source = 'starter'", []),
    "user": ("source IN ('manual', 'approval')", []),
}


def _allowlist_filters(sql, args, q, src):
    if q:
        sql += (" AND (instr(pattern, ?) > 0"
                " OR instr(lower(COALESCE(note, '')), ?) > 0)")
        args.extend([q, q])
    if src in _SRC_FILTERS:
        clause, extra = _SRC_FILTERS[src]
        sql += " AND " + clause
        args.extend(extra)
    return sql, args


def count_allowlist(conn, ts, q=None, src=None):
    """Active-entry count, with the same filters as list_allowlist
    so a pager's total always agrees with its rows."""
    sql = (
        "SELECT COUNT(*) AS n FROM allowlist"
        " WHERE (expires_at IS NULL OR expires_at > ?)"
    )
    sql, args = _allowlist_filters(sql, [ts], q, src)
    return conn.execute(sql, args).fetchone()["n"]


def list_allowlist(conn, ts, include_expired=False, q=None, limit=None,
                   offset=0, src=None):
    if include_expired:
        return conn.execute("SELECT * FROM allowlist ORDER BY id").fetchall()
    sql = "SELECT * FROM allowlist WHERE (expires_at IS NULL OR expires_at > ?)"
    sql, args = _allowlist_filters(sql, [ts], q, src)
    sql += " ORDER BY expires_at IS NULL, expires_at, pattern"
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        args.extend([limit, offset])
    return conn.execute(sql, args).fetchall()


def upsert_pending(conn, host, port, rationale, origin, ts):
    """Deduplicate pending requests on (host, port): bump count, keep the
    first rationale seen (the agent's original case, not the latest retry)."""
    row = conn.execute(
        "SELECT id FROM requests WHERE host = ? AND port = ? AND status = 'pending'",
        (host, port),
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE requests SET count = count + 1, last_seen = ? WHERE id = ?",
            (ts, row["id"]),
        )
        conn.commit()
        return row["id"], False
    cur = conn.execute(
        "INSERT INTO requests (host, port, rationale, first_seen, last_seen,"
        " count, origin, status) VALUES (?, ?, ?, ?, ?, 1, ?, 'pending')",
        (host, port, rationale, ts, ts, origin),
    )
    conn.commit()
    return cur.lastrowid, True


def pending_count(conn):
    return conn.execute(
        "SELECT COUNT(*) AS n FROM requests WHERE status = 'pending'"
    ).fetchone()["n"]


def pending_requests(conn):
    return conn.execute(
        "SELECT * FROM requests WHERE status = 'pending' ORDER BY first_seen"
    ).fetchall()


def get_request(conn, req_id):
    return conn.execute("SELECT * FROM requests WHERE id = ?", (req_id,)).fetchone()


def decide_request(conn, req_id, status, actor, reason, ts):
    conn.execute(
        "UPDATE requests SET status = ?, decided_at = ?, decided_by = ?,"
        " decision_reason = ? WHERE id = ? AND status = 'pending'",
        (status, ts, actor, reason, req_id),
    )
    conn.commit()


def standing_denial(conn, host, port):
    """The most recent resolved decision for (host, port), if it was a denial.

    A denied destination stays denied on resubmit — the agent is told, with the
    operator's reason — until the operator changes their mind via manual add.
    """
    row = conn.execute(
        "SELECT * FROM requests WHERE host = ? AND port = ?"
        " AND status IN ('approved', 'denied')"
        " ORDER BY decided_at DESC LIMIT 1",
        (host, port),
    ).fetchone()
    if row is not None and row["status"] == "denied":
        return row
    return None


def events_last_hour(conn, event, ts):
    return conn.execute(
        "SELECT COUNT(*) AS n FROM decisions WHERE event = ? AND ts > ?",
        (event, ts - 3600),
    ).fetchone()["n"]


def recent_events(conn, limit=200):
    return conn.execute(
        "SELECT * FROM decisions ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()


def pause_state(conn):
    """Enforcement-pause state: 0 = enforcing, -1 = off until the operator
    turns it back on, otherwise the unix time the window ends. Set only from
    the panel (operator action); read per-decision by the broker so expiry
    needs no sweeper — the same live-evaluation rule as allowlist expiry."""
    value = get_setting(conn, "enforcement_paused_until")
    if value == "off":
        return -1
    try:
        return int(value) if value else 0
    except (TypeError, ValueError):
        return 0


def pause_active(conn, ts):
    state = pause_state(conn)
    return state == -1 or ts < state


def get_setting(conn, key):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return None if row is None else row["value"]


def set_setting(conn, key, value):
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?)"
        " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()


# -- panel sessions -----------------------------------------------------------
# Logins live here rather than in panel memory so a service restart or reboot
# does not sign every device out; the cookie carries the same lifetime.


def _session_key(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(conn, token, csrf, ts, expires_at):
    conn.execute(
        "DELETE FROM panel_sessions WHERE expires_at <= ?", (ts,)
    )
    conn.execute(
        "INSERT INTO panel_sessions (token_hash, csrf, created_at, expires_at)"
        " VALUES (?, ?, ?, ?)",
        (_session_key(token), csrf, ts, expires_at),
    )
    conn.commit()


def get_session(conn, token, ts):
    """{'csrf', 'expires'} for a live session, else None. Expired rows are
    simply not matched; the next login sweeps them."""
    row = conn.execute(
        "SELECT csrf, expires_at FROM panel_sessions"
        " WHERE token_hash = ? AND expires_at > ?",
        (_session_key(token), ts),
    ).fetchone()
    if row is None:
        return None
    return {"csrf": row["csrf"], "expires": row["expires_at"]}


def delete_session(conn, token):
    conn.execute(
        "DELETE FROM panel_sessions WHERE token_hash = ?", (_session_key(token),)
    )
    conn.commit()


def clear_sessions(conn):
    """Sign every device out — the companion to a password change."""
    conn.execute("DELETE FROM panel_sessions")
    conn.commit()
