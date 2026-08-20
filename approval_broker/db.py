"""SQLite storage: allowlist, request queue, append-only decision log.

One writer discipline: callers serialise writes with their own lock; WAL mode
lets the panel and broker share the file. The decisions table is append-only —
there is deliberately no update or delete helper for it.
"""

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
CREATE INDEX IF NOT EXISTS idx_requests_hostport ON requests (host, port);
CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions (ts);
"""


def now() -> int:
    return int(time.time())


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
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(SCHEMA)
    _migrate(conn)
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
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
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
            entries.append((host, port))
    ts = now()
    added = skipped = 0
    for host, port in entries:
        exists = conn.execute(
            "SELECT 1 FROM allowlist WHERE pattern = ? AND port = ?"
            " AND consumed_at IS NULL"
            " AND (expires_at IS NULL OR expires_at > ?)",
            (host, port, ts),
        ).fetchone()
        if exists:
            skipped += 1
            continue
        add_allowlist(conn, host, "exact", port, created_by, "permanent",
                      None, source, note)
        added += 1
    return added, skipped


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


def count_allowlist(conn, ts, q=None):
    """Active-entry count, with the same substring filter as list_allowlist
    so a pager's total always agrees with its rows."""
    sql = (
        "SELECT COUNT(*) AS n FROM allowlist"
        " WHERE (expires_at IS NULL OR expires_at > ?)"
    )
    args = [ts]
    if q:
        sql += " AND instr(pattern, ?) > 0"
        args.append(q)
    return conn.execute(sql, args).fetchone()["n"]


def list_allowlist(conn, ts, include_expired=False, q=None, limit=None, offset=0):
    if include_expired:
        return conn.execute("SELECT * FROM allowlist ORDER BY id").fetchall()
    sql = "SELECT * FROM allowlist WHERE (expires_at IS NULL OR expires_at > ?)"
    args = [ts]
    if q:
        sql += " AND instr(pattern, ?) > 0"
        args.append(q)
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
