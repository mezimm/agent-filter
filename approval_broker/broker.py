"""Broker daemon: the decision engine behind both unix sockets.

submit.sock  (broker:agent 0620)  — the agent asks for a destination, with a
                                    rationale, and learns a fixed reason code.
acl.sock     (broker:proxy 0660)  — Squid's helper asks allow/deny per
                                    connection; every deny for a valid,
                                    unblocked hostname lands in the queue.

Every error path answers with a deny. If this process is down, Squid's helper
times out and Squid denies: the agent has no network. That is correct.
"""

import json
import os
import re
import socket
import threading

from . import codes, config, db, validation

MAX_LINE = 8192
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class Broker:
    # A compromised agent can hammer an already-allowed host through the proxy
    # thousands of times a second. Logging every identical proxy decision would
    # let it fill the disk (the append-only decisions table has no DELETE), so
    # repeats of the same proxy event within this window are suppressed — the
    # destination is still logged, just not once per reconnect.
    COALESCE_WINDOW = 10

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
        self._recent_log = {}

    # -- helpers ---------------------------------------------------------

    def _log(self, ts, event, host, port, actor, code, detail=""):
        if event in ("proxy_allow", "proxy_deny"):
            key = (event, host, port, code)
            last = self._recent_log.get(key)
            if last is not None and ts - last < self.COALESCE_WINDOW:
                return
            self._recent_log[key] = ts
            if len(self._recent_log) > 4096:
                self._recent_log = {
                    k: v for k, v in self._recent_log.items()
                    if ts - v < self.COALESCE_WINDOW
                }
        db.log_event(self.conn, self.textlog, ts, event, host, port, actor, code, detail)

    def _budget_hit(self, ts, event, cap, label):
        """True if the hourly budget for `event` is exhausted; logs one trip
        per window rather than one row per refused attempt."""
        if db.events_last_hour(self.conn, event, ts) < cap:
            return False
        trips = self.conn.execute(
            "SELECT COUNT(*) AS n FROM decisions WHERE event = 'rate_limit_trip'"
            " AND detail = ? AND ts > ?",
            (label, ts - 3600),
        ).fetchone()["n"]
        if trips == 0:
            self._log(ts, "rate_limit_trip", None, None, "broker", "RATE_LIMITED", label)
        return True

    @staticmethod
    def _reply(code, host=None, port=None, operator_reason=None):
        status = {
            "ALLOWED": "allowed",
            "PENDING": "queued",
            "DENIED_BY_ADMIN": "denied",
            "BROKER_UNAVAILABLE": "error",
        }.get(code, "rejected")
        message = codes.message(code)
        if code == "PENDING" and host:
            message = "Awaiting approval for %s:%d" % (host, port)
        if code == "DENIED_BY_ADMIN" and operator_reason:
            message = "%s; operator: %s" % (message, operator_reason)
        return {"status": status, "code": code, "message": message}

    def _clean_rationale(self, value):
        if not isinstance(value, str):
            return None
        cap = self.cfg.get("limits", "rationale_max_bytes")
        return _CTRL.sub(" ", value)[:cap] or None

    # -- agent submissions (spec section 12) -----------------------------

    def submit(self, payload) -> dict:
        try:
            with self.lock:
                return self._submit_locked(payload)
        except Exception:
            return self._reply("BROKER_UNAVAILABLE")

    def _submit_locked(self, payload) -> dict:
        ts = db.now()
        if not isinstance(payload, dict):
            return self._auto_reject(ts, None, None, "INVALID_HOSTNAME")
        raw_host = payload.get("host")
        port = payload.get("port", 443)
        if not isinstance(port, int):
            return self._auto_reject(ts, None, None, "INVALID_HOSTNAME")
        rationale = self._clean_rationale(payload.get("reason"))

        if validation.looks_like_wildcard(raw_host):
            return self._auto_reject(ts, None, port, "WILDCARD_NOT_PERMITTED")
        try:
            # Agent hostnames are machine-generated and must be plain ASCII;
            # a Unicode form that folds to an allowed name is not a legitimate
            # request, it is a probe, so it is rejected rather than accepted.
            host = validation.normalize_hostname(
                raw_host if isinstance(raw_host, str) else "", self.tlds,
                ascii_only=True,
            )
        except validation.ValidationError as exc:
            return self._auto_reject(ts, None, port, exc.code)
        host = validation.canonical_host(host, self.psl)
        if validation.is_blocked(host, self.blocked):
            return self._auto_reject(ts, host, port, "DOMAIN_PERMANENTLY_BLOCKED")
        if port not in self.cfg.get("ports", "allowed"):
            return self._auto_reject(ts, host, port, "PORT_NOT_PERMITTED")

        # Charge the submission budget for every submission, before the
        # allowed/denied fast paths — otherwise an agent reconnecting to an
        # approved host both escapes the budget and writes an unbounded row
        # per attempt.
        if self._budget_hit(
            ts, "submission", self.cfg.get("limits", "submissions_per_hour"),
            "submissions",
        ):
            return self._reply("RATE_LIMITED")

        if db.active_match(self.conn, host, port, ts) is not None:
            self._log(ts, "submission", host, port, "agent", "ALLOWED")
            return self._reply("ALLOWED", host, port)

        denial = db.standing_denial(self.conn, host, port)
        if denial is not None:
            self._log(ts, "submission", host, port, "agent", "DENIED_BY_ADMIN")
            return self._reply(
                "DENIED_BY_ADMIN", host, port, denial["decision_reason"]
            )

        existing = self.conn.execute(
            "SELECT id FROM requests WHERE host = ? AND port = ?"
            " AND status = 'pending'",
            (host, port),
        ).fetchone()
        if existing is None and (
            db.pending_count(self.conn) >= self.cfg.get("limits", "pending_max")
        ):
            self._log(ts, "submission", host, port, "agent", "QUEUE_FULL")
            return self._reply("QUEUE_FULL")

        db.upsert_pending(self.conn, host, port, rationale, "agent_submitted", ts)
        self._log(ts, "submission", host, port, "agent", "PENDING")
        return self._reply("PENDING", host, port)

    def _auto_reject(self, ts, host, port, code) -> dict:
        """Auto-rejections never reach the queue (spec section 12 exception).
        Past the hourly budget they stop being logged per-event too — a
        submit-reject loop must not grow the database forever."""
        if self._budget_hit(
            ts, "auto_reject", self.cfg.get("limits", "auto_rejects_per_hour"),
            "auto_rejects",
        ):
            return self._reply("RATE_LIMITED")
        self._log(ts, "auto_reject", host, port, "agent", code)
        return self._reply(code, host, port)

    # -- proxy checks ----------------------------------------------------

    def acl_check(self, payload) -> dict:
        try:
            with self.lock:
                return self._acl_locked(payload)
        except Exception:
            return {"allow": False, "code": "BROKER_UNAVAILABLE"}

    def _acl_locked(self, payload) -> dict:
        ts = db.now()
        raw_host = payload.get("host") if isinstance(payload, dict) else None
        port = payload.get("port", 443) if isinstance(payload, dict) else 443
        # The proxy sets final=true only on a connection's SNI check — the last
        # of its two helper calls — so a 'once' grant is spent there, after the
        # CONNECT check has already passed on the same connection.
        final = bool(payload.get("final")) if isinstance(payload, dict) else False
        if not isinstance(port, int):
            port = -1
        try:
            # Input here comes from Squid and can only be ASCII; rejecting raw
            # non-ASCII keeps odd-encoding probes visible as auto-rejects
            # instead of folding them into an allowed name.
            host = validation.normalize_hostname(
                raw_host if isinstance(raw_host, str) else "", self.tlds,
                ascii_only=True,
            )
        except validation.ValidationError as exc:
            self._log(ts, "proxy_deny", str(raw_host)[:253], port, "proxy", exc.code)
            return {"allow": False, "code": exc.code}
        host = validation.canonical_host(host, self.psl)
        if validation.is_blocked(host, self.blocked):
            self._log(ts, "proxy_deny", host, port, "proxy",
                      "DOMAIN_PERMANENTLY_BLOCKED")
            return {"allow": False, "code": "DOMAIN_PERMANENTLY_BLOCKED"}
        if port not in self.cfg.get("ports", "allowed"):
            self._log(ts, "proxy_deny", host, port, "proxy", "PORT_NOT_PERMITTED")
            return {"allow": False, "code": "PORT_NOT_PERMITTED"}

        # Operator-initiated pause (panel): every valid destination is allowed
        # and logged until the window expires. Deliberately after the blocked
        # and port gates — a pause never softens those.
        if db.pause_active(self.conn, ts):
            self._log(ts, "proxy_allow", host, port, "proxy", "PAUSED_ALLOW")
            return {"allow": True, "code": "PAUSED_ALLOW"}

        if db.active_match(self.conn, host, port, ts, consume=final) is not None:
            self._log(ts, "proxy_allow", host, port, "proxy", "ALLOWED")
            return {"allow": True, "code": "ALLOWED"}

        denial = db.standing_denial(self.conn, host, port)
        if denial is not None:
            self._log(ts, "proxy_deny", host, port, "proxy", "DENIED_BY_ADMIN")
            return {"allow": False, "code": "DENIED_BY_ADMIN"}

        # A denied connection nobody submitted a rationale for is the more
        # valuable signal: something reached for the network outside the
        # instrumented path. Queue it, within the cap.
        if db.pending_count(self.conn) < self.cfg.get("limits", "pending_max") or (
            self.conn.execute(
                "SELECT 1 FROM requests WHERE host = ? AND port = ?"
                " AND status = 'pending'",
                (host, port),
            ).fetchone()
            is not None
        ):
            db.upsert_pending(self.conn, host, port, None, "proxy_denied", ts)
        self._log(ts, "proxy_deny", host, port, "proxy", "PENDING")
        return {"allow": False, "code": "PENDING"}


# -- socket servers ------------------------------------------------------


def _systemd_sockets():
    """Collect sockets passed by systemd socket activation, by name."""
    result = {}
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return result
    count = int(os.environ.get("LISTEN_FDS", "0"))
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    for i in range(count):
        name = names[i] if i < len(names) else "unknown"
        sock = socket.socket(fileno=3 + i)
        result[name] = sock
    return result


def _own_socket(path):
    """Fallback for tests and manual runs: create the socket ourselves.
    Production uses systemd socket units, which own the modes from the spec."""
    try:
        os.unlink(path)
    except OSError:
        pass
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(path)
    return sock


def _serve(sock, handler):
    sock.listen(256)
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return  # listener closed: stop serving
        threading.Thread(target=_handle, args=(conn, handler), daemon=True).start()


def _handle(conn, handler):
    try:
        conn.settimeout(5)
        data = b""
        while b"\n" not in data and len(data) < MAX_LINE:
            chunk = conn.recv(1024)
            if not chunk:
                break
            data += chunk
        try:
            payload = json.loads(data.split(b"\n", 1)[0].decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            payload = None
        response = handler(payload)
        conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    cfg = config.load()
    broker = Broker(cfg)
    socks = _systemd_sockets()
    submit_sock = socks.get("submit") or _own_socket(
        cfg.get("paths", "submit_socket")
    )
    acl_sock = socks.get("acl") or _own_socket(cfg.get("paths", "acl_socket"))
    threading.Thread(
        target=_serve, args=(submit_sock, broker.submit), daemon=True
    ).start()
    _serve(acl_sock, broker.acl_check)


if __name__ == "__main__":
    main()
