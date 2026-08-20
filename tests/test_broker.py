"""Spec section 15: queue, wildcard-from-agent, rate limits, fail-closed."""

import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from approval_broker import db
from approval_broker.broker import Broker
from approval_broker.config import Config

REPO = os.path.join(os.path.dirname(__file__), "..")


def make_broker(tmp, limits=None):
    cfg = Config(
        {
            "paths": {
                "db": os.path.join(tmp, "broker.db"),
                "decisions_log": os.path.join(tmp, "decisions.log"),
                "tld_list": os.path.join(REPO, "data", "tlds.txt"),
                "blocked_domains": os.path.join(REPO, "data", "blocked-domains.txt"),
            },
            "limits": limits or {},
        }
    )
    return Broker(cfg)


class Submissions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.broker = make_broker(self.tmp)

    def test_valid_submission_queues(self):
        reply = self.broker.submit(
            {"host": "files.pythonhosted.org", "port": 443, "reason": "dep install"}
        )
        self.assertEqual(reply["code"], "PENDING")
        self.assertEqual(reply["status"], "queued")
        self.assertIn("files.pythonhosted.org:443", reply["message"])

    def test_wildcard_auto_rejected_never_queued(self):
        reply = self.broker.submit({"host": "*.pages.dev", "port": 443})
        self.assertEqual(reply["code"], "WILDCARD_NOT_PERMITTED")
        self.assertEqual(db.pending_count(self.broker.conn), 0)

    def test_tailscale_refused_from_submit(self):
        for host in ["tailscale.com", "controlplane.tailscale.com"]:
            reply = self.broker.submit({"host": host, "port": 443})
            self.assertEqual(reply["code"], "DOMAIN_PERMANENTLY_BLOCKED")
        self.assertEqual(db.pending_count(self.broker.conn), 0)

    def test_ip_literal_rejected_not_queued(self):
        reply = self.broker.submit({"host": "1.1.1.1", "port": 443})
        self.assertEqual(reply["code"], "IP_LITERAL_REJECTED")
        self.assertEqual(db.pending_count(self.broker.conn), 0)

    def test_port_not_permitted(self):
        reply = self.broker.submit({"host": "example.com", "port": 8443})
        self.assertEqual(reply["code"], "PORT_NOT_PERMITTED")

    def test_duplicates_deduplicate_and_count(self):
        for _ in range(3):
            self.broker.submit({"host": "example.org", "port": 443})
        rows = db.pending_requests(self.broker.conn)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["count"], 3)

    def test_rationale_control_chars_stripped_and_capped(self):
        self.broker.submit(
            {"host": "example.org", "port": 443, "reason": "a\x00b\x1bc" + "x" * 5000}
        )
        row = db.pending_requests(self.broker.conn)[0]
        self.assertNotIn("\x00", row["rationale"])
        self.assertNotIn("\x1b", row["rationale"])
        self.assertLessEqual(len(row["rationale"]), 2048)

    def test_no_internals_in_responses(self):
        for payload in [{"host": "domain.com:443"}, {"host": "*.x.dev"}, None]:
            reply = self.broker.submit(payload)
            joined = " ".join(str(v) for v in reply.values())
            self.assertNotIn("Traceback", joined)
            self.assertNotIn("sqlite", joined.lower())
            self.assertNotIn("allowlist entry", joined)


class QueueLimits(unittest.TestCase):
    def test_queue_cap_enforced(self):
        tmp = tempfile.mkdtemp()
        broker = make_broker(tmp, {"pending_max": 3, "submissions_per_hour": 100})
        for i in range(3):
            broker.submit({"host": "host%d.example.org" % i, "port": 443})
        reply = broker.submit({"host": "host9.example.org", "port": 443})
        self.assertEqual(reply["code"], "QUEUE_FULL")
        self.assertEqual(db.pending_count(broker.conn), 3)
        # An existing pending host still deduplicates when the queue is full.
        reply = broker.submit({"host": "host0.example.org", "port": 443})
        self.assertEqual(reply["code"], "PENDING")

    def test_submission_budget_enforced(self):
        tmp = tempfile.mkdtemp()
        broker = make_broker(tmp, {"pending_max": 100, "submissions_per_hour": 2})
        broker.submit({"host": "a.example.org", "port": 443})
        broker.submit({"host": "b.example.org", "port": 443})
        reply = broker.submit({"host": "c.example.org", "port": 443})
        self.assertEqual(reply["code"], "RATE_LIMITED")

    def test_auto_reject_budget_trips_once(self):
        tmp = tempfile.mkdtemp()
        broker = make_broker(tmp, {"auto_rejects_per_hour": 2})
        for _ in range(5):
            broker.submit({"host": "*.pages.dev"})
        trips = broker.conn.execute(
            "SELECT COUNT(*) AS n FROM decisions WHERE event = 'rate_limit_trip'"
        ).fetchone()["n"]
        self.assertEqual(trips, 1)
        reply = broker.submit({"host": "*.pages.dev"})
        self.assertEqual(reply["code"], "RATE_LIMITED")


class AclChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.broker = make_broker(self.tmp)

    def test_allowlisted_host_allowed(self):
        db.add_allowlist(
            self.broker.conn, "example.com", "exact", 443, "test", "permanent",
            None, "manual",
        )
        reply = self.broker.acl_check({"host": "example.com", "port": 443})
        self.assertEqual(reply, {"allow": True, "code": "ALLOWED"})

    def test_www_companion_admitted_api_not(self):
        db.add_allowlist(
            self.broker.conn, "domain.com", "exact", 443, "test", "permanent",
            None, "manual",
        )
        self.assertTrue(
            self.broker.acl_check({"host": "www.domain.com", "port": 443})["allow"]
        )
        self.assertFalse(
            self.broker.acl_check({"host": "api.domain.com", "port": 443})["allow"]
        )

    def test_denied_host_enqueued_as_proxy_denied(self):
        reply = self.broker.acl_check({"host": "example.net", "port": 443})
        self.assertFalse(reply["allow"])
        rows = db.pending_requests(self.broker.conn)
        self.assertEqual(rows[0]["origin"], "proxy_denied")
        self.assertIsNone(rows[0]["rationale"])

    def test_blocked_and_invalid_never_enqueued(self):
        self.broker.acl_check({"host": "derp.tailscale.com", "port": 443})
        self.broker.acl_check({"host": "127.0.0.1", "port": 443})
        self.assertEqual(db.pending_count(self.broker.conn), 0)

    def test_expired_entry_stops_without_restart(self):
        db.add_allowlist(
            self.broker.conn, "example.com", "exact", 443, "test", "24h",
            db.now() - 10, "approval",
        )
        reply = self.broker.acl_check({"host": "example.com", "port": 443})
        self.assertFalse(reply["allow"])

    def test_once_scope_two_phase_connection(self):
        # A real connection makes two helper calls: CONNECT (no final) then SNI
        # (final). Both must pass on the first connection; consumption happens
        # on the final call, so the second connection's CONNECT check fails.
        db.add_allowlist(
            self.broker.conn, "one.example.com", "exact", 443, "test", "once",
            db.now() + 3600, "approval",
        )
        # Connection 1
        self.assertTrue(
            self.broker.acl_check({"host": "one.example.com", "port": 443})["allow"]
        )
        self.assertTrue(
            self.broker.acl_check(
                {"host": "one.example.com", "port": 443, "final": True}
            )["allow"]
        )
        # Connection 2: grant is spent.
        self.assertFalse(
            self.broker.acl_check({"host": "one.example.com", "port": 443})["allow"]
        )

    def test_once_not_consumed_by_submission(self):
        db.add_allowlist(
            self.broker.conn, "one.example.com", "exact", 443, "test", "once",
            db.now() + 3600, "approval",
        )
        # A submission must not burn the grant (submission is not a connection).
        self.assertEqual(
            self.broker.submit({"host": "one.example.com", "port": 443})["code"],
            "ALLOWED",
        )
        self.assertTrue(
            self.broker.acl_check({"host": "one.example.com", "port": 443})["allow"]
        )

    def test_non_ascii_host_rejected_on_machine_paths(self):
        # A Unicode form that would fold to an allowed name is a probe, not a
        # request, on the agent and proxy paths.
        db.add_allowlist(
            self.broker.conn, "example.com", "exact", 443, "test", "permanent",
            None, "manual",
        )
        self.assertEqual(
            self.broker.submit({"host": "еxample.com", "port": 443})["code"],
            "INVALID_HOSTNAME",
        )
        self.assertFalse(
            self.broker.acl_check({"host": "ｅxample.com", "port": 443})["allow"]
        )

    def test_standing_denial_returned_not_requeued(self):
        ts = db.now()
        db.upsert_pending(self.broker.conn, "bad.example.com", 443, None,
                          "agent_submitted", ts)
        req = db.pending_requests(self.broker.conn)[0]
        db.decide_request(self.broker.conn, req["id"], "denied", "operator",
                          "not needed", ts)
        reply = self.broker.acl_check({"host": "bad.example.com", "port": 443})
        self.assertEqual(reply["code"], "DENIED_BY_ADMIN")
        self.assertEqual(db.pending_count(self.broker.conn), 0)
        # The submit path carries the operator's reason back to the agent.
        reply = self.broker.submit({"host": "bad.example.com", "port": 443})
        self.assertEqual(reply["code"], "DENIED_BY_ADMIN")
        self.assertIn("not needed", reply["message"])


class FailClosed(unittest.TestCase):
    def test_corrupt_database_denies(self):
        tmp = tempfile.mkdtemp()
        broker = make_broker(tmp)
        broker.conn.close()
        broker.conn = sqlite3.connect(":memory:")  # no schema: every query fails
        broker.conn.row_factory = sqlite3.Row
        self.assertEqual(
            broker.acl_check({"host": "example.com", "port": 443}),
            {"allow": False, "code": "BROKER_UNAVAILABLE"},
        )
        self.assertEqual(
            broker.submit({"host": "example.com", "port": 443})["code"],
            "BROKER_UNAVAILABLE",
        )


class Migration(unittest.TestCase):
    def test_open_db_adds_missing_columns_to_old_database(self):
        # Simulate a pre-release database that lacks group_id/consumed_at, then
        # confirm open_db migrates it in place and decisions keep working —
        # the documented "rerun install.sh preserves the database" path.
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "old.db")
        old = sqlite3.connect(path)
        old.execute(
            "CREATE TABLE allowlist (id INTEGER PRIMARY KEY, pattern TEXT NOT NULL,"
            " kind TEXT NOT NULL, port INTEGER NOT NULL, created_at INTEGER NOT NULL,"
            " created_by TEXT NOT NULL, expires_at INTEGER,"
            " scope TEXT NOT NULL DEFAULT 'permanent', source TEXT NOT NULL, note TEXT)"
        )
        old.execute(
            "INSERT INTO allowlist (pattern, kind, port, created_at, created_by,"
            " scope, source) VALUES ('old.example.com', 'exact', 443, 1, 'legacy',"
            " 'permanent', 'manual')"
        )
        old.commit()
        old.close()

        conn = db.open_db(path)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(allowlist)")}
        self.assertIn("group_id", cols)
        self.assertIn("consumed_at", cols)
        # A legacy row (group_id NULL, consumed_at NULL) still matches and revokes.
        ts = db.now()
        self.assertIsNotNone(db.active_match(conn, "old.example.com", 443, ts))
        db.revoke_entry(conn, 1, ts)
        self.assertIsNone(db.active_match(conn, "old.example.com", 443, ts))


if __name__ == "__main__":
    unittest.main()
