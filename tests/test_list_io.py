"""Descriptions, user import with rejection reasons, erase-all, export,
and source filtering."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from approval_broker import db, validation

REPO = os.path.join(os.path.dirname(__file__), "..")


def load_refs():
    tlds = validation.load_tlds(os.path.join(REPO, "data", "tlds.txt"))
    blocked = validation.load_blocked(
        os.path.join(REPO, "data", "blocked-domains.txt"))
    psl = validation.load_psl(
        os.path.join(REPO, "data", "public-suffix-list.dat"))
    return tlds, blocked, psl


class ListIO(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.conn = db.open_db(os.path.join(self.tmp, "t.db"))
        self.tlds, self.blocked, self.psl = load_refs()

    def tearDown(self):
        self.conn.close()

    def _write_list(self, text):
        path = os.path.join(self.tmp, "list.txt")
        with open(path, "w") as fh:
            fh.write(text)
        return path

    # -- shipped-list descriptions ------------------------------------

    def test_section_comment_becomes_description(self):
        path = self._write_list(
            "# -- Package registries ---------\n"
            "pypi.org\n"
            "npmjs.com 443\n"
        )
        added, _ = db.import_list_file(
            self.conn, path, self.tlds, self.blocked, self.psl,
            "t", "default", "fallback")
        self.assertEqual(added, 2)
        row = self.conn.execute(
            "SELECT note FROM allowlist WHERE pattern = 'pypi.org'").fetchone()
        self.assertEqual(row["note"], "Package registries")

    def test_inline_description_wins_over_section(self):
        path = self._write_list(
            "# Section text\n"
            "example.com 443  # The canonical test host\n"
        )
        db.import_list_file(self.conn, path, self.tlds, self.blocked,
                            self.psl, "t", "starter", None)
        row = self.conn.execute(
            "SELECT note FROM allowlist WHERE pattern = 'example.com'"
        ).fetchone()
        self.assertEqual(row["note"], "The canonical test host")

    def test_reimport_heals_missing_description_only(self):
        db.add_allowlist(self.conn, "pypi.org", "exact", 443, "t",
                         "permanent", None, "default", None)
        db.add_allowlist(self.conn, "npmjs.com", "exact", 443, "t",
                         "permanent", None, "manual", "my own words")
        db.add_allowlist(self.conn, "crates.io", "exact", 443, "t",
                         "permanent", None, "default", "stale fragment).")
        path = self._write_list("# Registries\npypi.org\nnpmjs.com\ncrates.io\n")
        added, skipped = db.import_list_file(
            self.conn, path, self.tlds, self.blocked, self.psl,
            "t", "default", None)
        self.assertEqual((added, skipped), (0, 3))
        notes = dict(self.conn.execute(
            "SELECT pattern, note FROM allowlist"))
        self.assertEqual(notes["pypi.org"], "Registries")     # filled
        self.assertEqual(notes["npmjs.com"], "my own words")  # operator's
        self.assertEqual(notes["crates.io"], "Registries")    # corrected

    def test_multiline_comment_becomes_one_description(self):
        path = self._write_list(
            "# GitHub over HTTPS (dependencies; use HTTPS git remotes, SSH\n"
            "# egress is not carried).\n"
            "github.com\n"
            "\n"
            "# Next section\n"
            "pypi.org\n"
        )
        db.import_list_file(self.conn, path, self.tlds, self.blocked,
                            self.psl, "t", "default", None)
        notes = dict(self.conn.execute("SELECT pattern, note FROM allowlist"))
        self.assertEqual(
            notes["github.com"],
            "GitHub over HTTPS (dependencies; use HTTPS git remotes, SSH"
            " egress is not carried).")
        self.assertEqual(notes["pypi.org"], "Next section")

    # -- user import ---------------------------------------------------

    def test_user_import_adds_and_reports_rejects(self):
        text = (
            "api.example.com 443  # a service\n"
            "*.evil-bulk.com\n"
            "not a hostname!!\n"
            "vpn.tailscale.com\n"
            "goodhost.org 99999\n"
        )
        result = db.import_user_text(
            self.conn, text, self.tlds, self.blocked, self.psl, "op")
        self.assertEqual(result["added"], 1)
        self.assertEqual(result["present"], 0)
        reasons = {entry: reason for _, entry, reason in result["rejected"]}
        self.assertEqual(len(result["rejected"]), 4)
        self.assertIn("*.evil-bulk.com", reasons)
        self.assertIn("Add form", reasons["*.evil-bulk.com"])
        self.assertTrue(any("blocked" in r for r in reasons.values()))
        self.assertTrue(any("port" in r for r in reasons.values()))
        row = self.conn.execute(
            "SELECT note, source FROM allowlist"
            " WHERE pattern = 'api.example.com'").fetchone()
        self.assertEqual(row["note"], "a service")
        self.assertEqual(row["source"], "manual")

    def test_user_import_never_replaces(self):
        db.add_allowlist(self.conn, "api.example.com", "exact", 443, "t",
                         "permanent", None, "manual", "original words")
        result = db.import_user_text(
            self.conn, "api.example.com 443  # new words\n",
            self.tlds, self.blocked, self.psl, "op")
        self.assertEqual(result["present"], 1)
        self.assertEqual(result["added"], 0)
        row = self.conn.execute(
            "SELECT note FROM allowlist WHERE pattern = 'api.example.com'"
        ).fetchone()
        self.assertEqual(row["note"], "original words")

    def test_note_is_capped_and_sanitized(self):
        self.assertIsNone(db.clean_note("   "))
        self.assertEqual(len(db.clean_note("x" * 400)), 255)

    # -- erase + reload -------------------------------------------------

    def test_erase_all_then_reload_defaults(self):
        path = self._write_list("# S\na.example.com\nb.example.com\n")
        db.import_list_file(self.conn, path, self.tlds, self.blocked,
                            self.psl, "t", "default", None)
        db.add_allowlist(self.conn, "mine.example.com", "exact", 443, "t",
                         "permanent", None, "manual", None)
        ts = db.now()
        count = db.erase_all(self.conn, ts)
        self.assertEqual(count, 3)
        self.assertEqual(db.count_allowlist(self.conn, ts + 1), 0)
        added, skipped = db.import_list_file(
            self.conn, path, self.tlds, self.blocked, self.psl,
            "t", "default", None)
        self.assertEqual((added, skipped), (2, 0))
        self.assertEqual(db.count_allowlist(self.conn, db.now()), 2)

    # -- export ---------------------------------------------------------

    def test_export_round_trip_keeps_descriptions(self):
        db.add_allowlist(self.conn, "api.example.com", "exact", 443, "t",
                         "permanent", None, "manual", "a service")
        db.add_allowlist(self.conn, "widgets.dev", "wildcard", 443, "t",
                         "permanent", None, "manual", None)
        lines = db.export_lines(self.conn, db.now())
        self.assertIn("api.example.com 443  # a service", lines)
        self.assertIn("*.widgets.dev 443", lines)
        conn2 = db.open_db(os.path.join(self.tmp, "t2.db"))
        result = db.import_user_text(
            conn2, "\n".join(lines), self.tlds, self.blocked, self.psl, "op")
        self.assertEqual(result["added"], 1)   # the exact entry
        self.assertEqual(len(result["rejected"]), 1)  # the wildcard
        row = conn2.execute(
            "SELECT note FROM allowlist WHERE pattern = 'api.example.com'"
        ).fetchone()
        self.assertEqual(row["note"], "a service")
        conn2.close()

    # -- source filter ---------------------------------------------------

    def test_source_filter_buckets(self):
        db.add_allowlist(self.conn, "d.example.com", "exact", 443, "t",
                         "permanent", None, "default", None)
        db.add_allowlist(self.conn, "s.example.com", "exact", 443, "t",
                         "permanent", None, "starter", None)
        db.add_allowlist(self.conn, "m.example.com", "exact", 443, "t",
                         "permanent", None, "manual", None)
        db.add_allowlist(self.conn, "a.example.com", "exact", 443, "t",
                         "permanent", None, "approval", None)
        ts = db.now()
        self.assertEqual(db.count_allowlist(self.conn, ts, src="default"), 1)
        self.assertEqual(db.count_allowlist(self.conn, ts, src="starter"), 1)
        self.assertEqual(db.count_allowlist(self.conn, ts, src="user"), 2)
        rows = db.list_allowlist(self.conn, ts, src="user")
        self.assertEqual({r["pattern"] for r in rows},
                         {"m.example.com", "a.example.com"})

    def test_q_matches_description(self):
        db.add_allowlist(self.conn, "api.example.com", "exact", 443, "t",
                         "permanent", None, "manual", "Payment Processor")
        ts = db.now()
        self.assertEqual(db.count_allowlist(self.conn, ts, q="payment"), 1)
        self.assertEqual(db.count_allowlist(self.conn, ts, q="nomatch"), 0)


if __name__ == "__main__":
    unittest.main()
