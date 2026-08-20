"""Public Suffix List alarm: a wildcard on a stranger-signup zone gets a
prominent dialog warning, and confirming it past the warning is recorded as
an operator override; exact hostnames are never judged by the PSL."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from approval_broker import db, validation
from approval_broker.config import Config
from approval_broker.panel import PanelApp

REPO = os.path.join(os.path.dirname(__file__), "..")

SYNTHETIC_PSL = """\
// comment line
com
co.uk
hosting.example.net
*.compute.vendor.com
!allowed.compute.vendor.com
"""


def make_config(tmp, psl_path):
    return Config(
        {
            "paths": {
                "db": os.path.join(tmp, "broker.db"),
                "decisions_log": os.path.join(tmp, "decisions.log"),
                "tld_list": os.path.join(REPO, "data", "tlds.txt"),
                "blocked_domains": os.path.join(REPO, "data", "blocked-domains.txt"),
                "public_suffix_list": psl_path,
            }
        }
    )


class RuleMatching(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        path = os.path.join(self.tmp, "psl.dat")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(SYNTHETIC_PSL)
        self.psl = validation.load_psl(path)

    def conflict(self, base):
        return validation.wildcard_psl_conflict(base, self.psl)

    def test_base_that_is_a_suffix_refused(self):
        self.assertEqual(self.conflict("co.uk"), ("suffix", "co.uk"))
        self.assertEqual(
            self.conflict("hosting.example.net"),
            ("suffix", "hosting.example.net"),
        )

    def test_wildcard_rule_children_are_suffixes(self):
        self.assertEqual(
            self.conflict("zone1.compute.vendor.com"),
            ("suffix", "zone1.compute.vendor.com"),
        )

    def test_exception_rule_exempts_but_ancestor_still_checked(self):
        # The exception frees the name from being a suffix itself, and no
        # PSL zone lies beneath it, so the dialog may proceed.
        self.assertIsNone(self.conflict("allowed.compute.vendor.com"))

    def test_ancestor_of_a_suffix_refused(self):
        self.assertEqual(
            self.conflict("example.net"), ("ancestor", "hosting.example.net")
        )
        self.assertEqual(
            self.conflict("vendor.com"), ("ancestor", "*.compute.vendor.com")
        )
        self.assertEqual(
            self.conflict("compute.vendor.com"),
            ("ancestor", "*.compute.vendor.com"),
        )

    def test_unrelated_single_owner_base_passes(self):
        self.assertIsNone(self.conflict("pypi.org"))
        self.assertIsNone(self.conflict("deep.docs.pypi.org"))
        # Similar names must not match by substring accident.
        self.assertIsNone(self.conflict("notco.uk.example.org"))

    def test_missing_file_falls_back_to_builtin_minimum(self):
        psl = validation.load_psl(os.path.join(self.tmp, "absent.dat"))
        self.assertEqual(
            validation.wildcard_psl_conflict("github.io", psl),
            ("suffix", "github.io"),
        )
        self.assertEqual(
            validation.wildcard_psl_conflict("amazonaws.com", psl),
            ("ancestor", "s3.amazonaws.com"),
        )
        self.assertIsNone(validation.wildcard_psl_conflict("pypi.org", psl))


class ShippedSnapshot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.psl = validation.load_psl(
            os.path.join(REPO, "data", "public-suffix-list.dat")
        )

    def test_doctrine_zones_are_caught(self):
        for base in ["github.io", "pages.dev", "s3.amazonaws.com", "co.uk",
                     "workers.dev", "readthedocs.io", "js.org"]:
            conflict = validation.wildcard_psl_conflict(base, self.psl)
            self.assertEqual(conflict, ("suffix", base), base)

    def test_ancestors_of_zones_are_caught(self):
        for base in ["amazonaws.com", "core.windows.net"]:
            conflict = validation.wildcard_psl_conflict(base, self.psl)
            self.assertIsNotNone(conflict, base)
            self.assertEqual(conflict[0], "ancestor", base)

    def test_single_owner_domains_pass(self):
        for base in ["pypi.org", "ubuntu.com", "zendesk.com", "cloudflare.com"]:
            self.assertIsNone(
                validation.wildcard_psl_conflict(base, self.psl), base
            )

    def test_exact_hosts_under_zones_pass(self):
        # A project's own page under a shared zone is judged by its owner,
        # not the zone — only the wildcard form is refused.
        self.assertIsNone(
            validation.wildcard_psl_conflict("micro-editor.github.io", self.psl)
        )


class PanelOverride(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = PanelApp(make_config(
            self.tmp, os.path.join(REPO, "data", "public-suffix-list.dat")
        ))

    def last_detail(self, pattern):
        for row in db.recent_events(self.app.conn):
            if row["event"] == "manual_add" and row["host"] == pattern:
                return row["detail"]
        return None

    def test_psl_wildcard_reaches_dialog_with_conflict_reported(self):
        status, base = self.app.manual_add("*.github.io", "24h")
        self.assertEqual((status, base), ("wildcard", "github.io"))
        self.assertEqual(self.app.psl_conflict(base), ("suffix", "github.io"))
        kind, zone = self.app.psl_conflict("amazonaws.com")
        self.assertEqual(kind, "ancestor")
        self.assertTrue(zone.endswith("amazonaws.com"), zone)

    def test_confirmed_override_is_added_and_stamped_in_the_log(self):
        error = self.app.confirm_wildcard("*.pages.dev", "pages.dev", "24h")
        self.assertIsNone(error)
        row = self.app.conn.execute(
            "SELECT kind FROM allowlist WHERE pattern = 'pages.dev'"
        ).fetchone()
        self.assertEqual(row["kind"], "wildcard")
        self.assertIn("PSL-ZONE OVERRIDE (pages.dev)",
                      self.last_detail("pages.dev"))

    def test_residual_wildcard_carries_no_override_marker(self):
        status, base = self.app.manual_add("*.zendesk.com", "24h")
        self.assertEqual((status, base), ("wildcard", "zendesk.com"))
        self.assertIsNone(self.app.psl_conflict(base))
        self.assertIsNone(
            self.app.confirm_wildcard("*.zendesk.com", "zendesk.com", "24h")
        )
        self.assertNotIn("OVERRIDE", self.last_detail("zendesk.com"))

    def test_blocked_domains_still_hard_refused(self):
        # The override path is for PSL zones only; the never-allow list does
        # not soften.
        error = self.app.confirm_wildcard(
            "*.tailscale.com", "tailscale.com", "24h"
        )
        self.assertIn("DOMAIN_PERMANENTLY_BLOCKED", error)

    def test_exact_host_that_is_a_zone_still_addable(self):
        # gov.uk is a public suffix and also a real website; the exact form
        # carries no subdomain grant and stays legal.
        status, _ = self.app.manual_add("gov.uk", "24h")
        self.assertEqual(status, "added")


if __name__ == "__main__":
    unittest.main()
