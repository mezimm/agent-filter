"""Spec section 15: validation tests, table-driven from the section 7.1 table."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from approval_broker.validation import (
    ValidationError,
    canonical_host,
    classify_pattern,
    is_blocked,
    load_blocked,
    load_psl,
    load_tlds,
    looks_like_wildcard,
    matches,
    normalize_hostname,
)

TLDS = load_tlds(os.path.join(os.path.dirname(__file__), "..", "data", "tlds.txt"))
PSL = load_psl(
    os.path.join(os.path.dirname(__file__), "..", "data", "public-suffix-list.dat")
)


def norm(value):
    return normalize_hostname(value, TLDS)


class RejectionTable(unittest.TestCase):
    """One case per row of the spec section 7.1 evasion table, plus extras."""

    CASES = [
        (".domain.com", "leading dot"),
        ("domain.com..", "multiple trailing dots"),
        ("domain.com:443", "port smuggled in"),
        ("domain.com/x", "path smuggled in"),
        ("evil.com#allowed.com", "fragment"),
        ("user@evil.com", "userinfo"),
        ("0x7f000001", "hex integer IP"),
        ("2130706433", "decimal integer IP"),
        ("127.1", "shortened IP"),
        ("127.0.0.1", "dotted quad"),
        ("0177.0.0.1", "octal component IP"),
        ("::1", "IPv6"),
        ("[::1]", "bracketed IPv6"),
        ("::ffff:127.0.0.1", "mapped IPv6"),
        ("localhost", "single label"),
        ("host.localhost", "reserved TLD localhost"),
        ("printer.local", "reserved TLD local"),
        ("vault.internal", "reserved TLD internal"),
        ("x.test", "reserved TLD test"),
        ("x.invalid", "reserved TLD invalid"),
        ("x.example", "reserved TLD example"),
        ("x.onion", "reserved TLD onion"),
        ("x.notarealtldzzz", "TLD not in IANA list"),
        ("", "empty"),
        (" domain.com", "leading whitespace"),
        ("domain.com ", "trailing whitespace"),
        ("do main.com", "interior space"),
        ("-bad.com", "label starts with hyphen"),
        ("bad-.com", "label ends with hyphen"),
        ("a..com", "empty label"),
        ("a." + "b" * 63 + "x.com", "label over 63 chars"),
        ("a" * 254, "over 253 bytes"),
        ("domain.com\x00", "control character"),
        ("domain.com\n", "newline"),
    ]

    def test_all_rejected(self):
        for value, why in self.CASES:
            with self.subTest(value=value, why=why):
                with self.assertRaises(ValidationError):
                    norm(value)

    def test_ip_literals_get_ip_code(self):
        for value in ["127.0.0.1", "0x7f000001", "2130706433", "127.1", "[::1]"]:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError) as ctx:
                    norm(value)
                self.assertEqual(ctx.exception.code, "IP_LITERAL_REJECTED")


class Normalisation(unittest.TestCase):
    def test_case_folds(self):
        self.assertEqual(norm("DOMAIN.COM"), "domain.com")

    def test_single_trailing_dot_strips(self):
        self.assertEqual(norm("domain.com."), norm("domain.com"))

    def test_cyrillic_does_not_collide(self):
        # First character Cyrillic a — visually identical, different name.
        lookalike = "аpi.github.com"
        result = norm(lookalike)
        self.assertNotEqual(result, "api.github.com")
        self.assertTrue(result.startswith("xn--"))

    def test_ordinary_hosts_pass(self):
        for value in [
            "example.com",
            "files.pythonhosted.org",
            "api.github.com",
            "a-b.c-d.co.uk",
            "xn--nxasmq6b.example.com".replace(".example.com", ".com"),
        ]:
            with self.subTest(value=value):
                self.assertEqual(norm(value), value.lower())

    def test_detail_never_in_message_code_only(self):
        try:
            norm("domain.com:443")
        except ValidationError as exc:
            self.assertEqual(str(exc), exc.code)


class Patterns(unittest.TestCase):
    def test_wildcard_classified(self):
        kind, base = classify_pattern("*.pypi.org", TLDS)
        self.assertEqual((kind, base), ("wildcard", "pypi.org"))

    def test_exact_classified(self):
        kind, base = classify_pattern("pypi.org", TLDS)
        self.assertEqual((kind, base), ("exact", "pypi.org"))

    def test_malformed_patterns_rejected(self):
        for value in ["*pypi.org", ".pypi.org", "*.", "*", "**.pypi.org"]:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    classify_pattern(value, TLDS)

    def test_agent_wildcard_detection(self):
        self.assertTrue(looks_like_wildcard("*.pages.dev"))
        self.assertTrue(looks_like_wildcard(".pages.dev"))
        self.assertFalse(looks_like_wildcard("pages.dev"))


class Matching(unittest.TestCase):
    def test_exact_matches_only_itself(self):
        self.assertTrue(matches("exact", "github.com", "github.com"))
        self.assertFalse(matches("exact", "github.com", "api.github.com"))
        self.assertFalse(matches("exact", "github.com", "raw.githubusercontent.com"))

    def test_wildcard_matches_depth_and_base(self):
        self.assertTrue(matches("wildcard", "pypi.org", "pypi.org"))
        self.assertTrue(matches("wildcard", "pypi.org", "files.pypi.org"))
        self.assertTrue(matches("wildcard", "pypi.org", "a.b.pypi.org"))
        self.assertFalse(matches("wildcard", "pypi.org", "notpypi.org"))
        self.assertFalse(matches("wildcard", "pypi.org", "pypi.org.evil.com"))


class Blocked(unittest.TestCase):
    def test_tailscale_blocked_at_every_depth(self):
        blocked = load_blocked(
            os.path.join(os.path.dirname(__file__), "..", "data", "blocked-domains.txt")
        )
        for host in [
            "tailscale.com",
            "controlplane.tailscale.com",
            "derp1.a.tailscale.com",
        ]:
            with self.subTest(host=host):
                self.assertTrue(is_blocked(host, blocked))
        self.assertFalse(is_blocked("nottailscale.com", blocked))
        self.assertFalse(is_blocked("tailscale.com.evil.net", blocked))

    def test_fallback_when_file_missing(self):
        blocked = load_blocked("/nonexistent/blocked.txt")
        self.assertTrue(is_blocked("tailscale.com", blocked))


if __name__ == "__main__":
    unittest.main()


class CanonicalHost(unittest.TestCase):
    def test_folding_rules(self):
        cases = [
            ("www.example.com", "example.com"),          # ordinary fold
            ("example.com", "example.com"),              # bare form unchanged
            ("www.bbc.co.uk", "bbc.co.uk"),              # folds at any depth
            ("www.com", "www.com"),                      # one-label remainder
            ("www.co.uk", "www.co.uk"),                  # remainder is a PSL zone
            ("www.github.io", "www.github.io"),          # remainder is a PSL zone
            ("www.www.example.com", "www.example.com"),  # one label per fold
            ("wwwx.example.com", "wwwx.example.com"),    # not a www label
        ]
        for raw, want in cases:
            self.assertEqual(canonical_host(raw, PSL), want, raw)
