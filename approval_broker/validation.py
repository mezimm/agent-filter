"""Hostname validation and matching — the single shared routine (spec section 7).

Every component that accepts or compares a hostname must go through
normalize_hostname().  The logic is positive: "is this a valid exact hostname
and nothing else?"  Anything that fails is rejected, whatever the evasion was.
"""

import ipaddress
import re
import socket

import idna

# Names below any of these suffixes are refused from every path (spec section 8.4).
# The list itself ships in data/blocked-domains.txt so entries carry their reasons;
# this constant is the fallback if that file is missing, and must never be smaller.
FALLBACK_BLOCKED = ("tailscale.com", "ts.net", "tailscale.io")

# Reserved and special-use TLDs that must never be reachable (spec section 7.2 step 7).
RESERVED_TLDS = frozenset(
    {"localhost", "local", "internal", "test", "invalid", "example", "onion"}
)

# Minimum Public Suffix List stand-in when the shipped snapshot is missing:
# the stranger-signup zones the doctrine names by name. The real list ships in
# data/public-suffix-list.dat; this fallback must never be smaller.
FALLBACK_PUBLIC_SUFFIXES = (
    "azureedge.net", "blob.core.windows.net", "cloudfront.net", "co.uk",
    "fly.dev", "firebaseapp.com", "github.io", "gitlab.io", "glitch.me",
    "herokuapp.com", "hf.space", "js.org", "netlify.app", "ngrok.io",
    "notion.site", "onrender.com", "pages.dev", "readthedocs.io", "repl.co",
    "s3.amazonaws.com", "streamlit.app", "trycloudflare.com",
    "up.railway.app", "vercel.app", "web.app", "wixsite.com", "workers.dev",
)

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

MAX_HOSTNAME_BYTES = 253


class ValidationError(ValueError):
    """A hostname failed validation.  `code` is a spec section 9 reason code."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        # Detail is for the local decision log only.  It must never be sent
        # back to the agent (spec section 9: no internals).
        self.detail = detail


def load_tlds(path: str) -> frozenset:
    """Load the IANA TLD snapshot (one TLD per line, comments with '#')."""
    tlds = set()
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            tlds.add(line.lower())
    if not tlds:
        raise ValueError("TLD list is empty: %s" % path)
    return frozenset(tlds)


def load_blocked(path: str) -> tuple:
    """Load the never-allow domain list; falls back to the built-in minimum."""
    blocked = set(FALLBACK_BLOCKED)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                blocked.add(line.lower().lstrip("*.").rstrip("."))
    except OSError:
        pass
    return tuple(sorted(blocked))


def load_psl(path: str) -> tuple:
    """Parse a Public Suffix List snapshot into (exact, wildcard, exception)
    rule sets, punycode-folded to match normalised hostnames. Falls back to
    the built-in minimum when the file is missing or empty.

    Rule semantics (publicsuffix.org/list): a bare line names one suffix, a
    `*.` line makes every direct child of its base a suffix, and a `!` line
    exempts one name from a wildcard rule.
    """
    fallback = (frozenset(FALLBACK_PUBLIC_SUFFIXES), frozenset(), frozenset())
    exact, wild, exc = set(), set(), set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                if line.startswith("!"):
                    target, rule = exc, line[1:]
                elif line.startswith("*."):
                    target, rule = wild, line[2:]
                else:
                    target, rule = exact, line
                try:
                    rule = idna.encode(rule, uts46=True).decode("ascii")
                except (idna.IDNAError, UnicodeError):
                    rule = rule.lower()
                target.add(rule)
    except OSError:
        return fallback
    if not exact:
        return fallback
    return (frozenset(exact), frozenset(wild), frozenset(exc))


def wildcard_psl_conflict(base, psl):
    """Why a wildcard on `base` would span a Public Suffix List zone, or None.

    Returns ('suffix', zone) when the base itself is a PSL zone (*.github.io,
    *.co.uk) and ('ancestor', zone) when a PSL zone lies underneath it
    (*.amazonaws.com contains s3.amazonaws.com). Either way the wildcard
    would admit names registrable by unrelated parties. Exact hostnames are
    never judged here: an exact host under a shared zone is as trustworthy
    as its specific owner.
    """
    exact, wild, exc = psl
    if base not in exc:
        if base in exact:
            return ("suffix", base)
        _, _, parent = base.partition(".")
        if parent and parent in wild:
            return ("suffix", base)
    marker = "." + base
    for rule in exact:
        if rule.endswith(marker):
            return ("ancestor", rule)
    for rule in wild:
        if rule == base or rule.endswith(marker):
            return ("ancestor", "*." + rule)
    return None


def _is_ip_literal(value: str) -> bool:
    """True if `value` denotes an IP address in any notation.

    Covers dotted quad, shortened ("127.1"), octal/hex components, single
    integer ("2130706433", "0x7f000001"), and IPv6 including bracketed and
    mapped forms.  inet_aton implements the classic permissive parser, which
    is exactly the parser an evasion would rely on.
    """
    candidate = value.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        pass
    try:
        socket.inet_aton(candidate)
        return True
    except (OSError, ValueError):
        pass
    try:
        int(candidate, 0)
        return True
    except ValueError:
        pass
    return False


def normalize_hostname(raw: str, tlds: frozenset, ascii_only: bool = False) -> str:
    """Validate and normalise one exact hostname, or raise ValidationError.

    Follows spec section 7.2 in order.  Returns the canonical form: punycode,
    lowercase, no trailing dot.  Store and compare only this form.

    ascii_only rejects any raw non-ASCII input instead of folding it through
    UTS46.  Use it wherever the input is machine-supplied (the agent socket,
    the proxy helper) so a Unicode form that would fold to an allowed name is
    surfaced as a rejection rather than silently accepted.  Leave it off for
    panel input, where a human may legitimately type an internationalised name.
    """
    if not isinstance(raw, str):
        raise ValidationError("INVALID_HOSTNAME", "not a string")
    if len(raw) > MAX_HOSTNAME_BYTES:
        raise ValidationError("INVALID_HOSTNAME", "exceeds 253 bytes")
    if raw != raw.strip() or not raw:
        raise ValidationError("INVALID_HOSTNAME", "empty or surrounding whitespace")
    if ascii_only and not raw.isascii():
        raise ValidationError("INVALID_HOSTNAME", "non-ASCII on a machine path")

    # Reject IP literals before any transformation so alternative encodings
    # are judged on the raw input the client actually sent.
    if _is_ip_literal(raw):
        raise ValidationError("IP_LITERAL_REJECTED", "raw input is an address")

    # Exactly one trailing dot (a valid FQDN spelling) is stripped; more is not.
    host = raw
    if host.endswith("."):
        host = host[:-1]
        if host.endswith("."):
            raise ValidationError("INVALID_HOSTNAME", "multiple trailing dots")

    # IDNA 2008 with UTS46 mapping: folds case, converts Unicode to punycode,
    # and rejects everything that is not a well-formed internationalised name.
    # The Cyrillic lookalike comes out as xn--… and can never equal its ASCII twin.
    try:
        encoded = idna.encode(host, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError) as exc:
        raise ValidationError("INVALID_HOSTNAME", "idna: %s" % exc)

    normalized = encoded.lower()
    if len(normalized) > MAX_HOSTNAME_BYTES:
        raise ValidationError("INVALID_HOSTNAME", "exceeds 253 bytes after encoding")
    if not all(33 <= ord(ch) <= 126 for ch in normalized):
        raise ValidationError("INVALID_HOSTNAME", "non-printable after encoding")

    labels = normalized.split(".")
    if len(labels) < 2:
        raise ValidationError("INVALID_HOSTNAME", "fewer than two labels")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise ValidationError("INVALID_HOSTNAME", "bad label")

    # Re-check as an address: something that survived encoding but still
    # parses as an IP in any notation is an address, not a name.
    if _is_ip_literal(normalized):
        raise ValidationError("IP_LITERAL_REJECTED", "normalised form is an address")

    tld = labels[-1]
    if tld in RESERVED_TLDS:
        raise ValidationError("INVALID_HOSTNAME", "reserved TLD")
    if tld not in tlds:
        raise ValidationError("INVALID_HOSTNAME", "TLD not in IANA list")

    return normalized


def classify_pattern(raw: str, tlds: frozenset):
    """Classify panel input as ('exact'|'wildcard', normalised_base).

    Only the panel may submit wildcards; agent submissions never reach this.
    """
    if not isinstance(raw, str):
        raise ValidationError("INVALID_HOSTNAME", "not a string")
    raw = raw.strip()
    if raw.startswith("*."):
        return "wildcard", normalize_hostname(raw[2:], tlds)
    if raw.startswith("*") or raw.startswith("."):
        raise ValidationError("INVALID_HOSTNAME", "malformed pattern")
    return "exact", normalize_hostname(raw, tlds)


def looks_like_wildcard(raw) -> bool:
    """True for agent input that is a pattern rather than an exact hostname."""
    return isinstance(raw, str) and (
        "*" in raw or raw.strip().startswith(".")
    )


def is_blocked(host: str, blocked: tuple) -> bool:
    """True if `host` (normalised) is on the never-allow list, at any depth."""
    for domain in blocked:
        if host == domain or host.endswith("." + domain):
            return True
    return False


def matches(kind: str, pattern: str, host: str) -> bool:
    """Does an allowlist entry match a normalised hostname (spec section 7.3)?

    Both `pattern` and `host` must already be normalised — and, for exact
    entries, folded through canonical_host(), which happens at the trust
    boundaries (broker sockets, panel input, list import), never here.
    'wildcard' matches any prefix depth plus the bare domain itself.
    """
    if kind == "exact":
        return host == pattern
    if kind == "wildcard":
        return host == pattern or host.endswith("." + pattern)
    return False


def canonical_host(host: str, psl) -> str:
    """Fold a leading 'www.' label into the bare domain.

    www.X and X are one equivalence class: the allowlist stores the bare
    form, and every lookup folds before matching, so approving either
    spelling covers both — the reasoning stops at www; no api., no cdn.
    The fold is skipped when the remainder would be a single label
    ('www.com' stays itself) or is a Public Suffix List zone ('www.co.uk'
    could be an unrelated party's registration under co.uk, so it stays
    distinct). `host` must already be normalised; `psl` is the tuple from
    load_psl().
    """
    if not host.startswith("www."):
        return host
    rest = host[4:]
    if "." not in rest:
        return host
    exact, wild, exc = psl
    if rest not in exc:
        if rest in exact:
            return host
        _, _, parent = rest.partition(".")
        if parent and parent in wild:
            return host
    return rest
