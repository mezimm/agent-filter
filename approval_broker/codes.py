"""Fixed reason codes with fixed human-readable text (spec section 9).

Diagnostics are never generated dynamically: the agent sees a code from this
table and its fixed message, plus (for DENIED_BY_ADMIN only) the operator's
typed reason. Internals — matching rules, entry ids, stack traces — never
leave the process.
"""

CODES = {
    "ALLOWED": "matched an active allowlist entry",
    "PAUSED_ALLOW": "allowed while enforcement is paused",
    "PENDING": "queued, awaiting a human decision",
    "DENIED_BY_ADMIN": "explicitly denied",
    "WILDCARD_NOT_PERMITTED": "wildcards may not be requested by the agent",
    "INVALID_HOSTNAME": "not a valid exact hostname",
    "IP_LITERAL_REJECTED": "IP addresses may not be requested; use a hostname",
    "PORT_NOT_PERMITTED": "port is not permitted",
    "DOMAIN_PERMANENTLY_BLOCKED": "this domain is permanently blocked",
    "RATE_LIMITED": "submission budget exhausted",
    "QUEUE_FULL": "too many pending requests",
    "BROKER_UNAVAILABLE": "approval broker unavailable",
}


def message(code: str) -> str:
    return CODES.get(code, CODES["BROKER_UNAVAILABLE"])
