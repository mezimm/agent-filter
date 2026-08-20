"""Configuration loading. /etc/approval-broker/config.toml is root-owned and
read-only to the broker account; every tunable lives there, with the defaults
below as the single fallback so a missing key cannot loosen a limit silently.
"""

import os
import tomllib

DEFAULT_PATH = "/etc/approval-broker/config.toml"

DEFAULTS = {
    "paths": {
        "db": "/var/lib/approval-broker/broker.db",
        "decisions_log": "/var/log/approval-broker/decisions.log",
        "tld_list": "/etc/approval-broker/tlds.txt",
        "blocked_domains": "/etc/approval-broker/blocked-domains.txt",
        "default_allowlist": "/etc/approval-broker/default-allowlist.txt",
        "public_suffix_list": "/etc/approval-broker/public-suffix-list.dat",
        "submit_socket": "/run/approval-broker/submit.sock",
        "acl_socket": "/run/approval-broker/acl.sock",
    },
    "panel": {
        # No default bind address on purpose: the panel must bind the VM's
        # Tailscale IPv4, and a missing config must fail loudly rather than
        # silently fall back to loopback, where the agent could reach it.
        "bind_ip": None,
        "port": 9120,
        "session_hours": 12,
    },
    "limits": {
        "pending_max": 20,
        "submissions_per_hour": 30,
        "auto_rejects_per_hour": 60,
        "rationale_max_bytes": 2048,
    },
    "ports": {
        "allowed": [443],
    },
    "scopes": {
        "session_hours": 4,
    },
    "log": {
        "rotate_bytes": 1_048_576,
        "keep": 5,
    },
}


class Config:
    def __init__(self, data: dict):
        self._data = data

    def get(self, section: str, key: str):
        try:
            return self._data[section][key]
        except KeyError:
            return DEFAULTS[section][key]


def load(path: str = None) -> Config:
    if path is None:
        path = os.environ.get("APPROVAL_BROKER_CONFIG", DEFAULT_PATH)
    try:
        with open(path, "rb") as fh:
            return Config(tomllib.load(fh))
    except FileNotFoundError:
        return Config({})
