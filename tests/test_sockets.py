"""Spec section 15 fail-closed: the wire path — sockets, helper, outage."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from approval_broker import db
from approval_broker.broker import Broker, _own_socket, _serve
from approval_broker.config import Config

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HELPER = os.path.join(REPO, "bin", "acl-helper")


def write_config(tmp):
    path = os.path.join(tmp, "config.toml")
    with open(path, "w") as fh:
        fh.write(
            '[paths]\ndb = "%s"\ndecisions_log = "%s"\ntld_list = "%s"\n'
            'blocked_domains = "%s"\nsubmit_socket = "%s"\nacl_socket = "%s"\n'
            % (
                os.path.join(tmp, "broker.db"),
                os.path.join(tmp, "decisions.log"),
                os.path.join(REPO, "data", "tlds.txt"),
                os.path.join(REPO, "data", "blocked-domains.txt"),
                os.path.join(tmp, "submit.sock"),
                os.path.join(tmp, "acl.sock"),
            )
        )
    return path


def ask(sock_path, payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(sock_path)
        sock.sendall((json.dumps(payload) + "\n").encode())
        data = b""
        while b"\n" not in data:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
    return json.loads(data.decode())


class SocketPath(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg_path = write_config(self.tmp)
        os.environ["APPROVAL_BROKER_CONFIG"] = self.cfg_path
        import approval_broker.config as config_module

        self.cfg = config_module.load(self.cfg_path)
        self.broker = Broker(self.cfg)
        self.submit_sock = _own_socket(self.cfg.get("paths", "submit_socket"))
        self.acl_sock = _own_socket(self.cfg.get("paths", "acl_socket"))
        threading.Thread(
            target=_serve, args=(self.submit_sock, self.broker.submit), daemon=True
        ).start()
        threading.Thread(
            target=_serve, args=(self.acl_sock, self.broker.acl_check), daemon=True
        ).start()

    def tearDown(self):
        self.submit_sock.close()
        self.acl_sock.close()
        os.environ.pop("APPROVAL_BROKER_CONFIG", None)

    def helper(self, lines, sni=False):
        args = [sys.executable, HELPER] + (["--sni"] if sni else [])
        proc = subprocess.run(
            args,
            input="\n".join(lines) + "\n",
            capture_output=True,
            text=True,
            timeout=30,
            env={
                **os.environ,
                "PYTHONPATH": REPO,
                "APPROVAL_BROKER_CONFIG": self.cfg_path,
            },
        )
        return proc.stdout.split()

    def test_submit_over_socket(self):
        reply = ask(
            self.cfg.get("paths", "submit_socket"),
            {"host": "files.pythonhosted.org", "port": 443, "reason": "dep"},
        )
        self.assertEqual(reply["code"], "PENDING")

    def test_garbage_input_gets_structured_refusal(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(self.cfg.get("paths", "submit_socket"))
            sock.sendall(b"not json at all\n")
            data = sock.recv(4096)
        reply = json.loads(data.decode())
        self.assertIn(reply["code"], ("INVALID_HOSTNAME", "BROKER_UNAVAILABLE"))

    def test_helper_allows_and_denies(self):
        db.add_allowlist(
            self.broker.conn, "example.com", "exact", 443, "test", "permanent",
            None, "manual",
        )
        verdicts = self.helper(
            ["example.com 443", "not-listed.example.org 443",
             "derp.tailscale.com 443", "127.0.0.1 443"]
        )
        self.assertEqual(verdicts, ["OK", "ERR", "ERR", "ERR"])

    def test_helper_sni_mode(self):
        db.add_allowlist(
            self.broker.conn, "example.com", "exact", 443, "test", "permanent",
            None, "manual",
        )
        verdicts = self.helper(["example.com", "evil.example.org", "-"], sni=True)
        self.assertEqual(verdicts, ["OK", "ERR", "ERR"])

    def test_broker_down_helper_denies(self):
        # Stop the broker: connect() fails and the helper must print ERR
        # for a host that would otherwise be allowed. The agent has no
        # network while the broker is down; that is correct.
        db.add_allowlist(
            self.broker.conn, "example.com", "exact", 443, "test", "permanent",
            None, "manual",
        )
        self.acl_sock.close()
        os.unlink(self.cfg.get("paths", "acl_socket"))
        verdicts = self.helper(["example.com 443"])
        self.assertEqual(verdicts, ["ERR"])

    def test_unresponsive_broker_helper_times_out_to_deny(self):
        # A socket that accepts but never answers: the helper's timeout
        # must convert the hang into a denial, not an open wait.
        path = self.cfg.get("paths", "acl_socket")
        self.acl_sock.close()
        os.unlink(path)
        silent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        silent.bind(path)
        silent.listen(1)
        try:
            verdicts = self.helper(["example.com 443"])
            self.assertEqual(verdicts, ["ERR"])
        finally:
            silent.close()


if __name__ == "__main__":
    unittest.main()
