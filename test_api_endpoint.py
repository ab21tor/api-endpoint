#!/usr/bin/env python3
"""Tests for api-endpoint. Stdlib only. Run:  python3 -B test_api_endpoint.py -v

Unit tests cover the pure pieces. Integration tests run the real service as a
subprocess against a fake L402 gateway and a fake phoenixd living in this
process (so their counters survive killing the service), on ephemeral ports,
with DATA_DIR in a temp dir. The two real proofs ship in fixtures/ with the
repo and are read (never written) to pin the anchored-detector to reality.

The four crash/money invariants, by test name:
  test_sigkill_mid_burst_every_acked_record_bought
  test_kill_inside_pay_to_redeem_window_exactly_one_payment
  test_corrupt_ledger_pauses_purchases_never_intake
  test_anchored_detector_against_real_proofs
"""

import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import api_endpoint  # noqa: E402

SERVICE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_endpoint.py")

_FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
ANCHORED_REAL = os.path.join(_FIXTURES, "anchored.ots")  # real anchored proof, bought from the gateway
PENDING_REAL = os.path.join(_FIXTURES, "pending.ots")    # real pending proof, same purchase path

TEST_PW = "testpw"
EXPECTED_AUTH = "Basic " + base64.b64encode(b":" + TEST_PW.encode()).decode()
CAL_TAG = b"\x00" + bytes.fromhex("83dfe30d2ef90c8e")


def pending_ots(fp):
    b = api_endpoint.OTS_MAGIC + bytes.fromhex(fp) + CAL_TAG + b"fake-calendar"
    assert api_endpoint.BITCOIN_ATTESTATION not in b
    return b


def anchored_ots(fp):
    return (api_endpoint.OTS_MAGIC + bytes.fromhex(fp)
            + api_endpoint.BITCOIN_ATTESTATION + b"\x01\x02")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# fake phoenixd
class FakeLightning:
    """Counts every /decodeinvoice and /payinvoice call. Invoices look like
    'lnfake:<sats>:<fp>:<n>' so amounts and fingerprints are recoverable.
    Preimage is sha256(invoice) — deterministic, so re-paying the same
    invoice yields the same preimage (a settled invoice settles once).
    Payments fail while their fingerprint is in fail_pay_fps; fail_next_pays
    fails the next N payments whatever the invoice, then settles."""

    def __init__(self):
        self.lock = threading.Lock()
        self.decode_calls = []
        self.pay_calls = []
        self.fail_pay_fps = set()
        self.fail_next_pays = 0
        self.auth_failures = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                try:
                    self.wfile.write(b)
                except OSError:
                    pass

            def do_POST(self):
                if self.headers.get("Authorization") != EXPECTED_AUTH:
                    with outer.lock:
                        outer.auth_failures += 1
                    self._json(401, {"error": "bad auth"})
                    return
                n = int(self.headers.get("Content-Length", "0"))
                q = urllib.parse.parse_qs(self.rfile.read(n).decode())
                invoice = (q.get("invoice") or [""])[0]
                if self.path == "/decodeinvoice":
                    with outer.lock:
                        outer.decode_calls.append(invoice)
                    parts = invoice.split(":")
                    if len(parts) == 4 and parts[0] == "lnfake":
                        self._json(200, {"amountSat": int(parts[1])})
                    else:
                        self._json(200, {"unparseable": True})
                    return
                if self.path == "/payinvoice":
                    with outer.lock:
                        outer.pay_calls.append(invoice)
                        fail = any(fp in invoice for fp in outer.fail_pay_fps)
                        if not fail and outer.fail_next_pays > 0:
                            outer.fail_next_pays -= 1
                            fail = True
                    if fail:
                        self._json(200, {"reason": "payment failed"})
                    else:
                        self._json(200, {"paymentPreimage":
                                         hashlib.sha256(invoice.encode()).hexdigest()})
                    return
                self._json(404, {})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()

    def pays_for_fp(self, fp):
        with self.lock:
            return [i for i in self.pay_calls if fp in i]

    def distinct_paid_invoices_for_fp(self, fp):
        return set(self.pays_for_fp(fp))


# fake L402 gateway
class FakeGateway:
    """Speaks the timestamp-gateway contract (main.py): 402 with a
    WWW-Authenticate L402 challenge, raw .ots bytes on redeem, and JSON
    base64 both ways on /upgrade."""

    def __init__(self):
        self.lock = threading.Lock()
        self.price = 21
        self.redeem_delay = 0.0
        self.challenges = []
        self.redeems = []
        self.upgrade_calls = []
        self.minted = {}      # token -> (fp, invoice)
        self.counter = 0
        self.anchor_now = set()
        self.stall_redeem = {}  # fp -> {"event", "secs", "used"}
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _raw(self, code, body, headers=None):
                self.send_response(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

            def _json(self, code, obj, headers=None):
                h = {"Content-Type": "application/json"}
                h.update(headers or {})
                self._raw(code, json.dumps(obj).encode(), h)

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                try:
                    body = json.loads(self.rfile.read(n).decode())
                except ValueError:
                    self._json(400, {"detail": "bad json"})
                    return
                digest = (body.get("digest") or "").lower()
                if self.path == "/timestamp":
                    auth = self.headers.get("Authorization", "")
                    if auth.startswith("L402 "):
                        outer._redeem(self, digest, auth)
                    else:
                        outer._challenge(self, digest)
                    return
                if self.path == "/upgrade":
                    outer._upgrade(self, digest, body)
                    return
                self._json(404, {"detail": "nope"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()

    def _challenge(self, h, digest):
        with self.lock:
            self.counter += 1
            token = f"tok-{digest[:12]}-{self.counter}"
            invoice = f"lnfake:{self.price}:{digest}:{self.counter}"
            self.minted[token] = (digest, invoice)
            self.challenges.append(digest)
        h._json(402, {"detail": {"status": "payment_required",
                                 "price_sats": self.price}},
                {"WWW-Authenticate":
                 f'L402 macaroon="{token}", invoice="{invoice}"'})

    def _redeem(self, h, digest, auth):
        token, _, preimage = auth[len("L402 "):].partition(":")
        with self.lock:
            entry = self.minted.get(token)
            stall = self.stall_redeem.get(digest)
            use_stall = bool(stall and not stall["used"])
            if use_stall:
                stall["used"] = True
        if not entry:
            h._json(401, {"detail": "unknown token"})
            return
        fp, invoice = entry
        if fp != digest or \
                hashlib.sha256(invoice.encode()).hexdigest() != preimage.lower():
            h._json(401, {"detail": "bad token or preimage"})
            return
        if use_stall:
            stall["event"].set()
            time.sleep(stall["secs"])
        if self.redeem_delay:
            time.sleep(self.redeem_delay)
        with self.lock:
            self.redeems.append(fp)
        h._raw(200, pending_ots(fp), {"Content-Type": "application/octet-stream"})

    def _upgrade(self, h, digest, body):
        try:
            ots = base64.b64decode(body.get("ots") or "", validate=True)
        except ValueError:
            h._json(200, {"status": "invalid", "bitcoin_anchored": False,
                          "ots": None})
            return
        with self.lock:
            self.upgrade_calls.append(digest)
            anchor = digest in self.anchor_now
        if anchor:
            nb = anchored_ots(digest)
            h._json(200, {"status": "anchored", "bitcoin_anchored": True,
                          "ots": base64.b64encode(nb).decode()})
        else:
            h._json(200, {"status": "pending", "bitcoin_anchored": False,
                          "ots": base64.b64encode(ots).decode()})

    def stall_next_redeem(self, fp, secs=10.0):
        ev = threading.Event()
        with self.lock:
            self.stall_redeem[fp] = {"event": ev, "secs": secs, "used": False}
        return ev

    def challenges_for(self, fp):
        with self.lock:
            return self.challenges.count(fp)

    def upgrades_for(self, fp):
        with self.lock:
            return self.upgrade_calls.count(fp)


# service subprocess runner
class ServiceRunner:
    def __init__(self, base_dir, env):
        self.base_dir = base_dir
        self.env = env
        self.proc = None
        self.port = int(env["LISTEN_ADDR"].rsplit(":", 1)[1])

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def start(self):
        full = dict(os.environ)
        full.update(self.env)
        errfile = open(os.path.join(self.base_dir, "service.err"), "ab")
        self.proc = subprocess.Popen([sys.executable, "-B", SERVICE], env=full,
                                     stdout=errfile, stderr=errfile,
                                     cwd=self.base_dir)
        errfile.close()
        self.wait_ready()

    def wait_ready(self, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError("service exited at startup:\n" + self.read_err())
            try:
                req = urllib.request.Request(self.url("/record"), method="GET")
                with urllib.request.urlopen(req, timeout=1):
                    return
            except urllib.error.HTTPError:
                return  # 405 means the door is up
            except OSError:
                time.sleep(0.05)
        raise AssertionError("service never became ready:\n" + self.read_err())

    def kill9(self):
        self.proc.kill()
        self.proc.wait()

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()

    def read_err(self):
        try:
            with open(os.path.join(self.base_dir, "service.err"),
                      errors="replace") as f:
                return f.read()
        except OSError:
            return "<no stderr>"


def post_record(runner, body, digest_header=None, path="/record", timeout=5):
    headers = {"Content-Type": "application/octet-stream"}
    if digest_header is not None:
        headers["X-Digest"] = digest_header
    req = urllib.request.Request(runner.url(path), data=body, headers=headers,
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


class IntegrationBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="api-endpoint-test-")
        self.ln = FakeLightning()
        self.gw = FakeGateway()
        self.runner = None

    def tearDown(self):
        if self.runner:
            self.runner.stop()
        self.gw.shutdown()
        self.ln.shutdown()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_env(self, **over):
        conf = os.path.join(self.tmp, "phoenix.conf")
        with open(conf, "w") as f:
            # The limited key comes first: the service must NOT match it.
            f.write("http-password-limited-access=nope\n"
                    f"http-password={TEST_PW}\n")
        env = {
            "LISTEN_ADDR": f"127.0.0.1:{free_port()}",
            "GATEWAY_URL": f"http://127.0.0.1:{self.gw.port}",
            "PHOENIXD_URL": f"http://127.0.0.1:{self.ln.port}",
            "PHOENIX_CONF": conf,
            "DATA_DIR": os.path.join(self.tmp, "data"),
            "MAX_PRICE_SATS": "5000",
            "DAILY_BUDGET_SATS": "200000",
            "POLL_SECS": "0.05",
            "UPGRADE_SECS": "3600",
            "HEARTBEAT_SECS": "0.2",
            "L402_EXPIRY_SECS": "3600",
        }
        env.update({k: str(v) for k, v in over.items()})
        return env

    def start_service(self, **over):
        self.runner = ServiceRunner(self.tmp, self.make_env(**over))
        self.runner.start()
        return self.runner

    def data(self, *parts):
        return os.path.join(self.tmp, "data", *parts)

    def debt_file(self, fp):
        return self.data("debts", fp)

    def sidecar_file(self, fp):
        return self.data("debts", fp + ".l402")

    def proof_file(self, fp):
        return self.data("proofs", fp + ".ots")

    def read_service_log(self):
        try:
            with open(self.data("log")) as f:
                return f.read()
        except OSError:
            return "<no log>"

    def wait_until(self, cond, timeout=20, what="condition"):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if cond():
                return
            time.sleep(0.03)
        err = self.runner.read_err() if self.runner else ""
        self.fail(f"timeout waiting for {what}\n--- service log ---\n"
                  f"{self.read_service_log()}\n--- service stderr ---\n{err}")


# unit tests
class TestAnchoredDetector(unittest.TestCase):
    def test_anchored_detector_against_real_proofs(self):
        """The byte scan against the two real proofs, read-only."""
        with open(ANCHORED_REAL, "rb") as f:
            anchored = f.read()
        with open(PENDING_REAL, "rb") as f:
            pending = f.read()
        self.assertTrue(api_endpoint.looks_like_ots(anchored))
        self.assertTrue(api_endpoint.is_anchored(anchored),
                        "real anchored proof not detected as anchored")
        self.assertTrue(api_endpoint.looks_like_ots(pending))
        self.assertFalse(api_endpoint.is_anchored(pending),
                         "real pending proof wrongly detected as anchored")


class TestPureUnits(unittest.TestCase):
    def test_hex_digest_rule(self):
        self.assertEqual(api_endpoint.validate_hex_digest(" " + "A" * 64 + "\n"),
                         "a" * 64)
        self.assertIsNone(api_endpoint.validate_hex_digest("a" * 63))
        self.assertIsNone(api_endpoint.validate_hex_digest("a" * 65))
        self.assertIsNone(api_endpoint.validate_hex_digest("g" * 64))
        self.assertIsNone(api_endpoint.validate_hex_digest(""))

    def test_l402_challenge_parse(self):
        mac, inv = api_endpoint.parse_l402_challenge(
            'L402 macaroon="m==", invoice="lnbc1"')
        self.assertEqual((mac, inv), ("m==", "lnbc1"))
        self.assertIsNone(api_endpoint.parse_l402_challenge("Basic zzz"))
        self.assertIsNone(api_endpoint.parse_l402_challenge('L402 macaroon="m"'))
        self.assertIsNone(api_endpoint.parse_l402_challenge(None))

    def test_amount_precedence_and_fail_closed(self):
        f = api_endpoint.amount_sats_from_decoded
        self.assertEqual(f({"amountSat": 12, "amount": 999000}), 12)
        self.assertEqual(f({"amount": 12000}), 12)
        self.assertEqual(f({"amountMsat": 15000}), 15)
        self.assertIsNone(f({"amountSat": 0}))
        self.assertIsNone(f({"amount": 500}))     # sub-sat rounds to zero: refuse
        self.assertIsNone(f({"amountSat": True}))
        self.assertIsNone(f({}))
        self.assertIsNone(f(None))

    def test_ledger_roundtrip_and_corruption(self):
        d = tempfile.mkdtemp(prefix="ledger-test-")
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "ledger")
        self.assertEqual(api_endpoint.read_ledger(p)[1], 0)  # absent = clean zero
        api_endpoint.write_ledger(p, "2026-07-31", 42)
        self.assertEqual(api_endpoint.read_ledger(p), ("2026-07-31", 42))
        for garbage in ("nonsense\n", "2026-07-31 12 extra\n",
                        "2026-07-31 -5\n", "2026-07-31 12\n2026-07-31 13\n"):
            with open(p, "w") as f:
                f.write(garbage)
            with self.assertRaises(api_endpoint.LedgerCorrupt, msg=repr(garbage)):
                api_endpoint.read_ledger(p)

    def test_config_teaching_errors_and_precedence(self):
        d = tempfile.mkdtemp(prefix="cfg-test-")
        self.addCleanup(shutil.rmtree, d, True)
        with self.assertRaises(api_endpoint.ConfigError) as cm:
            api_endpoint.resolve_config({}, script_dir=d)
        self.assertIn("LISTEN_ADDR", str(cm.exception))
        self.assertIn("127.0.0.1:8402", str(cm.exception))
        with self.assertRaises(api_endpoint.ConfigError) as cm:
            api_endpoint.resolve_config({"LISTEN_ADDR": "127.0.0.1:1"},
                                        script_dir=d)
        self.assertIn("GATEWAY_URL", str(cm.exception))
        for bad in ("nocolon", ":8000", "h:0", "h:70000", "h:abc"):
            with self.assertRaises(api_endpoint.ConfigError, msg=bad):
                api_endpoint.resolve_config(
                    {"LISTEN_ADDR": bad, "GATEWAY_URL": "http://x"}, script_dir=d)
        with self.assertRaises(api_endpoint.ConfigError):
            api_endpoint.resolve_config(
                {"LISTEN_ADDR": "h:1", "GATEWAY_URL": "http://x",
                 "MAX_PRICE_SATS": "-3"}, script_dir=d)
        with open(os.path.join(d, ".env"), "w") as f:
            f.write('# comment\nGATEWAY_URL="http://from-envfile:1/"\n'
                    "MAX_PRICE_SATS=7\n")
        cfg = api_endpoint.resolve_config(
            {"LISTEN_ADDR": "127.0.0.1:8402", "MAX_PRICE_SATS": "9"},
            script_dir=d)
        self.assertEqual(cfg["gateway_url"], "http://from-envfile:1")
        self.assertEqual(cfg["max_price_sats"], 9)   # invocation env wins
        cfg2 = api_endpoint.resolve_config({"LISTEN_ADDR": "127.0.0.1:8402"},
                                           script_dir=d)
        self.assertEqual(cfg2["max_price_sats"], 7)  # .env beats the default

    def test_phoenix_password_parsing(self):
        d = tempfile.mkdtemp(prefix="pw-test-")
        self.addCleanup(shutil.rmtree, d, True)
        conf = os.path.join(d, "phoenix.conf")
        with open(conf, "w") as f:
            f.write("http-password-limited-access=limited\nhttp-password=full\n")
        self.assertEqual(api_endpoint.read_phoenix_password(conf), "full")
        with open(conf, "w") as f:
            f.write("http-password-limited-access=limited\n")
        with self.assertRaises(api_endpoint.ConfigError):
            api_endpoint.read_phoenix_password(conf)
        with self.assertRaises(api_endpoint.ConfigError):
            api_endpoint.read_phoenix_password(os.path.join(d, "missing.conf"))


# integration: the door
class TestDoor(IntegrationBase):
    def test_routes_replies_and_fingerprints(self):
        r = self.start_service()
        # Raw record: hashed in memory, acked, promise on disk at ack time.
        body = b"hello api-endpoint"
        fp = hashlib.sha256(body).hexdigest()
        code, text = post_record(r, body)
        self.assertEqual((code, text), (200, f"received {fp}\n"))
        self.assertTrue(os.path.exists(self.debt_file(fp))
                        or os.path.exists(self.proof_file(fp)),
                        "acked with no debt and no proof on disk")
        # X-Digest: sha256 accepts a ready-made digest (case + whitespace).
        dg = hashlib.sha256(b"other record").hexdigest()
        code, text = post_record(r, (dg.upper() + "\n").encode(),
                                 digest_header="sha256")
        self.assertEqual((code, text), (200, f"received {dg}\n"))
        # Never guess from content: a bare 64-hex body without the header
        # is a record like any other and gets hashed.
        hexbody = ("ab" * 32).encode()
        hashed = hashlib.sha256(hexbody).hexdigest()
        code, text = post_record(r, hexbody)
        self.assertEqual((code, text), (200, f"received {hashed}\n"))
        self.assertNotEqual(hashed, hexbody.decode())
        # Rejects.
        self.assertEqual(post_record(r, b"zzz", digest_header="sha256")[0], 400)
        self.assertEqual(post_record(r, ("c" * 63).encode(),
                                     digest_header="sha256")[0], 400)
        self.assertEqual(post_record(r, dg.encode(), digest_header="md5")[0], 400)
        self.assertEqual(post_record(r, b"")[0], 400)
        self.assertEqual(post_record(r, b"x", path="/status")[0], 404)
        req = urllib.request.Request(r.url("/record"), method="GET")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(cm.exception.code, 405)
        # No Content-Length -> 411 (raw socket; urllib always sends one).
        with socket.create_connection(("127.0.0.1", r.port), timeout=5) as s:
            s.sendall(b"POST /record HTTP/1.0\r\nHost: t\r\n\r\n")
            first_line = s.recv(1000).decode().split("\r\n")[0]
        self.assertIn("411", first_line)
        # All three accepted records end in proofs bought from the gateway.
        for f in (fp, dg, hashed):
            self.wait_until(lambda f=f: os.path.exists(self.proof_file(f)),
                            what=f"proof for {f[:12]}")
            with open(self.proof_file(f), "rb") as fh:
                self.assertEqual(fh.read(), pending_ots(f))
            self.assertFalse(os.path.exists(self.debt_file(f)))
            self.assertFalse(os.path.exists(self.sidecar_file(f)))
        # The password was used correctly and never rejected.
        self.assertEqual(self.ln.auth_failures, 0)
        # Heartbeat exists and carries pid + loop timestamps.
        self.wait_until(lambda: os.path.exists(self.data("heartbeat")),
                        what="heartbeat")
        with open(self.data("heartbeat")) as f:
            hb = f.read()
        self.assertIn(f"pid={self.runner.proc.pid}", hb)
        self.assertIn("buyer=", hb)
        self.assertIn("upgrader=", hb)

    def test_duplicate_record_one_payment_one_proof(self):
        r = self.start_service()
        body = b"posted twice"
        fp = hashlib.sha256(body).hexdigest()
        self.assertEqual(post_record(r, body)[0], 200)
        self.assertEqual(post_record(r, body)[0], 200)
        self.wait_until(lambda: os.path.exists(self.proof_file(fp)),
                        what="proof")
        self.wait_until(lambda: not os.path.exists(self.debt_file(fp)),
                        what="debt cleared")
        self.assertEqual(len(self.ln.pays_for_fp(fp)), 1)
        self.assertEqual(len(self.ln.distinct_paid_invoices_for_fp(fp)), 1)
        # A re-POST after the proof exists is acked without a new debt.
        code, text = post_record(r, body)
        self.assertEqual((code, text), (200, f"received {fp}\n"))
        self.assertFalse(os.path.exists(self.debt_file(fp)))
        self.assertEqual(len(self.ln.pays_for_fp(fp)), 1)


# integration: buyer policy
class TestBuyerPolicy(IntegrationBase):
    def test_price_ceiling_refuses_and_keeps_debt(self):
        self.gw.price = 60
        r = self.start_service(MAX_PRICE_SATS="50")
        code, text = post_record(r, b"too expensive")
        fp = text.split()[1]
        self.wait_until(lambda: self.gw.challenges_for(fp) >= 1,
                        what="challenge attempt")
        self.wait_until(lambda: "exceeds_price_ceiling" in self.read_service_log(),
                        what="ceiling skip logged")
        time.sleep(0.3)  # several more passes
        self.assertEqual(len(self.ln.pay_calls), 0)
        self.assertTrue(os.path.exists(self.debt_file(fp)), "debt was dropped")
        # No reservation happens before the ceiling check.
        self.assertFalse(os.path.exists(self.data("ledger")))

    def test_budget_exhausts_and_keeps_third_debt(self):
        self.gw.price = 10
        r = self.start_service(DAILY_BUDGET_SATS="25")
        fps = []
        for i in range(3):
            code, text = post_record(r, f"budget record {i}".encode())
            self.assertEqual(code, 200)
            fps.append(text.split()[1])
        self.wait_until(
            lambda: sum(os.path.exists(self.proof_file(f)) for f in fps) == 2,
            what="two proofs within budget")
        self.wait_until(lambda: "exceeds_daily_budget" in self.read_service_log(),
                        what="budget skip logged")
        time.sleep(0.3)
        bought = [f for f in fps if os.path.exists(self.proof_file(f))]
        owed = [f for f in fps if os.path.exists(self.debt_file(f))]
        self.assertEqual(len(bought), 2)
        self.assertEqual(len(owed), 1)
        day, spent = api_endpoint.read_ledger(self.data("ledger"))
        self.assertEqual((day, spent), (api_endpoint.utc_today(), 20))

    def test_budget_reserves_attempt_before_payment(self):
        self.gw.price = 10
        r = self.start_service()
        body = b"payment will fail first"
        fp = hashlib.sha256(body).hexdigest()
        self.ln.fail_pay_fps.add(fp)
        self.assertEqual(post_record(r, body)[0], 200)
        self.wait_until(lambda: len(self.ln.pays_for_fp(fp)) >= 1,
                        what="failed payment attempt")
        # Reserved before paying, and kept after the failure (fail closed).
        day, spent = api_endpoint.read_ledger(self.data("ledger"))
        self.assertEqual((day, spent), (api_endpoint.utc_today(), 10))
        self.assertFalse(os.path.exists(self.proof_file(fp)))
        self.assertTrue(os.path.exists(self.debt_file(fp)))
        self.assertTrue(os.path.exists(self.sidecar_file(fp)))
        self.assertIn("payment_failed", self.read_service_log())
        # Heal: the STORED invoice is retried — no fresh challenge, and the
        # single reservation covers the single possible settlement.
        challenges_before = self.gw.challenges_for(fp)
        self.ln.fail_pay_fps.discard(fp)
        self.wait_until(lambda: os.path.exists(self.proof_file(fp)),
                        what="proof after payment heals")
        self.assertEqual(self.gw.challenges_for(fp), challenges_before)
        self.assertEqual(len(self.ln.distinct_paid_invoices_for_fp(fp)), 1)
        day, spent = api_endpoint.read_ledger(self.data("ledger"))
        self.assertEqual(spent, 10)

    def test_exhausted_budget_makes_no_gateway_contact(self):
        """A box whose day is fully spent must not ask the gateway for
        challenges (or phoenixd for decodes) — while a younger debt whose
        sidecar already holds a paid preimage still redeems: settlement
        outranks expiry, whatever the budget says."""
        os.makedirs(self.data("debts"))
        with open(self.data("ledger"), "w") as f:
            f.write(f"{api_endpoint.utc_today()} 200000\n")
        # Older debt, no sidecar: the budget gate must skip it silently.
        fp_old = hashlib.sha256(b"exhausted old debt").hexdigest()
        with open(self.debt_file(fp_old), "w") as f:
            f.write(fp_old + "\n")
        past = time.time() - 100
        os.utime(self.debt_file(fp_old), (past, past))
        # Younger debt, paid but unredeemed: preimage in the sidecar, the
        # matching token pre-minted in the gateway.
        fp_paid = hashlib.sha256(b"exhausted paid debt").hexdigest()
        invoice = f"lnfake:21:{fp_paid}:777"
        token = "tok-preminted-777"
        preimage = hashlib.sha256(invoice.encode()).hexdigest()
        with self.gw.lock:
            self.gw.minted[token] = (fp_paid, invoice)
        with open(self.debt_file(fp_paid), "w") as f:
            f.write(fp_paid + "\n")
        with open(self.sidecar_file(fp_paid), "w") as f:
            f.write(json.dumps({"macaroon": token, "invoice": invoice,
                                "preimage": preimage}) + "\n")
        self.start_service()
        self.wait_until(lambda: os.path.exists(self.proof_file(fp_paid)),
                        what="paid sidecar redeemed while exhausted")
        time.sleep(0.4)  # several more passes at POLL_SECS=0.05
        self.assertEqual(len(self.gw.challenges), 0,
                         "gateway asked for challenges while exhausted")
        self.assertEqual(len(self.ln.decode_calls), 0,
                         "phoenixd decoded while exhausted")
        self.assertEqual(len(self.ln.pay_calls), 0, "paid while exhausted")
        # The redeem was the only gateway contact, and only for the paid debt.
        with self.gw.lock:
            self.assertEqual(self.gw.redeems, [fp_paid])
        self.assertFalse(os.path.exists(self.debt_file(fp_paid)))
        self.assertFalse(os.path.exists(self.sidecar_file(fp_paid)))
        self.assertTrue(os.path.exists(self.debt_file(fp_old)),
                        "debt was dropped")
        # Once per transition, not per debt per pass.
        self.assertEqual(self.read_service_log().count("budget_exhausted"), 1)
        day, spent = api_endpoint.read_ledger(self.data("ledger"))
        self.assertEqual((day, spent), (api_endpoint.utc_today(), 200000))

    def test_budget_resumes_on_new_day(self):
        """When the UTC day rolls over, purchasing resumes and budget_resumed
        logs exactly once."""
        os.makedirs(self.data())
        with open(self.data("ledger"), "w") as f:
            f.write(f"{api_endpoint.utc_today()} 200000\n")
        r = self.start_service()
        code, text = post_record(r, b"resumes tomorrow")
        self.assertEqual(code, 200)
        fp = text.split()[1]
        self.wait_until(lambda: "budget_exhausted" in self.read_service_log(),
                        what="budget_exhausted logged")
        time.sleep(0.3)
        self.assertEqual(len(self.gw.challenges), 0)
        self.assertTrue(os.path.exists(self.debt_file(fp)))
        # The day rolls: same spend, yesterday's date — today has headroom.
        api_endpoint.write_ledger(self.data("ledger"), "2000-01-01", 200000)
        self.wait_until(lambda: os.path.exists(self.proof_file(fp)),
                        what="proof after the day rolls")
        log = self.read_service_log()
        self.assertEqual(log.count("budget_resumed"), 1)
        self.assertEqual(log.count("budget_exhausted"), 1)
        self.assertFalse(os.path.exists(self.debt_file(fp)))
        day, spent = api_endpoint.read_ledger(self.data("ledger"))
        self.assertEqual((day, spent), (api_endpoint.utc_today(), 21))


# integration: circuit breaker
class TestCircuitBreaker(IntegrationBase):
    def test_breaker_trips_and_stops_the_spend(self):
        """The measured fault: the payer answers but cannot pay. Three
        consecutive failures trip the breaker, the spend stops at 3 reserved
        sats, and intake keeps accepting while purchasing is paused."""
        self.gw.price = 1
        # Hold purchases with a corrupt ledger
        # while the records arrive, so the first live pass meets every debt
        # at once and each failure is a fresh 1-sat reservation.
        os.makedirs(self.data())
        with open(self.data("ledger"), "w") as f:
            f.write("hold until fed\n")
        r = self.start_service(CIRCUIT_BREAKER_FAILURES="3",
                               CIRCUIT_BREAKER_PAUSE_SECS="3600")
        fps = []
        for i in range(8):
            body = f"breaker record {i}".encode()
            self.ln.fail_pay_fps.add(hashlib.sha256(body).hexdigest())
            code, text = post_record(r, body)
            self.assertEqual(code, 200)
            fps.append(text.split()[1])
        os.remove(self.data("ledger"))  # repair: the buyer meets 8 debts
        self.wait_until(lambda: "breaker_tripped" in self.read_service_log(),
                        what="breaker_tripped logged")
        time.sleep(0.3)  # many passes while paused
        self.assertEqual(len(self.ln.pay_calls), 3,
                         "attempts continued after the breaker tripped")
        day, spent = api_endpoint.read_ledger(self.data("ledger"))
        self.assertEqual((day, spent), (api_endpoint.utc_today(), 3))
        # Intake is untouched while the breaker holds.
        code, text = post_record(r, b"accepted while breaker open")
        self.assertEqual(code, 200)
        fp = text.split()[1]
        self.assertTrue(os.path.exists(self.debt_file(fp)))
        # Nothing was bought and no debt was dropped.
        for f in fps:
            self.assertTrue(os.path.exists(self.debt_file(f)))
            self.assertFalse(os.path.exists(self.proof_file(f)))

    def test_settled_payment_resets_the_breaker(self):
        """Two failures, then payments settle: any successful purchase resets
        the count, so the breaker never trips and every record is bought."""
        self.gw.price = 1
        self.ln.fail_next_pays = 2
        r = self.start_service(CIRCUIT_BREAKER_FAILURES="3",
                               CIRCUIT_BREAKER_PAUSE_SECS="3600")
        fps = []
        for i in range(3):
            code, text = post_record(r, f"reset record {i}".encode())
            self.assertEqual(code, 200)
            fps.append(text.split()[1])
        for fp in fps:
            self.wait_until(lambda fp=fp: os.path.exists(self.proof_file(fp)),
                            what=f"proof for {fp[:12]}")
            self.assertFalse(os.path.exists(self.debt_file(fp)))
            self.assertFalse(os.path.exists(self.sidecar_file(fp)))
        # Both refusals really happened (or the test is vacuous), and each
        # record settled exactly once: 2 failures + 3 settlements.
        self.assertEqual(self.ln.fail_next_pays, 0)
        self.assertIn("payment_failed", self.read_service_log())
        self.assertEqual(len(self.ln.pay_calls), 5)
        self.assertNotIn("breaker_tripped", self.read_service_log())


# integration: corrupt ledger
class TestCorruptLedger(IntegrationBase):
    def test_corrupt_ledger_pauses_purchases_never_intake(self):
        """A corrupt ledger stops buying (no gateway contact, no
        payments) while the door keeps accepting and writing debts."""
        os.makedirs(self.data())
        with open(self.data("ledger"), "w") as f:
            f.write("this is not a ledger\n")
        r = self.start_service()
        fps = []
        for i in range(2):
            code, text = post_record(r, f"paused intake {i}".encode())
            self.assertEqual(code, 200, "intake must accept while paused")
            fps.append(text.split()[1])
        self.wait_until(
            lambda: "purchases_paused reason=ledger_unreadable" in self.read_service_log(),
            what="purchases_paused logged")
        time.sleep(0.4)  # many passes while paused
        self.assertEqual(len(self.gw.challenges), 0, "gateway contacted while paused")
        self.assertEqual(len(self.ln.pay_calls), 0, "paid while paused")
        for fp in fps:
            self.assertTrue(os.path.exists(self.debt_file(fp)),
                            "debt missing while paused")
        # Intake STILL accepts new records while purchases are paused.
        code, text = post_record(r, b"accepted mid-pause")
        self.assertEqual(code, 200)
        fp3 = text.split()[1]
        self.assertTrue(os.path.exists(self.debt_file(fp3)))
        # The corrupt ledger was never overwritten or reset by the service.
        with open(self.data("ledger")) as f:
            self.assertEqual(f.read(), "this is not a ledger\n")
        # Operator repairs the ledger: purchases resume, nothing was lost.
        os.remove(self.data("ledger"))
        for fp in fps + [fp3]:
            self.wait_until(lambda fp=fp: os.path.exists(self.proof_file(fp)),
                            what=f"proof after repair for {fp[:12]}")
        self.assertIn("purchases_resumed", self.read_service_log())


# integration: upgrader
class TestUpgrader(IntegrationBase):
    def test_upgrade_replaces_only_on_anchored_and_then_stops(self):
        r = self.start_service(UPGRADE_SECS="0.15")
        body = b"to be anchored"
        fp = hashlib.sha256(body).hexdigest()
        self.assertEqual(post_record(r, body)[0], 200)
        self.wait_until(lambda: os.path.exists(self.proof_file(fp)), what="proof")
        # Pending answers must never rewrite the file.
        self.wait_until(lambda: self.gw.upgrades_for(fp) >= 2,
                        what="two pending upgrade polls")
        with open(self.proof_file(fp), "rb") as f:
            self.assertEqual(f.read(), pending_ots(fp))
        # The gateway anchors it: the file is replaced with the upgraded bytes.
        self.gw.anchor_now.add(fp)

        def proof_is_anchored():
            with open(self.proof_file(fp), "rb") as f:
                return api_endpoint.is_anchored(f.read())

        self.wait_until(proof_is_anchored, what="proof anchored on disk")
        with open(self.proof_file(fp), "rb") as f:
            self.assertEqual(f.read(), anchored_ots(fp))
        self.assertIn("anchored fp=" + fp, self.read_service_log())
        # Anchored proofs are never polled again.
        n = self.gw.upgrades_for(fp)
        time.sleep(0.6)
        self.assertEqual(self.gw.upgrades_for(fp), n)


# integration: SIGKILL recovery
class TestKillMidBurst(IntegrationBase):
    def test_sigkill_mid_burst_every_acked_record_bought(self):
        """SIGKILL mid-burst; after restart every acknowledged
        fingerprint ends in a proof, and no fingerprint paid twice."""
        self.gw.redeem_delay = 0.12  # keep a backlog while the burst runs
        r = self.start_service()
        acked = []
        stop = threading.Event()

        def blaster():
            for i in range(60):
                if stop.is_set():
                    return
                try:
                    code, text = post_record(r, f"burst record {i}".encode())
                except Exception:
                    return  # the kill landed; in-flight request died unacked
                if code != 200:
                    return
                acked.append(text.split()[1])

        t = threading.Thread(target=blaster)
        t.start()
        self.wait_until(
            lambda: len(acked) >= 12 and
            any(n.endswith(".ots") for n in os.listdir(self.data("proofs"))),
            timeout=30, what="mid-burst state (some bought, more owed)")
        r.kill9()
        stop.set()
        t.join(timeout=15)
        snapshot = list(acked)
        self.assertGreaterEqual(len(snapshot), 12)
        # Every acknowledged fingerprint is on disk as debt or proof — the
        # promise survived the kill.
        for fp in snapshot:
            self.assertTrue(os.path.exists(self.debt_file(fp))
                            or os.path.exists(self.proof_file(fp)),
                            f"acked {fp} vanished at kill")
        # The kill must have landed mid-work or it proved nothing.
        self.assertTrue(any(os.path.exists(self.debt_file(fp)) for fp in snapshot),
                        "kill landed after all debts were bought; test is vacuous")
        # Restart on the same disk: everything acknowledged gets bought.
        self.gw.redeem_delay = 0.0
        r.start()
        self.wait_until(
            lambda: all(os.path.exists(self.proof_file(fp)) for fp in snapshot),
            timeout=45, what="every acked record bought after restart")
        for fp in snapshot:
            self.assertFalse(os.path.exists(self.debt_file(fp)))
            self.assertEqual(len(self.ln.distinct_paid_invoices_for_fp(fp)), 1,
                             f"{fp} paid on more than one invoice")
        # The ledger survived the kill well-formed and covers every purchase.
        day, spent = api_endpoint.read_ledger(self.data("ledger"))
        self.assertEqual(day, api_endpoint.utc_today())
        self.assertGreaterEqual(spent, self.gw.price * len(snapshot))


class TestKillPayRedeemWindow(IntegrationBase):
    def test_kill_inside_pay_to_redeem_window_exactly_one_payment(self):
        """SIGKILL while the redeem is in flight (payment done,
        proof not yet saved). After restart the stored preimage is redeemed —
        the fake phoenixd counts exactly one payment for the fingerprint."""
        r = self.start_service()
        body = b"kill me between pay and redeem"
        fp = hashlib.sha256(body).hexdigest()
        ev = self.gw.stall_next_redeem(fp, secs=10.0)
        self.assertEqual(post_record(r, body)[0], 200)
        self.assertTrue(ev.wait(20), "redeem never started")
        # Inside the window: paid, preimage durable in the sidecar, no proof.
        with open(self.sidecar_file(fp)) as f:
            sidecar = json.load(f)
        self.assertIn("preimage", sidecar)
        self.assertEqual(len(self.ln.pays_for_fp(fp)), 1)
        self.assertFalse(os.path.exists(self.proof_file(fp)))
        r.kill9()
        # Restart: redeem-only recovery from the sidecar.
        r.start()
        self.wait_until(lambda: os.path.exists(self.proof_file(fp)),
                        timeout=30, what="proof after redeem-only recovery")
        self.assertEqual(len(self.ln.pays_for_fp(fp)), 1,
                         "restart paid a second time")
        self.assertEqual(self.gw.challenges_for(fp), 1,
                         "restart re-challenged instead of redeeming")
        self.assertFalse(os.path.exists(self.debt_file(fp)))
        self.assertFalse(os.path.exists(self.sidecar_file(fp)))
        self.assertIn("bought fp=" + fp, self.read_service_log())


if __name__ == "__main__":
    unittest.main(verbosity=2)
