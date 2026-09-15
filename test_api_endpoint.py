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

INFLIGHT > 1 (several gateway submissions in the air at once) is pinned by
TestInflight against FreeDoorGateway, a stub that measures how many
submissions it holds per fingerprint and in total.
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
OTHER_DIGEST = hashlib.sha256(b"someone else's record").hexdigest()


# The detached-proof header the ots client writes: magic, version 1, the
# sha256 file-hash op (0x08), then the 32-byte digest — proof_digest reads it.
OTS_HEAD = api_endpoint.OTS_MAGIC + b"\x01\x08"


def _varbytes(b):
    return api_endpoint.varuint(len(b)) + b


def pending_ots(fp):
    """A complete pending proof: the digest attested by a calendar URI.
    (Before 2026-09-15 this was a bare tag followed by text, which the
    header check accepted; the adapter now deserialises the whole proof.)"""
    b = OTS_HEAD + bytes.fromhex(fp) + CAL_TAG + _varbytes(_varbytes(b"http://fake-calendar/"))
    assert api_endpoint.BITCOIN_ATTESTATION not in b
    assert api_endpoint.inspect_proof(b, fp) == (api_endpoint.PENDING, "pending")
    return b


def anchored_ots(fp):
    """A complete proof with a Bitcoin block-header attestation (height 2)."""
    b = OTS_HEAD + bytes.fromhex(fp) + api_endpoint.BITCOIN_ATTESTATION + b"\x01\x02"
    assert api_endpoint.inspect_proof(b, fp) == (api_endpoint.BITCOIN_ATTESTATION_PRESENT, "bitcoin")
    return b


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
    invoice yields the same preimage (a settled invoice settles once) —
    and the invoice's payment hash, which /decodeinvoice reports, is the
    sha256 of that preimage, as on a real wallet. GET
    /payments/outgoingbyhash/{hash} answers as phoenixd 0.8.0 does: the
    settled record (isPaid true, preimage) for an invoice this wallet paid,
    a completed unpaid record for one it refused, 204 for one it never
    saw; lookup_down makes it answer 500 instead.
    Payments fail while their fingerprint is in fail_pay_fps; fail_next_pays
    fails the next N payments whatever the invoice, then settles."""

    def __init__(self):
        self.lock = threading.Lock()
        self.decode_calls = []
        self.pay_calls = []
        self.fail_pay_fps = set()
        self.fail_next_pays = 0
        self.auth_failures = 0
        self.pay_delay = 0.0        # hold each payment open, so overlap would show
        self.inflight_pays = 0
        self.max_inflight_pays = 0  # the most payments ever open at once
        self.settled = {}           # payment hash -> preimage
        self.refused = set()        # payment hashes of failed attempts
        self.lookups = []
        self.lookup_down = False
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

            def do_GET(self):
                if self.headers.get("Authorization") != EXPECTED_AUTH:
                    with outer.lock:
                        outer.auth_failures += 1
                    self._json(401, {"error": "bad auth"})
                    return
                prefix = "/payments/outgoingbyhash/"
                if self.path.startswith(prefix):
                    h = self.path[len(prefix):]
                    with outer.lock:
                        outer.lookups.append(h)
                        if outer.lookup_down:
                            self._json(500, {"error": "injected"})
                        elif h in outer.settled:
                            self._json(200, {"paymentHash": h, "preimage": outer.settled[h],
                                             "isPaid": True, "completedAt": 1})
                        elif h in outer.refused:
                            self._json(200, {"paymentHash": h, "preimage": None,
                                             "isPaid": False, "completedAt": 1})
                        else:
                            self.send_response(204)
                            self.send_header("Content-Length", "0")
                            self.end_headers()
                    return
                self._json(404, {})

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
                        self._json(200, {"amountSat": int(parts[1]),
                                         "paymentHash": FakeLightning.payment_hash(invoice)})
                    else:
                        self._json(200, {"unparseable": True})
                    return
                if self.path == "/payinvoice":
                    with outer.lock:
                        outer.pay_calls.append(invoice)
                        outer.inflight_pays += 1
                        outer.max_inflight_pays = max(outer.max_inflight_pays,
                                                      outer.inflight_pays)
                        fail = any(fp in invoice for fp in outer.fail_pay_fps)
                        if not fail and outer.fail_next_pays > 0:
                            outer.fail_next_pays -= 1
                            fail = True
                    if outer.pay_delay:
                        time.sleep(outer.pay_delay)
                    with outer.lock:
                        outer.inflight_pays -= 1
                    if fail:
                        with outer.lock:
                            outer.refused.add(FakeLightning.payment_hash(invoice))
                        self._json(200, {"reason": "payment failed"})
                    else:
                        with outer.lock:
                            outer.settled[FakeLightning.payment_hash(invoice)] = FakeLightning.preimage(invoice)
                        self._json(200, {"paymentPreimage": FakeLightning.preimage(invoice)})
                    return
                self._json(404, {})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @staticmethod
    def preimage(invoice):
        return hashlib.sha256(invoice.encode()).hexdigest()

    @staticmethod
    def payment_hash(invoice):
        return hashlib.sha256(bytes.fromhex(FakeLightning.preimage(invoice))).hexdigest()

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
        # /upgrade throttle, the real gateway's shape: after upgrade_limit
        # anonymous upgrades the answer is 429 + Retry-After, unless the
        # request carries "Bearer <upgrade_token>" (the D4 exemption).
        self.upgrade_limit = None
        self.upgrade_token = None
        self.upgrade_auth_seen = []
        # A buggy or hostile gateway: every proof it hands back (free door,
        # redeem, upgrade) is a well-formed proof of SOMEONE ELSE's digest.
        self.wrong_digest = False
        # When set, every redeem answers this status with an empty body.
        self.redeem_status_override = None
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
                    outer._upgrade(self, digest, body, self.headers.get("Authorization"))
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
        if self.redeem_status_override is not None:
            h._json(self.redeem_status_override, {"detail": "not now"})
            return
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
        if self.redeem_status_override is not None:
            # Set while this redeem stalled (the J9 tests): refuse now.
            h._json(self.redeem_status_override, {"detail": "not now"})
            return
        h._raw(200, pending_ots(OTHER_DIGEST if self.wrong_digest else fp),
               {"Content-Type": "application/octet-stream"})

    def _upgrade(self, h, digest, body, auth=None):
        try:
            ots = base64.b64decode(body.get("ots") or "", validate=True)
        except ValueError:
            h._json(200, {"status": "invalid", "bitcoin_anchored": False,
                          "ots": None})
            return
        with self.lock:
            self.upgrade_auth_seen.append(auth)
            exempt = self.upgrade_token is not None and auth == f"Bearer {self.upgrade_token}"
            anonymous = sum(1 for a in self.upgrade_auth_seen
                            if not (self.upgrade_token is not None and a == f"Bearer {self.upgrade_token}"))
            if self.upgrade_limit is not None and not exempt and anonymous > self.upgrade_limit:
                h._json(429, {"detail": "slow down"}, {"Retry-After": "1"})
                return
            self.upgrade_calls.append(digest)
            anchor = digest in self.anchor_now
        if anchor:
            nb = anchored_ots(OTHER_DIGEST if self.wrong_digest else digest)
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


class FreeDoorGateway(FakeGateway):
    """The gateway's free door (L402_ENABLED=false): /timestamp answers
    200 + a pending proof, no challenge. Knobs, each read under the lock per
    request: challenge_delay holds every answer open so several can be in
    the air together; free_left counts down free answers (None = free
    forever), after which the door is FakeGateway's paid one (402 +
    challenge); rate_limit answers 429 with Retry-After; fail_first[fp] = n
    answers 500 to fp's first n submissions. It measures what the service
    may never do: the most submissions ever open for one fingerprint, and
    the most open in total — so a test can pin once-per-fingerprint while
    proving the concurrency was real."""

    def __init__(self):
        super().__init__()
        self.challenge_delay = 0.0
        self.free_left = None
        self.rate_limit = False
        self.retry_after = 2
        self.fail_first = {}
        self.inflight_fp = {}
        self.max_inflight_fp = 0
        self.inflight_total = 0
        self.max_inflight_total = 0

    def _challenge(self, h, digest):
        with self.lock:
            self.inflight_fp[digest] = self.inflight_fp.get(digest, 0) + 1
            self.max_inflight_fp = max(self.max_inflight_fp, self.inflight_fp[digest])
            self.inflight_total += 1
            self.max_inflight_total = max(self.max_inflight_total, self.inflight_total)
        try:
            if self.challenge_delay:
                time.sleep(self.challenge_delay)
            with self.lock:
                if self.fail_first.get(digest, 0) > 0:
                    self.fail_first[digest] -= 1
                    mode = "fail"
                elif self.rate_limit:
                    mode = "limited"
                elif self.free_left is None or self.free_left > 0:
                    if self.free_left is not None:
                        self.free_left -= 1
                    mode = "free"
                else:
                    mode = "paid"
                if mode != "paid":
                    self.challenges.append(digest)
            if mode == "paid":
                super()._challenge(h, digest)  # records the challenge itself
            elif mode == "free":
                h._raw(200, pending_ots(OTHER_DIGEST if self.wrong_digest else digest),
                       {"Content-Type": "application/octet-stream"})
            elif mode == "limited":
                h._json(429, {"detail": "slow down"},
                        {"Retry-After": str(self.retry_after)})
            else:
                h._json(500, {"detail": "transient"})
        finally:
            with self.lock:
                self.inflight_fp[digest] -= 1
                self.inflight_total -= 1


# fake calendar (the appliance shape's counterpart to FakeGateway)
CAL_PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")
CAL_BITCOIN_TAG = bytes.fromhex("0588960d73d71901")
CAL_NONCE = b"\x11" * 16
CAL_IDX = b"\x65\x53\xf1\x00"          # a 4-byte big-endian unix second
CAL_MAC = b"\x22" * 8
CAL_SIBLING = b"\x33" * 32
CAL_URI = "http://127.0.0.1:14788/"


def cal_vu(n):
    """Independent varuint encoder so the service's is checked, not echoed."""
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def cal_vb(b):
    return cal_vu(len(b)) + b


def cal_pending_response(digest):
    """What the fork's calendar answers to POST /digest: append nonce,
    sha256, prepend the second, append the mac, then a pending attestation
    naming the calendar uri. Returns (bytes, commitment)."""
    commitment = CAL_IDX + hashlib.sha256(digest + CAL_NONCE).digest() + CAL_MAC
    body = (b"\xf0" + cal_vb(CAL_NONCE) + b"\x08" + b"\xf1" + cal_vb(CAL_IDX)
            + b"\xf0" + cal_vb(CAL_MAC)
            + b"\x00" + CAL_PENDING_TAG + cal_vb(cal_vb(CAL_URI.encode())))
    return body, commitment


def cal_bitcoin_response(height):
    """What GET /timestamp/<commitment> answers once the anchor is deep."""
    return (b"\xf0" + cal_vb(CAL_SIBLING) + b"\x08"
            + b"\x00" + CAL_BITCOIN_TAG + cal_vb(cal_vu(height)))


class FakeCalendar:
    """Speaks the fork's calendar protocol (otsserver/rpc.py): POST /digest
    and POST /operator/digest take raw digest bytes and answer the serialized
    pending timestamp; GET /timestamp/<hex> answers 404 while pending and the
    Bitcoin path once mined. It records every path served and every body it
    received, and measures how many submissions it holds in the air per
    digest and in total, so a test can pin once-per-fingerprint while proving
    the concurrency was real. Knobs: mined_height; answer (None, 402, 503 or
    "garbage"); delay (seconds each POST is held open)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.paths = []
        self.received = []
        self.known = set()
        self.mined_height = None
        self.answer = None
        self.delay = 0.0
        self.gets = 0
        self.get_paths = []
        self.inflight = {}
        self.max_inflight_fp = 0
        self.inflight_total = 0
        self.max_inflight_total = 0
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

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                digest = self.rfile.read(n)
                with outer.lock:
                    outer.paths.append(self.path)
                    outer.received.append(digest)
                    outer.inflight[digest] = outer.inflight.get(digest, 0) + 1
                    outer.max_inflight_fp = max(outer.max_inflight_fp, outer.inflight[digest])
                    outer.inflight_total += 1
                    outer.max_inflight_total = max(outer.max_inflight_total,
                                                   outer.inflight_total)
                    answer = outer.answer
                try:
                    if outer.delay:
                        time.sleep(outer.delay)
                    if self.path not in ("/digest", "/operator/digest"):
                        self._raw(404, b"not found", {"Content-Type": "text/plain"})
                        return
                    if answer == 402:
                        # A misconfigured CALENDAR_URL pointing at a gateway.
                        self._raw(402, b'{"detail": "payment required"}',
                                  {"WWW-Authenticate":
                                   'L402 macaroon="tok", invoice="lnfake:21:x:1"'})
                        return
                    if answer == 503:
                        self._raw(503, b"aggregator unavailable",
                                  {"Content-Type": "text/plain", "Retry-After": "5"})
                        return
                    if answer == "garbage":
                        self._raw(200, b"<html>not a timestamp</html>",
                                  {"Content-Type": "text/html"})
                        return
                    body, commitment = cal_pending_response(digest)
                    with outer.lock:
                        outer.known.add(commitment)
                    self._raw(200, body, {"Content-Type": "application/octet-stream"})
                finally:
                    with outer.lock:
                        outer.inflight[digest] -= 1
                        outer.inflight_total -= 1

            def do_GET(self):
                with outer.lock:
                    outer.gets += 1
                    outer.get_paths.append(self.path)
                    mined = outer.mined_height
                if not self.path.startswith("/timestamp/"):
                    self._raw(404, b"not found", {"Content-Type": "text/plain"})
                    return
                try:
                    commitment = bytes.fromhex(self.path[len("/timestamp/"):])
                except ValueError:
                    self._raw(400, b"commitment must be hex-encoded bytes",
                              {"Content-Type": "text/plain"})
                    return
                with outer.lock:
                    known = commitment in outer.known
                if not known:
                    self._raw(404, b"Not found", {"Content-Type": "text/plain"})
                    return
                if mined is None:
                    self._raw(404, b"Pending confirmation in Bitcoin blockchain",
                              {"Content-Type": "text/plain"})
                    return
                self._raw(200, cal_bitcoin_response(mined),
                          {"Content-Type": "application/octet-stream"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()


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
        self.assertTrue(api_endpoint.bitcoin_attestation_present(anchored),
                        "real anchored proof not detected as anchored")
        self.assertTrue(api_endpoint.looks_like_ots(pending))
        self.assertFalse(api_endpoint.bitcoin_attestation_present(pending),
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
        # Heal: the STORED invoice is retried — no fresh challenge. The
        # wallet is asked first and reports the attempt failed, so the retry
        # is a second payinvoice call and reserves again: the budget counts
        # calls, not invoices (2026-09-15 review, A7).
        challenges_before = self.gw.challenges_for(fp)
        self.ln.fail_pay_fps.discard(fp)
        self.wait_until(lambda: os.path.exists(self.proof_file(fp)),
                        what="proof after payment heals")
        self.assertEqual(self.gw.challenges_for(fp), challenges_before)
        self.assertEqual(len(self.ln.distinct_paid_invoices_for_fp(fp)), 1)
        self.assertIn(FakeLightning.payment_hash(self.ln.pays_for_fp(fp)[0]), self.ln.lookups)
        day, spent = api_endpoint.read_ledger(self.data("ledger"))
        self.assertEqual(spent, 20)

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


# D5 (2026-09-08): a proof is only ever stored if it is a proof OF the
# fingerprint this box asked about. The review's E-A1 shape: a gateway that
# answers with a well-formed proof of somebody else's digest.
class TestWrongDigestRefused(IntegrationBase):
    def test_proof_digest_reads_the_real_fixtures(self):
        with open(ANCHORED_REAL, "rb") as f:
            anchored = f.read()
        with open(PENDING_REAL, "rb") as f:
            pending = f.read()
        self.assertEqual(api_endpoint.proof_digest(anchored),
                         "e7783786ddd776a96d7dbc2fcc628b38c0e9fd758fb5c9be08d162a1a79c96e5")
        self.assertEqual(len(api_endpoint.proof_digest(pending) or ""), 64)
        self.assertIsNone(api_endpoint.proof_digest(api_endpoint.OTS_MAGIC + b"\x01\x08short"))
        self.assertIsNone(api_endpoint.proof_digest(b"not a proof at all"))

    def test_free_door_wrong_digest_refused_then_bought(self):
        self.gw.shutdown()
        self.gw = FreeDoorGateway()
        self.gw.wrong_digest = True
        r = self.start_service()
        body = b"my record, somebody else's proof"
        fp = hashlib.sha256(body).hexdigest()
        self.assertEqual(post_record(r, body)[0], 200)
        self.wait_until(lambda: "proof_wrong_digest fp=" + fp in self.read_service_log(),
                        what="refusal logged")
        time.sleep(0.3)
        self.assertFalse(os.path.exists(self.proof_file(fp)), "a proof of another digest was stored")
        self.assertTrue(os.path.exists(self.debt_file(fp)), "the debt was dropped")
        self.assertNotIn(fp, os.listdir(self.data("pending")))
        # The gateway recovers: the next answer is a proof of fp and is stored.
        self.gw.wrong_digest = False
        self.wait_until(lambda: os.path.exists(self.proof_file(fp)), what="proof after recovery")
        with open(self.proof_file(fp), "rb") as f:
            self.assertEqual(api_endpoint.proof_digest(f.read()), fp)
        self.assertFalse(os.path.exists(self.debt_file(fp)))

    def test_paid_redeem_wrong_digest_refused(self):
        self.gw.wrong_digest = True
        r = self.start_service()
        body = b"paid for, wrong proof back"
        fp = hashlib.sha256(body).hexdigest()
        self.assertEqual(post_record(r, body)[0], 200)
        self.wait_until(lambda: "proof_wrong_digest fp=" + fp in self.read_service_log(),
                        what="refusal logged")
        time.sleep(0.3)
        self.assertFalse(os.path.exists(self.proof_file(fp)))
        # Paid once; the sidecar keeps the preimage for the retry (redeem-only, never pay again).
        self.assertEqual(len(self.ln.pays_for_fp(fp)), 1)
        with open(self.sidecar_file(fp)) as f:
            self.assertIn("preimage", json.load(f))
        self.gw.wrong_digest = False
        self.wait_until(lambda: os.path.exists(self.proof_file(fp)), what="proof after recovery")
        self.assertEqual(len(self.ln.pays_for_fp(fp)), 1)

    def test_upgrade_wrong_digest_refused_keeps_pending(self):
        r = self.start_service(UPGRADE_SECS="0.2")
        body = b"to be upgraded wrongly"
        fp = hashlib.sha256(body).hexdigest()
        self.assertEqual(post_record(r, body)[0], 200)
        self.wait_until(lambda: os.path.exists(self.proof_file(fp)), what="proof")
        self.gw.wrong_digest = True
        self.gw.anchor_now.add(fp)
        self.wait_until(lambda: "proof_wrong_digest fp=" + fp in self.read_service_log(),
                        what="refusal logged")
        with open(self.proof_file(fp), "rb") as f:
            self.assertEqual(f.read(), pending_ots(fp))   # untouched
        self.assertIn(fp, os.listdir(self.data("pending")))
        self.gw.wrong_digest = False
        self.wait_until(lambda: api_endpoint.bitcoin_attestation_present(open(self.proof_file(fp), "rb").read()),
                        what="anchored after recovery")
        with open(self.proof_file(fp), "rb") as f:
            self.assertEqual(api_endpoint.proof_digest(f.read()), fp)


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
                return api_endpoint.bitcoin_attestation_present(f.read())

        self.wait_until(proof_is_anchored, what="proof anchored on disk")
        with open(self.proof_file(fp), "rb") as f:
            self.assertEqual(f.read(), anchored_ots(fp))
        self.assertIn("bitcoin_attestation_present fp=" + fp, self.read_service_log())
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


class TestRedeemCeiling(IntegrationBase):
    """J9 (2026-09-08): a paid preimage the gateway keeps refusing (an L402
    secret rotation makes every stored macaroon a 401) is retried every pass
    up to REDEEM_ATTEMPTS_MAX times, then marked needs-attention in its
    sidecar and the heartbeat, logged once, and retried once per
    REDEEM_ATTENTION_RETRY_SECS. Never dropped, never re-paid."""

    def _paid_then_refused(self, **over):
        r = self.start_service(REDEEM_ATTEMPTS_MAX=3, **over)
        body = b"paid, then the gateway forgets the token"
        fp = hashlib.sha256(body).hexdigest()
        ev = self.gw.stall_next_redeem(fp, secs=3.0)
        self.assertEqual(post_record(r, body)[0], 200)
        self.assertTrue(ev.wait(20), "redeem never started")
        # The rotation: from here every redeem of the stored token is a 401.
        self.gw.redeem_status_override = 401
        return r, fp

    def test_ceiling_marks_attention_once_and_keeps_the_preimage(self):
        r, fp = self._paid_then_refused()
        self.wait_until(lambda: "redeem_needs_attention fp=" + fp in self.read_service_log(),
                        timeout=30, what="needs-attention event")
        time.sleep(0.5)   # a few more passes: nothing else may be logged for it
        log = self.read_service_log()
        self.assertEqual(log.count("redeem_needs_attention fp=" + fp), 1)
        self.assertLessEqual(log.count("redeem_failed fp=" + fp), 3)
        with open(self.sidecar_file(fp)) as f:
            sc = json.load(f)
        self.assertIn("preimage", sc)
        self.assertEqual(sc["attempts"], 3)
        self.assertIn("attention", sc)
        self.assertTrue(os.path.exists(self.debt_file(fp)), "the debt stays owed")
        self.assertEqual(len(self.ln.pays_for_fp(fp)), 1, "never re-paid")
        self.assertEqual(self.gw.challenges_for(fp), 1, "never re-challenged")
        self.wait_until(lambda: "attention=1" in open(self.data("heartbeat")).read(),
                        timeout=10, what="heartbeat attention count")

    def test_at_the_ceiling_the_retry_is_slow_and_a_fixed_gateway_heals_it(self):
        r, fp = self._paid_then_refused(REDEEM_ATTENTION_RETRY_SECS=1)
        self.wait_until(lambda: "redeem_needs_attention fp=" + fp in self.read_service_log(),
                        timeout=30, what="needs-attention event")
        redeems_at_mark = len(self.gw.redeems)
        time.sleep(0.6)
        # Retried once per second now, not every 50 ms pass: at most one more.
        self.assertLessEqual(len([x for x in self.gw.redeems if x == fp]) - redeems_at_mark, 1)
        # The gateway accepts the token again (the rotation is reverted):
        # the next slow retry redeems, the proof lands, attention clears.
        self.gw.redeem_status_override = None
        self.wait_until(lambda: os.path.exists(self.proof_file(fp)), timeout=30,
                        what="proof after the gateway recovered")
        self.assertFalse(os.path.exists(self.sidecar_file(fp)))
        self.assertEqual(len(self.ln.pays_for_fp(fp)), 1)
        self.wait_until(lambda: "attention=0" in open(self.data("heartbeat")).read(),
                        timeout=10, what="heartbeat attention cleared")

    def test_503_counts_nothing(self):
        r = self.start_service(REDEEM_ATTEMPTS_MAX=2)
        body = b"gateway says not now"
        fp = hashlib.sha256(body).hexdigest()
        self.gw.redeem_status_override = 503
        self.assertEqual(post_record(r, body)[0], 200)
        self.wait_until(lambda: self.read_service_log().count("redeem_failed fp=" + fp) >= 3,
                        timeout=30, what="several 503 refusals")
        self.assertNotIn("redeem_needs_attention", self.read_service_log())
        with open(self.sidecar_file(fp)) as f:
            self.assertNotIn("attempts", json.load(f))


# D4 (2026-09-08): the client's proofs must finish. The upgrader works from an
# on-disk pending index (DATA_DIR/pending/<fp>, a marker written before the
# proof and removed once the proof is anchored) instead of re-reading every
# proof file each pass, presents GATEWAY_UPGRADE_TOKEN so the gateway lifts
# its per-peer /upgrade throttle, and keeps UPGRADE_INFLIGHT calls in the air.
class TestUpgradeBacklog(IntegrationBase):
    def seed_pending_proofs(self, n, label, anchored=0):
        os.makedirs(self.data("proofs"), exist_ok=True)
        fps = []
        for i in range(n):
            fp = hashlib.sha256(f"{label} {i}".encode()).hexdigest()
            api_endpoint.atomic_write(self.proof_file(fp), pending_ots(fp))
            fps.append(fp)
        done = []
        for i in range(anchored):
            fp = hashlib.sha256(f"{label} anchored {i}".encode()).hexdigest()
            api_endpoint.atomic_write(self.proof_file(fp), anchored_ots(fp))
            done.append(fp)
        return fps, done

    def pending_index(self):
        """The markers (fingerprints) in DATA_DIR/pending, None when the
        directory does not exist yet; the .built flag is not a marker."""
        try:
            return sorted(n for n in os.listdir(self.data("pending"))
                          if api_endpoint.HEX64.fullmatch(n))
        except OSError:
            return None

    def test_upgrade_backlog_finishes_with_the_client_token(self):
        """The review's D4 shape: a gateway that throttles anonymous /upgrade
        to 5 per pass, 40 pending proofs on disk. With the token every
        proof is anchored in one pass; the anonymous budget is untouched."""
        fps, _ = self.seed_pending_proofs(40, "backlog")
        self.gw.upgrade_limit = 5
        self.gw.upgrade_token = "upgrade-tok"
        self.gw.anchor_now.update(fps)
        self.start_service(UPGRADE_SECS="0.2", GATEWAY_UPGRADE_TOKEN="upgrade-tok",
                           UPGRADE_INFLIGHT="8")
        self.wait_until(lambda: all(api_endpoint.bitcoin_attestation_present(open(self.proof_file(fp), "rb").read())
                                    for fp in fps), timeout=30, what="every pending proof anchored")
        self.assertEqual(self.pending_index(), [])
        log = self.read_service_log()
        self.assertNotIn("upgrade_rate_limited", log)
        self.assertEqual(log.count(" bitcoin_attestation_present fp="), 40)
        self.assertTrue(all(a == "Bearer upgrade-tok" for a in self.gw.upgrade_auth_seen))
        # Anchored proofs are never polled again: one call per fingerprint.
        time.sleep(0.6)
        self.assertEqual(sorted(self.gw.upgrade_calls), sorted(fps))

    def test_upgrade_without_token_is_still_throttled(self):
        """Control for the pin above: the same backlog without the token
        converts only what the anonymous budget allows per pass."""
        fps, _ = self.seed_pending_proofs(40, "throttled")
        self.gw.upgrade_limit = 5
        self.gw.upgrade_token = "upgrade-tok"
        self.gw.anchor_now.update(fps)
        self.start_service(UPGRADE_SECS="0.3")
        self.wait_until(lambda: "upgrade_rate_limited" in self.read_service_log(),
                        what="rate_limited logged")
        time.sleep(0.5)
        anchored = sum(api_endpoint.bitcoin_attestation_present(open(self.proof_file(fp), "rb").read()) for fp in fps)
        self.assertLessEqual(anchored, 5)
        self.assertGreaterEqual(len(self.pending_index()), 35)

    def test_pending_index_marker_before_proof_and_cleared_on_anchor(self):
        r = self.start_service(UPGRADE_SECS="0.2")
        body = b"indexed record"
        fp = hashlib.sha256(body).hexdigest()
        self.assertEqual(post_record(r, body)[0], 200)
        self.wait_until(lambda: os.path.exists(self.proof_file(fp)), what="proof")
        self.assertIn(fp, self.pending_index())
        self.gw.anchor_now.add(fp)
        self.wait_until(lambda: api_endpoint.bitcoin_attestation_present(open(self.proof_file(fp), "rb").read()),
                        what="anchored on disk")
        self.wait_until(lambda: fp not in self.pending_index(), what="marker cleared")
        n = self.gw.upgrades_for(fp)
        time.sleep(0.6)
        self.assertEqual(self.gw.upgrades_for(fp), n)

    def test_pending_index_built_once_from_the_proofs_dir(self):
        """A DATA_DIR from before the index (proofs, no pending/): startup
        scans the proofs directory once, marks only the pending ones, and
        never touches the anchored ones."""
        pending, anchored = self.seed_pending_proofs(3, "migrate", anchored=2)
        self.assertIsNone(self.pending_index())
        self.start_service(UPGRADE_SECS="3600")
        self.wait_until(lambda: "pending_index_built" in self.read_service_log(),
                        what="index built at startup")
        self.assertEqual(self.pending_index(), sorted(pending))
        self.assertIn("pending_index_built pending=3 scanned=5", self.read_service_log())
        # The same first pass then polls exactly the pending three, once
        # each; the anchored two are never sent to the gateway.
        self.wait_until(lambda: len(self.gw.upgrade_calls) >= 3, what="first pass polled the index")
        time.sleep(0.3)
        self.assertEqual(sorted(self.gw.upgrade_calls), sorted(pending))
        self.assertEqual(self.pending_index(), sorted(pending))  # still pending, still indexed

    def test_upgrade_inflight_knob(self):
        d = tempfile.mkdtemp(prefix="upg-cfg-")
        self.addCleanup(shutil.rmtree, d, True)
        base = {"LISTEN_ADDR": "127.0.0.1:8402", "GATEWAY_URL": "http://x"}
        cfg = api_endpoint.resolve_config(dict(base, INFLIGHT="6"), script_dir=d)
        self.assertEqual(cfg["upgrade_inflight"], 6)      # defaults to INFLIGHT
        self.assertEqual(api_endpoint.resolve_config(dict(base, UPGRADE_INFLIGHT="3"), script_dir=d)["upgrade_inflight"], 3)
        self.assertIsNone(api_endpoint.resolve_config(base, script_dir=d)["gateway_upgrade_token"])
        self.assertEqual(api_endpoint.resolve_config(dict(base, GATEWAY_UPGRADE_TOKEN="t"), script_dir=d)["gateway_upgrade_token"], "t")
        for bad in ("0", "-1", "x"):
            with self.assertRaises(api_endpoint.ConfigError):
                api_endpoint.resolve_config(dict(base, UPGRADE_INFLIGHT=bad), script_dir=d)


# INFLIGHT: several gateway submissions in the air at once
class TestInflightConfig(unittest.TestCase):
    def test_inflight_knob_strict_positive_int_default_one(self):
        d = tempfile.mkdtemp(prefix="inflight-cfg-")
        self.addCleanup(shutil.rmtree, d, True)
        base = {"LISTEN_ADDR": "127.0.0.1:8402", "GATEWAY_URL": "http://x"}
        self.assertEqual(api_endpoint.resolve_config(base, script_dir=d)["inflight"], 1)
        self.assertEqual(api_endpoint.resolve_config(dict(base, INFLIGHT="8"),
                                                     script_dir=d)["inflight"], 8)
        self.assertEqual(api_endpoint.resolve_config(dict(base, INFLIGHT=""),
                                                     script_dir=d)["inflight"], 1)
        for bad in ("0", "-1", "1.5", "eight", "+2", " 2"):
            with self.assertRaises(api_endpoint.ConfigError, msg=repr(bad)) as cm:
                api_endpoint.resolve_config(dict(base, INFLIGHT=bad), script_dir=d)
            self.assertIn("INFLIGHT", str(cm.exception))


class TestInflight(IntegrationBase):
    """Every test here runs the service at INFLIGHT=8 against FreeDoorGateway
    and asserts, besides its own claim, that submissions really did overlap
    (max_inflight_total >= 2) — otherwise the pin would be vacuous."""

    def setUp(self):
        super().setUp()
        self.gw.shutdown()
        self.gw = FreeDoorGateway()

    def seed_debts(self, n, label):
        """n debts on disk before the service starts, mtimes one second
        apart in the past, so the buyer's oldest-first order is exactly the
        returned list and the first pass sees all of them at once."""
        os.makedirs(self.data("debts"), exist_ok=True)
        fps = []
        base = time.time() - 1000
        for i in range(n):
            fp = hashlib.sha256(f"{label} {i}".encode()).hexdigest()
            with open(self.debt_file(fp), "w") as f:
                f.write(fp + "\n")
            os.utime(self.debt_file(fp), (base + i, base + i))
            fps.append(fp)
        return fps

    def debts_on_disk(self):
        try:
            return sorted(n for n in os.listdir(self.data("debts"))
                          if api_endpoint.HEX64.fullmatch(n))
        except OSError:
            return []

    def test_inflight_sigkill_mid_flight_converges_one_proof_each(self):
        """kill -9 with eight submissions in the air; after restart every
        acknowledged record has exactly one proof, no debt survives, and a
        proof-written-debt-uncleared straggler is absorbed by already_bought
        without another submission."""
        self.gw.challenge_delay = 0.15
        r = self.start_service(INFLIGHT="8")
        acked = []
        stop = threading.Event()

        def blaster():
            for i in range(60):
                if stop.is_set():
                    return
                try:
                    code, text = post_record(r, f"inflight burst {i}".encode())
                except Exception:
                    return
                if code != 200:
                    return
                acked.append(text.split()[1])

        t = threading.Thread(target=blaster)
        t.start()
        self.wait_until(
            lambda: len(acked) >= 12 and self.gw.inflight_total >= 2 and
            any(n.endswith(".ots") for n in os.listdir(self.data("proofs"))),
            timeout=30, what="mid-flight state (some bought, several in the air)")
        r.kill9()
        stop.set()
        t.join(timeout=15)
        snapshot = list(acked)
        self.assertGreaterEqual(len(snapshot), 12)
        self.assertGreaterEqual(self.gw.max_inflight_total, 2, "never concurrent")
        self.assertEqual(self.gw.max_inflight_fp, 1)
        for fp in snapshot:
            self.assertTrue(os.path.exists(self.debt_file(fp))
                            or os.path.exists(self.proof_file(fp)),
                            f"acked {fp} vanished at kill")
        owed = [fp for fp in snapshot if os.path.exists(self.debt_file(fp))]
        self.assertTrue(owed, "kill landed after everything was bought; vacuous")
        # The submissions that were in the air at the kill still finish at
        # the stub (their sockets are dead); let them land before counting.
        self.wait_until(lambda: self.gw.inflight_total == 0,
                        what="stub drained after the kill")
        # The straggler the kill cannot be made to produce on demand: proof
        # on disk, debt still there. Manufacture one from the youngest owed
        # record, which the killed process never submitted.
        straggler = owed[-1]
        self.assertFalse(os.path.exists(self.proof_file(straggler)))
        api_endpoint.atomic_write(self.proof_file(straggler), pending_ots(straggler))
        straggler_challenges = self.gw.challenges_for(straggler)
        self.assertEqual(straggler_challenges, 0)
        # Restart on the same disk.
        self.gw.challenge_delay = 0.0
        r.start()
        self.wait_until(lambda: not self.debts_on_disk(), timeout=45,
                        what="every debt settled after restart")
        log = self.read_service_log()
        for fp in snapshot:
            self.assertFalse(os.path.exists(self.debt_file(fp)))
            self.assertFalse(os.path.exists(self.sidecar_file(fp)))
            with open(self.proof_file(fp), "rb") as f:
                self.assertEqual(f.read(), pending_ots(fp))
            self.assertLessEqual(log.count(f"proof_free fp={fp}"), 1,
                                 f"{fp} bought more than once")
        self.assertIn(f"already_bought fp={straggler}", log)
        self.assertEqual(self.gw.challenges_for(straggler), straggler_challenges,
                         "the straggler was submitted again instead of absorbed")
        self.assertEqual(self.gw.max_inflight_fp, 1)
        # A free door costs nothing: no payment, no reservation.
        self.assertEqual(len(self.ln.pay_calls), 0)
        self.assertFalse(os.path.exists(self.data("ledger")))

    def test_inflight_fingerprint_in_flight_at_most_once(self):
        """No fingerprint is ever submitted twice at the same time — within
        a pass, across passes (a debt whose submission failed is re-submitted
        only after the earlier one has answered), and under a duplicate POST."""
        self.gw.challenge_delay = 0.1
        fps = self.seed_debts(24, "once")
        flaky = fps[3]
        self.gw.fail_first[flaky] = 3  # 500 three times: owed again each pass
        r = self.start_service(INFLIGHT="8")
        # A duplicate POST of an owed record while the buyer works: one debt.
        self.assertEqual(post_record(r, b"once 3")[0], 200)
        self.wait_until(lambda: not self.debts_on_disk(), timeout=30,
                        what="every debt settled")
        self.assertGreaterEqual(self.gw.max_inflight_total, 2, "never concurrent")
        self.assertEqual(self.gw.max_inflight_fp, 1,
                         "a fingerprint was in flight twice at once")
        for fp in fps:
            self.assertEqual(self.gw.challenges_for(fp), 4 if fp == flaky else 1)
            with open(self.proof_file(fp), "rb") as f:
                self.assertEqual(f.read(), pending_ots(fp))
        self.assertEqual(self.read_service_log().count(f"challenge_failed fp={flaky}"), 3)
        self.assertEqual(len(self.ln.pay_calls), 0)

    def test_inflight_door_flips_to_paid_mid_pass_goes_serial(self):
        """Twelve debts, window of eight; the stub answers the first five
        free, then 402 forever. The three 402s collected from the window and
        the four debts after it are bought serially: one challenge, one
        invoice, one reservation, one payment, one redeem per paid debt,
        payments never overlapping, oldest first."""
        self.gw.challenge_delay = 0.1
        self.gw.free_left = 5
        self.gw.price = 21
        self.ln.pay_delay = 0.05
        fps = self.seed_debts(12, "flip")
        self.start_service(INFLIGHT="8")
        self.wait_until(lambda: not self.debts_on_disk(), timeout=30,
                        what="every debt settled")
        log = self.read_service_log()
        free = [fp for fp in fps if f"proof_free fp={fp}" in log]
        paid = [fp for fp in fps if f"bought fp={fp}" in log]
        self.assertEqual(len(free), 5)
        self.assertEqual(len(paid), 7)
        self.assertEqual(set(free) | set(paid), set(fps))
        self.assertEqual(set(free) & set(paid), set())
        # The flip landed inside the first window: the free five and three
        # of the paid seven are among the eight oldest.
        self.assertTrue(all(fps.index(fp) < 8 for fp in free))
        self.assertEqual(sum(fps.index(fp) < 8 for fp in paid), 3)
        self.assertGreaterEqual(self.gw.max_inflight_total, 2, "never concurrent")
        self.assertEqual(self.gw.max_inflight_fp, 1)
        # Exactly one of everything per paid debt; nothing for the free ones.
        for fp in fps:
            self.assertEqual(self.gw.challenges_for(fp), 1,
                             "a collected 402 was submitted again")
        self.assertEqual(len(self.gw.minted), 7)
        with self.gw.lock:
            redeems = list(self.gw.redeems)
        for fp in paid:
            self.assertEqual(len(self.ln.pays_for_fp(fp)), 1)
            self.assertEqual(sum(fp in inv for inv in self.ln.decode_calls), 1)
            self.assertEqual(redeems.count(fp), 1)
        for fp in free:
            self.assertEqual(len(self.ln.pays_for_fp(fp)), 0)
            self.assertEqual(redeems.count(fp), 0)
        self.assertEqual(api_endpoint.read_ledger(self.data("ledger")),
                         (api_endpoint.utc_today(), 7 * 21))
        # Payments never concurrent; paid oldest first.
        self.assertEqual(self.ln.max_inflight_pays, 1)
        order = [inv.split(":")[2] for inv in self.ln.pay_calls]
        self.assertEqual(order, sorted(order, key=fps.index))
        self.assertEqual(redeems, order)
        self.assertNotIn("breaker_tripped", log)
        for fp in fps:
            self.assertFalse(os.path.exists(self.sidecar_file(fp)))

    def test_inflight_429_stops_new_submissions(self):
        """429 with Retry-After while eight are in the air: the answers
        already in flight land, no new submission is issued until the wait
        elapses, every debt stays, and buying resumes afterwards."""
        self.gw.challenge_delay = 0.1
        self.gw.rate_limit = True
        self.gw.retry_after = 2
        fps = self.seed_debts(30, "limited")
        self.start_service(INFLIGHT="8")
        self.wait_until(lambda: "rate_limited" in self.read_service_log(),
                        what="rate_limited logged")
        time.sleep(1.0)  # well inside Retry-After, many poll intervals
        n = len(self.gw.challenges)
        self.assertGreaterEqual(n, 1)
        self.assertLessEqual(n, 8, "submissions were issued under Retry-After")
        self.assertGreaterEqual(self.gw.max_inflight_total, 2, "never concurrent")
        self.assertEqual(self.debts_on_disk(), sorted(fps), "a debt was dropped")
        self.assertEqual(os.listdir(self.data("proofs")), [])
        self.assertEqual(len(self.ln.pay_calls), 0)
        self.assertIn("rate_limited wait_secs=2", self.read_service_log())
        # The wait elapses and the door is open again: everything is bought.
        self.gw.rate_limit = False
        self.wait_until(lambda: not self.debts_on_disk(), timeout=30,
                        what="every debt settled after the wait")
        self.assertEqual(self.gw.max_inflight_fp, 1)
        self.assertEqual(len(self.ln.pay_calls), 0)

    def test_inflight_breaker_trips_and_stops_submissions(self):
        """The paid door from the first debt, every payment refused: the
        eight 402s collected from one window are paid serially, the third
        failure trips the breaker, and no further submission or payment is
        issued while it holds."""
        self.gw.challenge_delay = 0.05
        self.gw.free_left = 0
        self.gw.price = 1
        self.ln.pay_delay = 0.05
        fps = self.seed_debts(8, "breaker")
        for fp in fps:
            self.ln.fail_pay_fps.add(fp)
        self.start_service(INFLIGHT="8", CIRCUIT_BREAKER_FAILURES="3",
                           CIRCUIT_BREAKER_PAUSE_SECS="3600")
        self.wait_until(lambda: "breaker_tripped" in self.read_service_log(),
                        what="breaker_tripped logged")
        time.sleep(0.3)  # many passes while paused
        self.assertEqual(len(self.ln.pay_calls), 3,
                         "attempts continued after the breaker tripped")
        self.assertEqual(self.ln.max_inflight_pays, 1)
        self.assertEqual(api_endpoint.read_ledger(self.data("ledger")),
                         (api_endpoint.utc_today(), 3))
        self.assertGreaterEqual(self.gw.max_inflight_total, 2, "never concurrent")
        self.assertEqual(self.gw.max_inflight_fp, 1)
        n = len(self.gw.challenges)
        self.assertEqual(n, 8, "the first window was not exactly the eight debts")
        time.sleep(0.3)
        self.assertEqual(len(self.gw.challenges), n,
                         "submissions were issued while the breaker held")
        self.assertEqual(self.debts_on_disk(), sorted(fps), "a debt was dropped")
        self.assertEqual(os.listdir(self.data("proofs")), [])
        # Oldest first, one reservation each for the three that were tried.
        order = [inv.split(":")[2] for inv in self.ln.pay_calls]
        self.assertEqual(order, fps[:3])


if __name__ == "__main__":
    unittest.main(verbosity=2)


# LOG_CAP_BYTES: the data log rotates to log.1 once it reaches the cap
class TestLogRotation(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="log-rotate-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.base = {"LISTEN_ADDR": "127.0.0.1:8402", "GATEWAY_URL": "http://x"}

    def cfg(self, cap):
        return api_endpoint.resolve_config(dict(self.base, LOG_CAP_BYTES=cap), script_dir=self.d)

    def lines(self, name):
        try:
            with open(os.path.join(self.d, name)) as f:
                return f.read().splitlines()
        except FileNotFoundError:
            return None

    def test_log_rotates_to_dot1_at_cap_and_replaces_previous(self):
        cfg = self.cfg("300")
        n = 0
        while self.lines("log.1") is None:
            n += 1
            api_endpoint.log_event(cfg, "ev", n=n)
            self.assertLess(n, 100, "no rotation within 100 lines at a 300-byte cap")
        first_gen = self.lines("log.1")
        self.assertGreaterEqual(sum(len(l) + 1 for l in first_gen), 300)
        self.assertEqual([int(l.split("n=")[1]) for l in first_gen + self.lines("log")], list(range(1, n + 1)))
        while self.lines("log.1") == first_gen:
            n += 1
            api_endpoint.log_event(cfg, "ev", n=n)
            self.assertLess(n, 200)
        second_gen = self.lines("log.1")
        self.assertEqual(int(second_gen[0].split("n=")[1]), len(first_gen) + 1)
        self.assertEqual([int(l.split("n=")[1]) for l in second_gen + self.lines("log")],
                         list(range(len(first_gen) + 1, n + 1)))

    def test_log_cap_zero_never_rotates(self):
        cfg = self.cfg("0")
        for n in range(200):
            api_endpoint.log_event(cfg, "ev", n=n, pad="x" * 60)
        self.assertIsNone(self.lines("log.1"))
        self.assertEqual(len(self.lines("log")), 200)

    def test_log_cap_knob_default_and_validation(self):
        d = self.d
        self.assertEqual(api_endpoint.resolve_config(self.base, script_dir=d)["log_cap_bytes"], 16 * 1024 * 1024)
        self.assertEqual(self.cfg("")["log_cap_bytes"], 16 * 1024 * 1024)
        for bad in ("-1", "1.5", "big", "+2"):
            with self.assertRaises(api_endpoint.ConfigError, msg=repr(bad)) as cm:
                self.cfg(bad)
            self.assertIn("LOG_CAP_BYTES", str(cm.exception))


# The appliance shape: CALENDAR_URL instead of GATEWAY_URL. The service
# submits each fingerprint to the calendar's counted /digest, builds the
# detached proof itself, and upgrades through GET /timestamp/<commitment>.
# No L402, no phoenixd, no ledger, no sidecar; INFLIGHT, the pending index,
# the crash paths and the wrong-digest refusal are the same code as the
# gateway shape.
class TestCalendarModeConfig(unittest.TestCase):
    def test_calendar_mode_config_exactly_one_url(self):
        base = {"LISTEN_ADDR": "127.0.0.1:8402"}
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(api_endpoint.ConfigError) as cm:
                api_endpoint.resolve_config(
                    {**base, "GATEWAY_URL": "http://x", "CALENDAR_URL": "http://y"},
                    script_dir=d)
            self.assertIn("GATEWAY_URL", str(cm.exception))
            self.assertIn("CALENDAR_URL", str(cm.exception))
            with self.assertRaises(api_endpoint.ConfigError) as cm:
                api_endpoint.resolve_config(base, script_dir=d)
            self.assertIn("GATEWAY_URL", str(cm.exception))
            self.assertIn("CALENDAR_URL", str(cm.exception))

            cal = api_endpoint.resolve_config(
                {**base, "CALENDAR_URL": "http://127.0.0.1:14788/"}, script_dir=d)
            self.assertEqual(cal["mode"], "calendar")
            self.assertEqual(cal["calendar_url"], "http://127.0.0.1:14788")
            self.assertIsNone(cal["gateway_url"])
            # The appliance defaults (ruling 2026-09-11): eight in flight, one
            # upgrade pass an hour.
            self.assertEqual(cal["inflight"], 8)
            self.assertEqual(cal["upgrade_inflight"], 8)
            self.assertEqual(cal["upgrade_secs"], 3600.0)

            gw = api_endpoint.resolve_config({**base, "GATEWAY_URL": "http://x"},
                                             script_dir=d)
            self.assertEqual(gw["mode"], "gateway")
            self.assertIsNone(gw["calendar_url"])
            self.assertEqual(gw["inflight"], 1)
            self.assertEqual(gw["upgrade_secs"], 600.0)

            explicit = api_endpoint.resolve_config(
                {**base, "CALENDAR_URL": "http://y", "INFLIGHT": "3",
                 "UPGRADE_SECS": "7"}, script_dir=d)
            self.assertEqual(explicit["inflight"], 3)
            self.assertEqual(explicit["upgrade_inflight"], 3)
            self.assertEqual(explicit["upgrade_secs"], 7.0)


class TestOtsParser(unittest.TestCase):
    def test_ots_parser_cross_checks_with_the_library(self):
        digest = hashlib.sha256(b"a record").digest()
        body, commitment = cal_pending_response(digest)
        ots = api_endpoint.build_ots(digest, body)
        self.assertEqual(ots, OTS_HEAD + digest + body)
        proof = api_endpoint.parse_ots(ots)
        self.assertEqual(proof.digest, digest)
        self.assertEqual(proof.commitment, commitment)
        self.assertEqual(proof.attestation, ("pending", CAL_URI))
        self.assertEqual(api_endpoint.proof_digest(ots), digest.hex())
        self.assertFalse(api_endpoint.bitcoin_attestation_present(ots))

        upgraded = api_endpoint.splice_upgrade(ots, cal_bitcoin_response(965446))
        up = api_endpoint.parse_ots(upgraded)
        self.assertEqual(up.digest, digest)
        self.assertEqual(up.attestation, ("bitcoin", 965446))
        self.assertTrue(api_endpoint.bitcoin_attestation_present(upgraded))
        self.assertEqual(upgraded[:proof.ops_end], ots[:proof.ops_end])

        with self.assertRaises(api_endpoint.OtsError):
            api_endpoint.parse_ots(b"not a proof")
        with self.assertRaises(api_endpoint.OtsError) as cm:
            api_endpoint.parse_ots(OTS_HEAD + digest + b"\xff" + body)
        self.assertIn("fork", str(cm.exception))
        with self.assertRaises(api_endpoint.OtsError):
            api_endpoint.splice_upgrade(upgraded, cal_bitcoin_response(1))

        try:
            from opentimestamps.core.serialize import StreamDeserializationContext
            from opentimestamps.core.timestamp import DetachedTimestampFile
            from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        except ImportError:
            self.skipTest("opentimestamps library not importable here")
        import io
        for raw in (ots, upgraded):
            detached = DetachedTimestampFile.deserialize(
                StreamDeserializationContext(io.BytesIO(raw)))
            self.assertEqual(detached.file_digest, digest)
        attestations = [a for _, a in detached.timestamp.all_attestations()]
        self.assertEqual(len(attestations), 1)
        self.assertIsInstance(attestations[0], BitcoinBlockHeaderAttestation)
        self.assertEqual(attestations[0].height, 965446)


class CalendarBase(IntegrationBase):
    def setUp(self):
        super().setUp()
        self.cal = FakeCalendar()

    def tearDown(self):
        self.cal.shutdown()
        super().tearDown()

    def make_calendar_env(self, **over):
        env = self.make_env(**over)
        env.pop("GATEWAY_URL", None)
        env["CALENDAR_URL"] = self.cal.url
        return env

    def start_calendar_service(self, **over):
        self.runner = ServiceRunner(self.tmp, self.make_calendar_env(**over))
        self.runner.start()
        return self.runner

    def pending_file(self, fp):
        return self.data("pending", fp)

    def post_and_wait(self, body, timeout=20):
        fp = hashlib.sha256(body).hexdigest()
        status, reply = post_record(self.runner, body)
        self.assertEqual((status, reply.strip()), (200, "received " + fp))
        self.wait_until(lambda: os.path.exists(self.proof_file(fp))
                        and not os.path.exists(self.debt_file(fp)),
                        timeout=timeout, what=f"proof for {fp[:12]}")
        return fp


class TestCalendarMode(CalendarBase):
    def test_calendar_mode_submits_raw_digest_to_counted_digest_path(self):
        self.start_calendar_service(INFLIGHT=1)
        body = b"record one"
        fp = self.post_and_wait(body)
        digest = bytes.fromhex(fp)
        # Every submission went to the counted door, never the operator lane,
        # and carried exactly the 32 raw digest bytes.
        self.assertEqual(self.cal.paths, ["/digest"])
        self.assertEqual(self.cal.received, [digest])
        with open(self.proof_file(fp), "rb") as f:
            data = f.read()
        self.assertEqual(data, OTS_HEAD + digest + cal_pending_response(digest)[0])
        self.assertEqual(api_endpoint.proof_digest(data), fp)
        self.assertFalse(api_endpoint.bitcoin_attestation_present(data))
        self.assertTrue(os.path.exists(self.pending_file(fp)))
        self.assertIn(f" proof_free fp={fp}", self.read_service_log())

    def test_calendar_mode_never_reads_phoenix_or_writes_ledger_or_sidecar(self):
        self.start_calendar_service(
            INFLIGHT=1, PHOENIX_CONF=os.path.join(self.tmp, "no-such-phoenix.conf"))
        fp = self.post_and_wait(b"record two")
        self.assertEqual(self.ln.decode_calls, [])
        self.assertEqual(self.ln.pay_calls, [])
        self.assertEqual(self.ln.auth_failures, 0)
        self.assertFalse(os.path.exists(self.data("ledger")))
        self.assertEqual([n for n in os.listdir(self.data("debts")) if n.endswith(".l402")], [])
        self.wait_until(lambda: os.path.exists(self.data("heartbeat")), what="heartbeat")
        with open(self.data("heartbeat")) as f:
            self.assertIn("breaker=ok", f.read())
        self.assertIn("mode=calendar", self.read_service_log())
        self.assertNotIn(fp, "")  # fp used above; keeps the name meaningful

    def test_calendar_mode_402_is_refused_without_payment(self):
        self.cal.answer = 402
        self.start_calendar_service(INFLIGHT=1)
        body = b"record three"
        fp = hashlib.sha256(body).hexdigest()
        post_record(self.runner, body)
        self.wait_until(lambda: f"challenge_failed fp={fp} status=402 note=calendar_answered_402"
                        in self.read_service_log(), what="the 402 refusal")
        self.assertTrue(os.path.exists(self.debt_file(fp)))
        self.assertFalse(os.path.exists(self.sidecar_file(fp)))
        self.assertFalse(os.path.exists(self.proof_file(fp)))
        self.assertEqual(self.ln.pay_calls, [])
        self.assertEqual(self.ln.decode_calls, [])
        self.cal.answer = None
        self.wait_until(lambda: os.path.exists(self.proof_file(fp)), what="proof after recovery")
        self.assertEqual(self.ln.pay_calls, [])

    def test_calendar_mode_503_stops_the_pass_and_keeps_the_debt(self):
        self.cal.answer = 503
        self.start_calendar_service(INFLIGHT=1)
        fps = [hashlib.sha256(b).hexdigest() for b in (b"r4a", b"r4b")]
        for b in (b"r4a", b"r4b"):
            post_record(self.runner, b)
        self.wait_until(lambda: "challenge_failed" in self.read_service_log()
                        and "status=503" in self.read_service_log(), what="the 503")
        time.sleep(0.5)
        for fp in fps:
            self.assertTrue(os.path.exists(self.debt_file(fp)))
            self.assertFalse(os.path.exists(self.proof_file(fp)))
        self.cal.answer = None
        for fp in fps:
            self.wait_until(lambda fp=fp: os.path.exists(self.proof_file(fp))
                            and not os.path.exists(self.debt_file(fp)),
                            what="proofs after the calendar recovers")
        self.assertEqual(set(self.cal.paths), {"/digest"})

    def test_calendar_mode_garbage_answer_keeps_debt(self):
        self.cal.answer = "garbage"
        self.start_calendar_service(INFLIGHT=1)
        body = b"record five"
        fp = hashlib.sha256(body).hexdigest()
        post_record(self.runner, body)
        self.wait_until(lambda: f"calendar_answer_rejected fp={fp}" in self.read_service_log(),
                        what="the rejected answer")
        self.assertTrue(os.path.exists(self.debt_file(fp)))
        self.assertFalse(os.path.exists(self.proof_file(fp)))
        self.cal.answer = None
        self.wait_until(lambda: os.path.exists(self.proof_file(fp)), what="proof after recovery")

    def test_calendar_mode_upgrade_404_stays_pending_then_anchored_bytes_spliced(self):
        self.start_calendar_service(INFLIGHT=1, UPGRADE_SECS=0.2)
        fp = self.post_and_wait(b"record six")
        with open(self.proof_file(fp), "rb") as f:
            original = f.read()
        commitment = api_endpoint.parse_ots(original).commitment
        self.wait_until(lambda: f"/timestamp/{commitment.hex()}" in self.cal.get_paths,
                        what="an upgrade GET for the commitment")
        time.sleep(0.5)
        self.assertTrue(os.path.exists(self.pending_file(fp)))
        self.assertNotIn(f" bitcoin_attestation_present fp={fp}", self.read_service_log())
        with open(self.proof_file(fp), "rb") as f:
            self.assertEqual(f.read(), original)

        self.cal.mined_height = 965446
        self.wait_until(lambda: not os.path.exists(self.pending_file(fp)),
                        what="the marker to clear")
        with open(self.proof_file(fp), "rb") as f:
            data = f.read()
        ops_end = api_endpoint.parse_ots(original).ops_end
        self.assertEqual(data, original[:ops_end] + cal_bitcoin_response(965446))
        self.assertEqual(api_endpoint.proof_digest(data), fp)
        self.assertTrue(api_endpoint.bitcoin_attestation_present(data))
        self.assertIn(f" bitcoin_attestation_present fp={fp}", self.read_service_log())
        gets = self.cal.gets
        time.sleep(0.8)
        self.assertEqual(self.cal.gets, gets)  # a complete proof is never asked about again

    def test_calendar_mode_nonlinear_proof_needs_attention_keeps_marker(self):
        self.start_calendar_service(INFLIGHT=1, UPGRADE_SECS=0.2)
        fp = hashlib.sha256(b"a proof from somewhere else").hexdigest()
        body, _ = cal_pending_response(bytes.fromhex(fp))
        foreign = OTS_HEAD + bytes.fromhex(fp) + b"\xff" + body
        with open(self.proof_file(fp), "wb") as f:
            f.write(foreign)
        with open(self.pending_file(fp), "wb"):
            pass
        self.wait_until(lambda: f"upgrade_needs_attention fp={fp} status=nonlinear"
                        in self.read_service_log(), what="the nonlinear refusal")
        self.assertTrue(os.path.exists(self.pending_file(fp)))
        with open(self.proof_file(fp), "rb") as f:
            self.assertEqual(f.read(), foreign)
        self.assertEqual(self.cal.gets, 0)

    def test_calendar_mode_inflight_eight_hits_digest_once_per_fingerprint(self):
        self.cal.delay = 0.3
        self.start_calendar_service(INFLIGHT=8)
        bodies = [b"burst %d" % i for i in range(16)]
        fps = [hashlib.sha256(b).hexdigest() for b in bodies]
        for b in bodies:
            self.assertEqual(post_record(self.runner, b)[0], 200)
        for fp in fps:
            self.wait_until(lambda fp=fp: os.path.exists(self.proof_file(fp))
                            and not os.path.exists(self.debt_file(fp)),
                            timeout=40, what="all sixteen proofs")
        self.assertGreaterEqual(self.cal.max_inflight_total, 2)  # the overlap was real
        self.assertEqual(self.cal.max_inflight_fp, 1)              # never twice at once
        self.assertEqual(set(self.cal.paths), {"/digest"})
        self.assertEqual(sorted(self.cal.received), sorted(bytes.fromhex(fp) for fp in fps))
        self.assertEqual(len(self.cal.received), 16)
        for fp in fps:
            with open(self.proof_file(fp), "rb") as f:
                self.assertEqual(api_endpoint.proof_digest(f.read()), fp)
