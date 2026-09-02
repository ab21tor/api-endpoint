#!/usr/bin/env python3
"""api-endpoint — the front door of a client box.

Client systems POST records to a local listener. Each record is SHA-256
fingerprinted in memory (raw bytes are never written and never logged) and
each fingerprint buys its own OpenTimestamps proof from a Lightning-paid
L402 timestamp gateway, paid via the payer phoenixd.

One route: POST /record. Everything else is the filesystem under DATA_DIR
(debts/, proofs/, ledger, heartbeat, log). Config, file semantics, and the
money rules: README.md.
"""

import base64
import http.client
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor
from concurrent.futures import wait as wait_futures
import json
import os
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

HEX64 = re.compile(r"[0-9a-f]{64}")
HEX64_ANYCASE = re.compile(r"[0-9a-fA-F]{64}")

# OpenTimestamps serialization constants. A detached proof always begins with
# HEADER_MAGIC, and an attestation is serialized as a 0x00 marker byte
# followed by its 8-byte type tag — so "\x00 + bitcoin tag" in the bytes
# means the proof carries a Bitcoin block-header attestation: anchored.
# Checked against a real anchored proof and a real pending proof in the tests.
OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
BITCOIN_ATTESTATION = b"\x00" + bytes.fromhex("0588960d73d71901")

# An X-Digest: sha256 body is 64 hex chars plus whatever whitespace a shell
# pipeline appends; anything bigger than this is not a digest.
MAX_HEX_BODY_BYTES = 1024
CHUNK = 65536


class ConfigError(Exception):
    """A startup error whose message tells the operator what to set."""


class Unreachable(Exception):
    """Transport-level failure: refused, timeout, DNS. Not an HTTP status."""


class LedgerCorrupt(Exception):
    """The budget ledger cannot be trusted; purchases pause, intake does not."""


def utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# config
def parse_env_file(path):
    """KEY=VALUE lines; blanks and #-comments skipped; one pair of matching
    surrounding quotes stripped. A missing file means no overrides."""
    out = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return out
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        if key:
            out[key] = val
    return out


def resolve_config(environ, script_dir=SCRIPT_DIR):
    """Invocation env > .env beside the script > defaults; empty string counts
    as unset (the shell ${VAR:-} convention). Raises ConfigError, naming
    what to set, on anything missing or malformed."""
    envfile = parse_env_file(os.path.join(script_dir, ".env"))

    def get(key, default=None):
        return environ.get(key) or envfile.get(key) or default

    listen = get("LISTEN_ADDR")
    if not listen:
        raise ConfigError(
            "set LISTEN_ADDR, e.g. 127.0.0.1:8402 — the host:port this door "
            "listens on; whatever can reach it can spend the budget"
        )
    host, sep, port_s = listen.rpartition(":")
    if not sep or not host or not re.fullmatch(r"[0-9]+", port_s) \
            or not 0 < int(port_s) < 65536:
        raise ConfigError(
            f"LISTEN_ADDR must be host:port, e.g. 127.0.0.1:8402 — got {listen!r}"
        )

    gateway = get("GATEWAY_URL")
    if not gateway:
        raise ConfigError(
            "set GATEWAY_URL, e.g. http://127.0.0.1:8000 — the L402 timestamp "
            "gateway this box buys proofs from"
        )

    def uint(key, default):
        raw = get(key, default)
        if not re.fullmatch(r"[0-9]+", str(raw)):
            raise ConfigError(f"{key} must be a non-negative integer, got {raw!r}")
        return int(raw)

    def secs(key, default):
        raw = get(key, default)
        try:
            v = float(raw)
        except (TypeError, ValueError):
            raise ConfigError(f"{key} must be a number of seconds, got {raw!r}")
        if not v > 0:
            raise ConfigError(f"{key} must be a positive number of seconds, got {raw!r}")
        return v

    def pint(key, default):
        raw = get(key, default)
        if not re.fullmatch(r"[0-9]+", str(raw)) or int(raw) < 1:
            raise ConfigError(f"{key} must be a positive integer, got {raw!r}")
        return int(raw)

    data_dir = get("DATA_DIR", script_dir)
    return {
        "listen_host": host,
        "listen_port": int(port_s),
        "gateway_url": gateway.rstrip("/"),
        "phoenixd_url": get("PHOENIXD_URL", "http://127.0.0.1:9740").rstrip("/"),
        "phoenix_conf": get("PHOENIX_CONF",
                            os.path.expanduser("~/.phoenix/phoenix.conf")),
        "max_price_sats": uint("MAX_PRICE_SATS", "5000"),
        "daily_budget_sats": uint("DAILY_BUDGET_SATS", "200000"),
        "poll_secs": secs("POLL_SECS", "2"),
        "upgrade_secs": secs("UPGRADE_SECS", "600"),
        "heartbeat_secs": secs("HEARTBEAT_SECS", "10"),
        "l402_expiry_secs": secs("L402_EXPIRY_SECS", "3600"),
        "breaker_failures": uint("CIRCUIT_BREAKER_FAILURES", "5"),
        "breaker_pause_secs": secs("CIRCUIT_BREAKER_PAUSE_SECS", "60"),
        "inflight": pint("INFLIGHT", "1"),
        "data_dir": data_dir,
        "debts_dir": os.path.join(data_dir, "debts"),
        "proofs_dir": os.path.join(data_dir, "proofs"),
        "ledger_path": os.path.join(data_dir, "ledger"),
        "heartbeat_path": os.path.join(data_dir, "heartbeat"),
        "log_path": os.path.join(data_dir, "log"),
    }


def read_phoenix_password(path):
    """The payer phoenixd's full http-password (paying requires it), read from
    phoenix.conf exactly like pay402. Never argv, never logged."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("http-password="):
                    pw = line[len("http-password="):].strip()
                    if pw:
                        return pw
    except OSError:
        pass
    raise ConfigError(
        f"no http-password in {path} — point PHOENIX_CONF at the payer "
        "phoenixd's phoenix.conf"
    )


# log
_LOG_LOCK = threading.Lock()


def log_event(cfg, event, **kv):
    """One fixed-format line: '<utc> <event> k=v ...'. Never record bytes,
    never secrets, never gateway or phoenixd URLs."""
    parts = [utc_now_iso(), event] + [f"{k}={v}" for k, v in kv.items()]
    with _LOG_LOCK:
        try:
            with open(cfg["log_path"], "a", encoding="utf-8") as f:
                f.write(" ".join(parts) + "\n")
        except OSError:
            pass  # a failing log must never take down intake or buying


# durable writes
def fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write(path, data):
    """tmp file in the same directory + rename, fsynced: readers see the old
    bytes or the new bytes, never a torn file."""
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix="." + os.path.basename(path) + ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    fsync_dir(d)


# ledger
LEDGER_LINE = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}) ([0-9]+)\s*")


def read_ledger(path):
    """Returns (day, spent_sats). Absent or empty is a clean zero; anything
    else must be one well-formed line — a corrupt ledger pauses purchases,
    never silently resets the budget."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        return utc_today(), 0
    except (OSError, UnicodeDecodeError):
        raise LedgerCorrupt("ledger unreadable")
    if text.strip() == "":
        return utc_today(), 0
    m = LEDGER_LINE.fullmatch(text)
    if not m:
        raise LedgerCorrupt("ledger malformed")
    return m.group(1), int(m.group(2))


def write_ledger(path, day, spent):
    atomic_write(path, f"{day} {spent}\n".encode())


# small pure pieces
def validate_hex_digest(text):
    """The X-Digest: sha256 body rule: exactly 64 hex chars once surrounding
    whitespace is trimmed, any case in, lowercase out. None = reject. The
    body is never inspected for hex-ness without the header — no guessing."""
    t = text.strip()
    if HEX64_ANYCASE.fullmatch(t):
        return t.lower()
    return None


def parse_l402_challenge(header):
    """'L402 macaroon="...", invoice="..."' -> (macaroon, invoice) or None."""
    if not header or not header.strip().startswith("L402"):
        return None
    m = re.search(r'macaroon="([^"]+)"', header)
    i = re.search(r'invoice="([^"]+)"', header)
    if not m or not i:
        return None
    return m.group(1), i.group(1)


def _as_positive_int(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v if v > 0 else None
    if isinstance(v, str) and re.fullmatch(r"[0-9]+", v):
        n = int(v)
        return n if n > 0 else None
    return None


def amount_sats_from_decoded(d):
    """Precedence, as in pay402: amountSat, then amount (msat), then
    amountMsat. None on anything unreadable or zero — the caller fails
    closed rather than pay an unbounded invoice."""
    if not isinstance(d, dict):
        return None
    sat = _as_positive_int(d.get("amountSat"))
    if sat is not None:
        return sat
    for key in ("amount", "amountMsat"):
        msat = _as_positive_int(d.get(key))
        if msat is not None and msat // 1000 > 0:
            return msat // 1000
    return None


def looks_like_ots(data):
    return data.startswith(OTS_MAGIC)


def is_anchored(data):
    return BITCOIN_ATTESTATION in data


class StateChange:
    """Log-once-per-transition holder, so a 2-second loop cannot flood the
    log with one persistent condition."""

    def __init__(self):
        self.state = None

    def transition(self, new):
        prev, self.state = self.state, new
        return prev != new, prev


# HTTP plumbing (urllib only; no curl, no argv, no new dependencies)
def http_post(url, body, headers, timeout):
    """POST returning (status, headers, body_bytes). 4xx/5xx are returned,
    not raised; only transport failures raise Unreachable."""
    req = urllib.request.Request(url, data=body, headers=dict(headers),
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        try:
            resp_body = e.read()
        except OSError:
            resp_body = b""
        return e.code, e.headers if e.headers is not None else {}, resp_body
    except (OSError, http.client.HTTPException) as e:
        raise Unreachable(type(e).__name__)


def gateway_challenge(cfg, fp):
    return http_post(cfg["gateway_url"] + "/timestamp",
                     json.dumps({"digest": fp}).encode(),
                     {"Content-Type": "application/json"}, timeout=60)


def gateway_redeem(cfg, fp, macaroon, preimage):
    # 120s: the gateway's calendar submission retries can take ~60s.
    return http_post(cfg["gateway_url"] + "/timestamp",
                     json.dumps({"digest": fp}).encode(),
                     {"Content-Type": "application/json",
                      "Authorization": f"L402 {macaroon}:{preimage}"},
                     timeout=120)


def gateway_upgrade(cfg, fp, ots_bytes):
    body = json.dumps({"digest": fp,
                       "ots": base64.b64encode(ots_bytes).decode("ascii")})
    return http_post(cfg["gateway_url"] + "/upgrade", body.encode(),
                     {"Content-Type": "application/json"}, timeout=60)


def phoenixd_call(cfg, password, endpoint, bolt11, timeout):
    tok = base64.b64encode(b":" + password.encode()).decode("ascii")
    status, _, body = http_post(
        cfg["phoenixd_url"] + endpoint,
        urllib.parse.urlencode({"invoice": bolt11}).encode(),
        {"Content-Type": "application/x-www-form-urlencoded",
         "Authorization": "Basic " + tok},
        timeout,
    )
    if status != 200:
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


def decode_invoice_sats(cfg, password, bolt11):
    """None on any failure — never pay an amount that could not be read."""
    return amount_sats_from_decoded(
        phoenixd_call(cfg, password, "/decodeinvoice", bolt11, timeout=15))


def pay_invoice(cfg, password, bolt11):
    """The payment preimage (64 hex) or None. Raises Unreachable when the
    outcome is unknown — the caller must treat that as possibly-paid."""
    d = phoenixd_call(cfg, password, "/payinvoice", bolt11, timeout=120)
    if isinstance(d, dict):
        p = d.get("paymentPreimage")
        if isinstance(p, str) and HEX64.fullmatch(p.lower()):
            return p.lower()
    return None


def _retry_after_secs(headers):
    v = (headers.get("Retry-After") or "").strip()
    if re.fullmatch(r"[0-9]+", v):
        return min(int(v), 300)
    return 10


# debts on disk
def debt_path(cfg, fp):
    return os.path.join(cfg["debts_dir"], fp)


def sidecar_path(cfg, fp):
    return debt_path(cfg, fp) + ".l402"


def proof_path(cfg, fp):
    return os.path.join(cfg["proofs_dir"], fp + ".ots")


def write_debt(cfg, fp):
    """Create the debt durably (file fsync + directory fsync). True if newly
    created, False if the fingerprint was already owed. Must complete before
    'received' goes out — the debt is the promise."""
    try:
        fd = os.open(debt_path(cfg, fp),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    try:
        os.write(fd, (fp + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(cfg["debts_dir"])
    return True


def list_debts_oldest_first(cfg):
    out = []
    for name in os.listdir(cfg["debts_dir"]):
        if HEX64.fullmatch(name):
            try:
                out.append((os.stat(os.path.join(cfg["debts_dir"], name)).st_mtime,
                            name))
            except OSError:
                continue
    out.sort()
    return [name for _, name in out]


def list_proofs(cfg):
    out = []
    for name in os.listdir(cfg["proofs_dir"]):
        if name.endswith(".ots") and HEX64.fullmatch(name[:-4]):
            out.append(name[:-4])
    out.sort()
    return out


def load_sidecar(path):
    """(None, 0) when absent; ({}, age) when present but unreadable;
    (dict, age) when well-formed. Age comes from mtime, which only changes
    when the sidecar itself is rewritten."""
    try:
        st = os.stat(path)
    except (FileNotFoundError, OSError):
        return None, 0.0
    age = max(0.0, time.time() - st.st_mtime)
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict) and isinstance(d.get("macaroon"), str) \
                and isinstance(d.get("invoice"), str):
            return d, age
    except (OSError, ValueError):
        pass
    return {}, age


def write_sidecar(path, macaroon, invoice, preimage=None):
    d = {"macaroon": macaroon, "invoice": invoice}
    if preimage:
        d["preimage"] = preimage
    atomic_write(path, (json.dumps(d) + "\n").encode())


def clear_debt(cfg, fp):
    for p in (sidecar_path(cfg, fp), debt_path(cfg, fp)):
        try:
            os.unlink(p)
        except OSError:
            pass


# the buyer
def _breaker_failed(cfg, br):
    """A definite payment failure. True = keep the pass working; False the
    moment the breaker trips or a probe fails — purchasing stops. The wait
    doubles per failed probe, capped at an hour."""
    if br["open"]:
        br["wait"] = min(br["wait"] * 2, 3600)
        br["until"] = time.time() + br["wait"]
        return False
    br["failures"] += 1
    if br["failures"] < cfg["breaker_failures"]:
        return True
    br["open"] = True
    br["wait"] = float(cfg["breaker_pause_secs"])
    br["until"] = time.time() + br["wait"]
    log_event(cfg, "breaker_tripped", failures=br["failures"],
              pause_secs=int(br["wait"]))
    return False


def _breaker_settled(cfg, br):
    """Any settled payment closes the breaker and clears the failure count."""
    if br["open"]:
        log_event(cfg, "breaker_cleared")
    br["open"] = False
    br["failures"] = 0
    br["wait"] = 0.0
    br["until"] = 0.0


def _mark_down(cfg, flags, which):
    changed, _ = flags[which].transition("down")
    if changed:
        log_event(cfg, which + "_unreachable")
    return False


def _mark_up(cfg, flags, which):
    changed, prev = flags[which].transition("up")
    if changed and prev == "down":
        log_event(cfg, which + "_recovered")


def _redeem(cfg, fp, macaroon, preimage, amt, flags):
    try:
        status, headers, body = gateway_redeem(cfg, fp, macaroon, preimage)
    except Unreachable:
        return _mark_down(cfg, flags, "gateway")
    _mark_up(cfg, flags, "gateway")
    if status == 200:
        if looks_like_ots(body):
            atomic_write(proof_path(cfg, fp), body)
            clear_debt(cfg, fp)
            log_event(cfg, "bought", fp=fp,
                      sats=amt if amt is not None else "unknown")
            return True
        log_event(cfg, "redeem_failed", fp=fp, status=status,
                  note="body_not_ots_paid_but_unredeemed")
        return True
    if status == 429:
        wait = _retry_after_secs(headers)
        flags["retry_at"][0] = time.time() + wait
        log_event(cfg, "rate_limited", wait_secs=wait)
        return False
    # Paid but not redeemed. The sidecar (macaroon + preimage) stays and
    # every pass retries forever; the gateway's rule is that settlement
    # outranks expiry.
    log_event(cfg, "redeem_failed", fp=fp, status=status,
              note="paid_but_unredeemed")
    return status != 503


def _pay_and_redeem(cfg, password, fp, macaroon, invoice, amt, flags):
    br = flags["breaker"]
    if br["open"]:
        # buyer_pass gates while the pause runs, so being here with the
        # breaker open means the pause elapsed: this payment is the single
        # probe that decides whether purchasing resumes.
        log_event(cfg, "breaker_probe", pause_secs=int(br["wait"]))
    try:
        preimage = pay_invoice(cfg, password, invoice)
    except Unreachable:
        # Unknown outcome: the sidecar stays, and the next pass retries THIS
        # stored invoice, never a fresh challenge — the payment cannot double.
        _mark_down(cfg, flags, "phoenixd")
        log_event(cfg, "payment_outcome_unknown", fp=fp,
                  sats=amt if amt is not None else "unknown")
        return False
    _mark_up(cfg, flags, "phoenixd")
    if not preimage:
        log_event(cfg, "payment_failed", fp=fp,
                  sats=amt if amt is not None else "unknown",
                  note="reserved_against_budget")
        return _breaker_failed(cfg, br)
    _breaker_settled(cfg, br)
    try:
        write_sidecar(sidecar_path(cfg, fp), macaroon, invoice, preimage)
    except OSError:
        # Still redeem now; if that fails too, the retry path re-pays this
        # same stored invoice and phoenixd's own dedupe is the last line.
        log_event(cfg, "cannot_write_sidecar", fp=fp)
    return _redeem(cfg, fp, macaroon, preimage, amt, flags)


def finish_sidecar(cfg, password, fp, sc, age, flags):
    """Resume an in-flight purchase after a crash or failed attempt. With a
    preimage: redeem only — never pay again. Without one: re-pay the STORED
    invoice only, until L402_EXPIRY_SECS, then abandon the challenge loudly
    (the one edge where a double charge cannot be ruled out)."""
    macaroon, invoice, preimage = sc.get("macaroon"), sc.get("invoice"), sc.get("preimage")

    if isinstance(preimage, str) and isinstance(macaroon, str):
        return _redeem(cfg, fp, macaroon, preimage, None, flags)

    if isinstance(macaroon, str) and isinstance(invoice, str):
        if age <= cfg["l402_expiry_secs"]:
            return _pay_and_redeem(cfg, password, fp, macaroon, invoice, None, flags)
    else:
        if fp not in flags["corrupt_logged"]:
            flags["corrupt_logged"].add(fp)
            log_event(cfg, "sidecar_corrupt", fp=fp)
        if age <= cfg["l402_expiry_secs"]:
            return True  # unknown in-flight state: wait out the invoice window

    # Past the invoice lifetime with no preimage in hand. If the payment did
    # settle out there, a fresh challenge means paying twice — say so loudly.
    # The ledger already counted the first attempt and keeps it.
    log_event(cfg, "rechallenge_after_unknown_payment", fp=fp,
              note="possible_double_charge")
    try:
        os.unlink(sidecar_path(cfg, fp))
    except OSError:
        pass
    flags["corrupt_logged"].discard(fp)
    return True


def _budget_preflight(cfg, flags):
    """Budget preflight before any gateway contact: a corrupt ledger pauses
    every purchase (and challenge), never intake. Returns one of
    ("stop", None, None)  — the ledger is unreadable: the pass ends;
    ("skip", day, spent)  — today's budget is spent: the debt is kept;
    ("ok", day, spent)    — proceed to the gateway."""
    try:
        day, spent = read_ledger(cfg["ledger_path"])
    except LedgerCorrupt:
        changed, _ = flags["ledger"].transition("paused")
        if changed:
            log_event(cfg, "purchases_paused", reason="ledger_unreadable")
        return "stop", None, None
    changed, prev = flags["ledger"].transition("ok")
    if changed and prev == "paused":
        log_event(cfg, "purchases_resumed")

    # An exhausted budget skips the debt here, before any gateway or phoenixd
    # contact; logged once per transition, like the ledger pause above. Skip,
    # not stop: a later debt's sidecar may hold a paid preimage, and
    # settlement outranks expiry whatever the budget says.
    today = utc_today()
    already = spent if day == today else 0
    remaining = cfg["daily_budget_sats"] - already
    if remaining <= 0:
        changed, _ = flags["budget"].transition("exhausted")
        if changed:
            log_event(cfg, "budget_exhausted", remaining=remaining,
                      budget=cfg["daily_budget_sats"])
        return "skip", day, spent
    changed, prev = flags["budget"].transition("ok")
    if changed and prev == "exhausted":
        log_event(cfg, "budget_resumed", remaining=remaining,
                  budget=cfg["daily_budget_sats"])
    return "ok", day, spent


def buy_one(cfg, password, fp, flags):
    """Work one debt to its next durable state. True = keep working this
    pass; False = stop the pass (gateway or payer down, rate-limited, the
    ledger unreadable, or the breaker tripped). Every skip leaves the debt
    in place — never dropped."""
    if os.path.exists(proof_path(cfg, fp)):
        # One record, one payment, one proof: a re-POSTed or already-bought
        # fingerprint costs nothing.
        clear_debt(cfg, fp)
        log_event(cfg, "already_bought", fp=fp)
        return True

    sc, age = load_sidecar(sidecar_path(cfg, fp))
    if sc is not None:
        return finish_sidecar(cfg, password, fp, sc, age, flags)

    verdict, day, spent = _budget_preflight(cfg, flags)
    if verdict != "ok":
        return verdict == "skip"  # "stop" ends the pass; "skip" keeps the debt

    try:
        status, headers, body = gateway_challenge(cfg, fp)
    except Unreachable:
        return _mark_down(cfg, flags, "gateway")
    _mark_up(cfg, flags, "gateway")
    return _buy_challenged(cfg, password, fp, status, headers, body,
                           day, spent, flags)


def _buy_challenged(cfg, password, fp, status, headers, body, day, spent, flags):
    """The gateway has answered a challenge for fp: the free door hands the
    proof over, 429 rate-limits the pass, 402 enters the paid machinery
    (decode, ceilings, reserve, sidecar, pay, redeem). day/spent are the
    ledger as read by the preflight that preceded THIS call — nothing may
    have reserved against the ledger in between."""
    if status == 200 and looks_like_ots(body):
        # The gateway handed the proof over without charging: its free door
        # (L402_ENABLED=false).
        atomic_write(proof_path(cfg, fp), body)
        clear_debt(cfg, fp)
        log_event(cfg, "proof_free", fp=fp)
        return True
    if status == 429:
        wait = _retry_after_secs(headers)
        flags["retry_at"][0] = time.time() + wait
        log_event(cfg, "rate_limited", wait_secs=wait)
        return False
    if status != 402:
        log_event(cfg, "challenge_failed", fp=fp, status=status)
        return status != 503  # a paused gateway fails every debt: stop the pass
    parsed = parse_l402_challenge(headers.get("WWW-Authenticate", ""))
    if not parsed:
        log_event(cfg, "challenge_malformed", fp=fp)
        return True
    macaroon, invoice = parsed

    # Ceiling and budget are enforced on the DECODED amount, never the
    # gateway's claim (the pay402 rule; fail closed when unreadable).
    try:
        amt = decode_invoice_sats(cfg, password, invoice)
    except Unreachable:
        return _mark_down(cfg, flags, "phoenixd")
    _mark_up(cfg, flags, "phoenixd")
    if amt is None:
        log_event(cfg, "skip", fp=fp, reason="cannot_decode_invoice")
        return True
    if amt > cfg["max_price_sats"]:
        log_event(cfg, "skip", fp=fp, reason="exceeds_price_ceiling",
                  amt=amt, ceiling=cfg["max_price_sats"])
        return True
    today = utc_today()
    already = spent if day == today else 0
    remaining = cfg["daily_budget_sats"] - already
    if amt > remaining:
        log_event(cfg, "skip", fp=fp, reason="exceeds_daily_budget",
                  amt=amt, remaining=remaining)
        return True

    # Reserve before paying (attempts, not successes; never refunded
    # intra-day), and persist the challenge BEFORE the payment it authorizes
    # so a crash after payinvoice can redeem without paying twice.
    try:
        write_ledger(cfg["ledger_path"], today, already + amt)
    except OSError:
        log_event(cfg, "cannot_write_ledger", fp=fp)
        return False
    try:
        write_sidecar(sidecar_path(cfg, fp), macaroon, invoice)
    except OSError:
        log_event(cfg, "cannot_write_sidecar", fp=fp)
        return False
    return _pay_and_redeem(cfg, password, fp, macaroon, invoice, amt, flags)


def buyer_pass(cfg, password, flags):
    if cfg["inflight"] > 1:
        return _buyer_pass_inflight(cfg, password, flags)
    br = flags["breaker"]
    for fp in list_debts_oldest_first(cfg):
        if time.time() < flags["retry_at"][0]:
            return  # honoring the gateway's Retry-After
        if br["open"] and time.time() < br["until"]:
            return  # breaker open: purchase nothing until the pause elapses
        if not buy_one(cfg, password, fp, flags):
            return


def _buyer_pass_inflight(cfg, password, flags):
    """INFLIGHT > 1. Up to cfg["inflight"] gateway_challenge submissions
    ride in flight at once, oldest debts first. The worker threads do only
    the HTTP call; every response is handled here on the buyer thread, so
    the files, the ledger, the log and the flags are touched by one thread
    exactly as at INFLIGHT=1. A free-door answer (200 + ots) completes as
    today. The first sign of the paid door — a 402, or a sidecar already on
    disk — ends the concurrent phase: the outstanding answers are collected,
    then that debt and every remaining debt go one at a time through the
    same paid machinery buy_one uses. Payments are never concurrent. A
    fingerprint is in flight at most once because a pass drains before it
    returns and the next pass lists the debts afresh. Retry-After and the
    breaker gate every new submission just as they gate every serial debt;
    a stop (429, 503, gateway unreachable, ledger unreadable) still lets the
    answers already in flight land, then ends the pass — any 402 among them
    is simply owed again next pass, unpaid and unreserved."""
    br = flags["breaker"]
    n = cfg["inflight"]
    queue = list_debts_oldest_first(cfg)
    pos = {fp: i for i, fp in enumerate(queue)}
    idx = 0            # next debt not yet taken from the queue
    outstanding = {}   # future -> (fp, day, spent as read before submitting)
    deferred = {}      # fp -> (status, headers, body): 402s for the serial phase
    stop = False       # buy_one's False: the pass ends once the air is clear
    go_serial = False  # the paid door showed itself: serial from here on

    def gated():
        if time.time() < flags["retry_at"][0]:
            return True  # honoring the gateway's Retry-After
        if br["open"] and time.time() < br["until"]:
            return True  # breaker open: purchase nothing until the pause elapses
        return False

    with ThreadPoolExecutor(max_workers=n, thread_name_prefix="inflight") as pool:
        while True:
            while (not stop and not go_serial and idx < len(queue)
                   and len(outstanding) < n):
                if gated():
                    stop = True
                    break
                fp = queue[idx]
                idx += 1
                if os.path.exists(proof_path(cfg, fp)):
                    buy_one(cfg, password, fp, flags)  # already_bought: no contact
                    continue
                if load_sidecar(sidecar_path(cfg, fp))[0] is not None:
                    idx -= 1  # an in-flight purchase: the paid machinery's, serially
                    go_serial = True
                    break
                verdict, day, spent = _budget_preflight(cfg, flags)
                if verdict == "stop":
                    stop = True
                    break
                if verdict == "skip":
                    continue
                outstanding[pool.submit(gateway_challenge, cfg, fp)] = (fp, day, spent)
            if not outstanding:
                break
            done, _ = wait_futures(outstanding, return_when=FIRST_COMPLETED)
            for fut in done:
                fp, day, spent = outstanding.pop(fut)
                exc = fut.exception()
                if exc is not None:
                    if isinstance(exc, Unreachable):
                        _mark_down(cfg, flags, "gateway")
                        stop = True
                        continue
                    raise exc
                _mark_up(cfg, flags, "gateway")
                status, headers, body = fut.result()
                if status == 402:
                    deferred[fp] = (status, headers, body)
                    go_serial = True
                    continue
                if not _buy_challenged(cfg, password, fp, status, headers, body,
                                       day, spent, flags):
                    stop = True
    if stop or not go_serial:
        return
    # Serial phase: the 402s already answered, oldest first, then every debt
    # still untouched, each one to completion before the next begins. A
    # collected 402 re-reads the ledger first: the reservation just made for
    # the debt before it must count.
    for fp in sorted(deferred, key=pos.get) + queue[idx:]:
        if gated():
            return
        if fp in deferred:
            status, headers, body = deferred[fp]
            verdict, day, spent = _budget_preflight(cfg, flags)
            if verdict == "stop":
                return
            if verdict == "skip":
                continue
            ok = _buy_challenged(cfg, password, fp, status, headers, body,
                                 day, spent, flags)
        else:
            ok = buy_one(cfg, password, fp, flags)
        if not ok:
            return


def buyer_loop(cfg, password, hb):
    flags = {
        "gateway": StateChange(),
        "phoenixd": StateChange(),
        "ledger": StateChange(),
        "budget": StateChange(),
        "retry_at": [0.0],
        "corrupt_logged": set(),
        # The circuit breaker lives in memory only, by design: a process
        # killed while paused starts closed and re-trips if the fault holds.
        "breaker": {"failures": 0, "open": False, "wait": 0.0, "until": 0.0},
    }
    hb["breaker"] = flags["breaker"]  # the heartbeat reports open/closed
    while True:
        hb["buyer"] = time.time()
        try:
            buyer_pass(cfg, password, flags)
        except Exception as e:  # the loop must survive anything
            log_event(cfg, "buyer_error", err=type(e).__name__)
        time.sleep(cfg["poll_secs"])


# the upgrader
def upgrade_pass(cfg, flags):
    """POST each still-pending proof to the gateway's free /upgrade (JSON in,
    JSON out, ots base64 both ways). The file is replaced only when the
    response says bitcoin_anchored and the returned bytes agree."""
    checked = 0
    newly_anchored = 0
    for fp in list_proofs(cfg):
        path = proof_path(cfg, fp)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        if is_anchored(data):
            continue
        checked += 1
        try:
            status, headers, body = gateway_upgrade(cfg, fp, data)
        except Unreachable:
            _mark_down(cfg, flags, "upgrade_gateway")
            break
        _mark_up(cfg, flags, "upgrade_gateway")
        if status == 429:
            log_event(cfg, "upgrade_rate_limited",
                      wait_secs=_retry_after_secs(headers))
            break
        if status != 200:
            log_event(cfg, "upgrade_failed", fp=fp, status=status)
            if status == 503:
                break
            continue
        try:
            resp = json.loads(body)
        except ValueError:
            log_event(cfg, "upgrade_failed", fp=fp, status="bad_json")
            continue
        if not isinstance(resp, dict) or resp.get("status") == "pending":
            continue  # normal: Bitcoin has not confirmed yet
        if resp.get("bitcoin_anchored") is True and isinstance(resp.get("ots"), str):
            try:
                new_bytes = base64.b64decode(resp["ots"], validate=True)
            except ValueError:
                log_event(cfg, "upgrade_failed", fp=fp, status="bad_base64")
                continue
            if looks_like_ots(new_bytes) and is_anchored(new_bytes):
                try:
                    atomic_write(path, new_bytes)
                except OSError:
                    log_event(cfg, "upgrade_failed", fp=fp, status="write_failed")
                    continue
                newly_anchored += 1
                log_event(cfg, "anchored", fp=fp)
            else:
                log_event(cfg, "upgrade_failed", fp=fp,
                          status="anchored_reply_without_anchored_bytes")
            continue
        # invalid / mismatch / no_attestations: our artifact is wrong — loud.
        log_event(cfg, "upgrade_needs_attention", fp=fp,
                  status=resp.get("status"))
    if checked:
        log_event(cfg, "upgrade_pass", checked=checked, anchored=newly_anchored)


def upgrader_loop(cfg, hb):
    flags = {"upgrade_gateway": StateChange()}
    while True:
        hb["upgrader"] = time.time()
        try:
            upgrade_pass(cfg, flags)
        except Exception as e:
            log_event(cfg, "upgrader_error", err=type(e).__name__)
        time.sleep(cfg["upgrade_secs"])


# heartbeat
def _ts_or_never(t):
    if not t:
        return "never"
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_heartbeat(cfg, hb):
    br = hb.get("breaker") or {}
    line = "{} pid={} buyer={} breaker={} upgrader={}\n".format(
        utc_now_iso(), os.getpid(),
        _ts_or_never(hb.get("buyer")),
        "paused" if br.get("open") else "ok",
        _ts_or_never(hb.get("upgrader")))
    try:
        atomic_write(cfg["heartbeat_path"], line.encode())
    except OSError:
        pass


# the door
def make_handler(cfg):
    class Handler(BaseHTTPRequestHandler):
        # One stalled client must not hold a worker forever.
        timeout = 60
        server_version = "api-endpoint/1"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass  # our own log carries the events; no per-request stderr noise

        def _reply(self, code, text, extra=None):
            payload = (text + "\n").encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(payload)
            except OSError:
                pass

        def _method_not_allowed(self):
            self._reply(405, "method not allowed; the only route is POST /record",
                        {"Allow": "POST"})

        do_GET = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = \
            _method_not_allowed

        def _fingerprint(self):
            """(fp, None) on success; (None, (code, slug, message)) to
            reject; (None, None) when the client vanished mid-body (no reply
            owed — no promise was made)."""
            if self.headers.get("Transfer-Encoding"):
                return None, (411, "length_required",
                              "send Content-Length; chunked bodies are not supported")
            cl = (self.headers.get("Content-Length") or "").strip()
            if not re.fullmatch(r"[0-9]+", cl):
                return None, (411, "length_required", "Content-Length is required")
            length = int(cl)

            xd = self.headers.get("X-Digest")
            if xd is not None:
                # A ready-made digest is accepted ONLY under this header.
                if xd.strip().lower() != "sha256":
                    return None, (400, "bad_x_digest",
                                  "the only supported X-Digest value is sha256")
                if length > MAX_HEX_BODY_BYTES:
                    return None, (400, "bad_digest",
                                  "X-Digest: sha256 body must be 64 hex chars")
                try:
                    body = self.rfile.read(length)
                except OSError:
                    return None, None
                if len(body) != length:
                    return None, None
                try:
                    text = body.decode("ascii")
                except UnicodeDecodeError:
                    return None, (400, "bad_digest",
                                  "X-Digest: sha256 body must be 64 hex chars")
                fp = validate_hex_digest(text)
                if fp is None:
                    return None, (400, "bad_digest",
                                  "X-Digest: sha256 body must be 64 hex chars")
                return fp, None

            # Default: SHA-256 of the raw bytes, streamed in chunks — never
            # stored, never logged, memory stays flat whatever the size.
            if length == 0:
                return None, (400, "empty_body", "record body is empty")
            h = sha256()
            remaining = length
            while remaining > 0:
                try:
                    chunk = self.rfile.read(min(CHUNK, remaining))
                except OSError:
                    return None, None
                if not chunk:
                    return None, None
                h.update(chunk)
                remaining -= len(chunk)
            return h.hexdigest(), None

        def do_POST(self):
            if self.path.split("?", 1)[0] != "/record":
                self._reply(404, "not found; the only route is POST /record")
                return
            fp, err = self._fingerprint()
            if fp is None:
                if err is not None:
                    code, slug, msg = err
                    log_event(cfg, "rejected", reason=slug)
                    self._reply(code, msg)
                return
            new_debt = False
            if not os.path.exists(proof_path(cfg, fp)):
                try:
                    new_debt = write_debt(cfg, fp)
                except OSError:
                    # The debt could not be made durable: no debt, no promise.
                    log_event(cfg, "intake_error", fp=fp,
                              reason="debt_write_failed")
                    self._reply(500, "cannot record the debt; not received")
                    return
            log_event(cfg, "received", fp=fp, new_debt=str(new_debt).lower())
            self._reply(200, "received " + fp)

    return Handler


# main
def main():
    os.umask(0o077)
    try:
        cfg = resolve_config(os.environ)
        password = read_phoenix_password(cfg["phoenix_conf"])
        os.makedirs(cfg["debts_dir"], exist_ok=True)
        os.makedirs(cfg["proofs_dir"], exist_ok=True)
    except ConfigError as e:
        print(f"api-endpoint: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"api-endpoint: cannot prepare DATA_DIR: {e}", file=sys.stderr)
        return 2

    try:
        server = ThreadingHTTPServer((cfg["listen_host"], cfg["listen_port"]),
                                     make_handler(cfg))
    except OSError as e:
        print(f"api-endpoint: cannot bind LISTEN_ADDR "
              f"{cfg['listen_host']}:{cfg['listen_port']}: {e}", file=sys.stderr)
        return 2

    log_event(cfg, "startup",
              listen=f"{cfg['listen_host']}:{cfg['listen_port']}",
              max_price_sats=cfg["max_price_sats"],
              daily_budget_sats=cfg["daily_budget_sats"],
              poll_secs=cfg["poll_secs"],
              upgrade_secs=cfg["upgrade_secs"],
              debts=len(list_debts_oldest_first(cfg)),
              proofs=len(list_proofs(cfg)),
              **({"inflight": cfg["inflight"]} if cfg["inflight"] > 1 else {}))

    hb = {}
    threading.Thread(target=server.serve_forever, name="door",
                     daemon=True).start()
    threading.Thread(target=buyer_loop, args=(cfg, password, hb), name="buyer",
                     daemon=True).start()
    threading.Thread(target=upgrader_loop, args=(cfg, hb), name="upgrader",
                     daemon=True).start()

    # Main thread: the heartbeat. Debts and sidecars carry everything across
    # a death, so there is no shutdown sequence.
    try:
        while True:
            write_heartbeat(cfg, hb)
            time.sleep(cfg["heartbeat_secs"])
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
