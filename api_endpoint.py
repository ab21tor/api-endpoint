#!/usr/bin/env python3
"""api-endpoint — the front door of a client box.

Client systems POST records to a local listener. Each record is SHA-256
fingerprinted in memory (raw bytes are never written and never logged) and
each fingerprint gets its own OpenTimestamps proof, in one of two shapes:

  hosted    GATEWAY_URL  — bought from a Lightning-paid L402 timestamp
                           gateway, paid via the payer phoenixd (or handed
                           over by the gateway's free door);
  appliance CALENDAR_URL — submitted straight to the box's own calendar
                           (the opentimestamps-server fork's counted
                           /digest), no payment anywhere.

One route: POST /record. Everything else is the filesystem under DATA_DIR
(debts/, proofs/, pending/, ledger, heartbeat, log). Config, file semantics, and the
money rules: README.md.
"""

import base64
import collections
import http.client
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor
from concurrent.futures import wait as wait_futures
import json
import math
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
# followed by its 8-byte type tag. Whether a proof carries a Bitcoin
# block-header attestation is decided by deserialising the whole proof and
# inspecting its attestation nodes (inspect_proof), never by scanning the
# bytes for the tag: a chosen digest or an operand can contain those nine
# bytes (2026-09-15 review, "structural parsing is called Bitcoin
# verification"). Checked against a real anchored proof and a real pending
# proof in the tests.
OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
BITCOIN_TAG = bytes.fromhex("0588960d73d71901")
BITCOIN_ATTESTATION = b"\x00" + BITCOIN_TAG
# The other two block-header attestations the public client knows
# (LitecoinBlockHeaderAttestation; EthereumBlockHeaderAttestation under
# dubious/). Their payload is one varuint height, read to its end exactly
# as the client reads it; they are not usable attestations here and read
# as unknown (2026-09-18 cold review R09: they used to be opaque, so an
# empty or trailing payload the client refuses parsed, and beside a
# Bitcoin node made a proof bitcoin_attestation_present).
HEIGHT_TAGS = (BITCOIN_TAG, bytes.fromhex("06869a0d73d71b45"), bytes.fromhex("30fe8087b5c7ead7"))

# OpenTimestamps proof bytes, the subset a single calendar emits — a COPY of
# the parser in the fork's ops/selfstamp.py (2026-09-11), kept here because
# this file is one stdlib file with no sibling to import from. The two
# copies are held to the same corpus (proof_corpus.py) against the
# opentimestamps library by their tests; a change to one is a change to
# both. docs/contracts.md, "The proof parser": what "parses" means here.
OTS_VERSION = 1
OP_SHA256 = 0x08
OP_APPEND = 0xF0
OP_PREPEND = 0xF1
ATTESTATION_MARKER = 0x00
FORK_MARKER = 0xFF
PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")

# The public client's limits (opentimestamps 0.4.x: core/op.py,
# core/notary.py, core/timestamp.py), mirrored so that "parses" means the
# same here as there. The last one is ours: the client reads a varuint of
# any length; nothing valid needs more than ten bytes.
MAX_OPERAND = 4096              # Op.MAX_RESULT_LENGTH: an append/prepend operand is 1..4096 bytes
MAX_MSG = 4096                  # Op.MAX_MSG_LENGTH: no message on a path is longer
MAX_ATTESTATION_PAYLOAD = 8192  # TimeAttestation.MAX_PAYLOAD_SIZE
MAX_URI = 1000                  # PendingAttestation.MAX_URI_LENGTH
URI_CHARS = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._/:")
MAX_OPS_ON_A_PATH = 255         # Timestamp.deserialize's recursion limit (256 levels)
MAX_VARUINT_BYTES = 10

Proof = collections.namedtuple("Proof", "digest commitment attestation ops_end")


class OtsError(Exception):
    """A proof this adapter cannot read or must not write. The only error
    the readers below raise, whatever the bytes (2026-09-15/16 review
    F13: an IndexError escaped and stopped the startup reconciliation)."""


def varuint(n):
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def read_varuint(data, pos):
    value = 0
    shift = 0
    start = pos
    while True:
        if pos >= len(data):
            raise OtsError("truncated varuint")
        if pos - start >= MAX_VARUINT_BYTES:
            raise OtsError("varuint longer than %d bytes" % MAX_VARUINT_BYTES)
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


def read_varbytes(data, pos, max_len, min_len=0):
    length, pos = read_varuint(data, pos)
    if length > max_len:
        raise OtsError("varbytes longer than %d bytes" % max_len)
    if length < min_len:
        raise OtsError("varbytes shorter than %d byte" % min_len)
    if pos + length > len(data):
        raise OtsError("truncated varbytes")
    return data[pos:pos + length], pos + length


def read_attestation(data, pos):
    """The attestation whose marker byte was just read: (kind, value, end).
    A known payload (pending, and the three block-header tags) is consumed
    to its last byte (2026-09-15/16 review F03: a byte after the height, or
    no height at all, used to pass); a pending URI is at most MAX_URI bytes
    of URI_CHARS; only Bitcoin is a usable attestation; every other tag,
    the Litecoin and Ethereum ones included, is kept as ("unknown", tag
    hex), which parses and is no usable attestation."""
    atag = data[pos:pos + 8]
    if len(atag) != 8:
        raise OtsError("truncated attestation tag")
    pos += 8
    payload, pos = read_varbytes(data, pos, MAX_ATTESTATION_PAYLOAD)
    if atag == PENDING_TAG:
        uri, end = read_varbytes(payload, 0, MAX_URI)
        if end != len(payload):
            raise OtsError("trailing bytes in the pending attestation")
        if any(b not in URI_CHARS for b in uri):
            raise OtsError("pending uri has a character outside the allowed set")
        return "pending", uri.decode("ascii"), pos
    if atag in HEIGHT_TAGS:
        height, end = read_varuint(payload, 0)
        if end != len(payload):
            raise OtsError("trailing bytes in the block header attestation")
        if atag == BITCOIN_TAG:
            return "bitcoin", height, pos
    return "unknown", atag.hex(), pos


def _apply_op(tag, msg, data, pos):
    """One operation on msg, within the public client's limits: (new msg, pos)."""
    if len(msg) > MAX_MSG:
        raise OtsError("message longer than %d bytes" % MAX_MSG)
    if tag == OP_SHA256:
        new = sha256(msg).digest()
    elif tag == OP_APPEND:
        operand, pos = read_varbytes(data, pos, MAX_OPERAND, min_len=1)
        new = msg + operand
    elif tag == OP_PREPEND:
        operand, pos = read_varbytes(data, pos, MAX_OPERAND, min_len=1)
        new = operand + msg
    else:
        raise OtsError("unsupported op 0x%02x" % tag)
    if len(new) > MAX_OPERAND:
        raise OtsError("result longer than %d bytes" % MAX_OPERAND)
    return new, pos


def parse_ots(data):
    """Read a linear detached proof: header, sha256 op, 32-byte digest, a
    chain of sha256/append/prepend ops, one attestation. Returns Proof with
    the message the attestation is about (the commitment) and the offset
    of the attestation marker (the splice point for an upgrade). Anything
    else — a fork marker, an op the calendar never emits, trailing bytes —
    is refused rather than guessed at."""
    if data[:len(OTS_MAGIC)] != OTS_MAGIC:
        raise OtsError("not an OpenTimestamps proof (bad magic)")
    pos = len(OTS_MAGIC)
    version, pos = read_varuint(data, pos)
    if version != OTS_VERSION:
        raise OtsError("unsupported proof version %d" % version)
    if pos >= len(data) or data[pos] != OP_SHA256:
        raise OtsError("file hash op is not sha256")
    pos += 1
    digest = data[pos:pos + 32]
    if len(digest) != 32:
        raise OtsError("truncated digest")
    pos += 32
    msg = digest
    ops = 0
    while True:
        if pos >= len(data):
            raise OtsError("truncated: no attestation")
        tag = data[pos]
        if tag == ATTESTATION_MARKER:
            ops_end = pos
            kind, value, pos = read_attestation(data, pos + 1)
            if pos != len(data):
                raise OtsError("trailing bytes after the attestation")
            return Proof(digest, msg, (kind, value), ops_end)
        if tag == FORK_MARKER:
            raise OtsError("non-linear timestamp (fork marker); use the ots client")
        msg, pos = _apply_op(tag, msg, data, pos + 1)
        ops += 1
        if ops > MAX_OPS_ON_A_PATH:
            raise OtsError("more than %d operations on one path" % MAX_OPS_ON_A_PATH)


def build_ots(digest, calendar_response):
    """The calendar's answer to a digest POST is the serialized timestamp of
    that digest; prefixing the detached-file header makes it a .ots file,
    byte-for-byte what the ots client writes for a single calendar."""
    ots = OTS_MAGIC + varuint(OTS_VERSION) + bytes([OP_SHA256]) + digest + calendar_response
    proof = parse_ots(ots)
    if proof.digest != digest:
        raise OtsError("digest mismatch while building the proof")
    return ots


def splice_upgrade(ots, calendar_response):
    """Replace a pending attestation with the calendar's timestamp of the
    commitment (its path up the anchor tree ending in a Bitcoin
    attestation). Refused unless the result is a complete, linear proof of
    the same digest."""
    proof = parse_ots(ots)
    if proof.attestation[0] != "pending":
        raise OtsError("proof is not pending")
    upgraded = ots[:proof.ops_end] + calendar_response
    new = parse_ots(upgraded)
    if new.attestation[0] != "bitcoin":
        raise OtsError("upgrade response carries no Bitcoin attestation")
    if new.digest != proof.digest:
        raise OtsError("digest changed by the upgrade")
    return upgraded


# The structural states of a proof on disk. None of them is verification:
# "verified" would mean the path from the digest was replayed to a merkle
# root and that root checked against the Bitcoin block header, which this
# adapter never does (the fork's claim kit and the ots client do).
BITCOIN_ATTESTATION_PRESENT = "bitcoin_attestation_present"   # an attestation node names a Bitcoin block
PENDING = "pending"                                           # only pending attestations: a calendar is still owed
INVALID = "invalid"                                           # not a whole proof, or not of this fingerprint


def proof_attestations(data):
    """Every attestation node of a detached proof, forks included (a proof
    the gateway upgraded keeps its pending attestation beside the Bitcoin
    path), once the whole file has been walked: (digest hex, [(kind,
    value), ...]). Raises OtsError, and only OtsError, on anything that is
    not one complete proof by the public client's rules: bad magic, an
    unknown op, truncation, trailing bytes, a payload not consumed whole,
    a limit exceeded.

    The walk is a loop, not a recursion: a timestamp is zero or more
    fork-marked branches then a last branch, and a branch is an operation
    followed by a timestamp, or an attestation. Every fork marker promises
    one more branch of the same timestamp after the branch it opens ends,
    so `pending` holds, per open fork, the message length and operation
    count the sibling branch resumes with; an attestation ends a branch,
    and the whole proof when no fork is open."""
    if data[:len(OTS_MAGIC)] != OTS_MAGIC:
        raise OtsError("not an OpenTimestamps proof (bad magic)")
    pos = len(OTS_MAGIC)
    version, pos = read_varuint(data, pos)
    if version != OTS_VERSION:
        raise OtsError("unsupported proof version %d" % version)
    if pos >= len(data) or data[pos] != OP_SHA256:
        raise OtsError("file hash op is not sha256")
    pos += 1
    digest = data[pos:pos + 32]
    if len(digest) != 32:
        raise OtsError("truncated digest")
    pos += 32
    out = []
    pending = []
    msg_len, ops, after_fork = 32, 0, False
    while True:
        if pos >= len(data):
            raise OtsError("truncated: no attestation")
        tag = data[pos]
        pos += 1
        if tag == FORK_MARKER:
            if after_fork:
                raise OtsError("a fork marker followed by another fork marker")
            pending.append((msg_len, ops))
            after_fork = True
            continue
        after_fork = False
        if tag == ATTESTATION_MARKER:
            kind, value, pos = read_attestation(data, pos)
            out.append((kind, value))
            if not pending:
                break
            msg_len, ops = pending.pop()
            continue
        if msg_len > MAX_MSG:
            raise OtsError("message longer than %d bytes" % MAX_MSG)
        if tag == OP_SHA256:
            msg_len = 32
        elif tag in (OP_APPEND, OP_PREPEND):
            operand, pos = read_varbytes(data, pos, MAX_OPERAND, min_len=1)
            msg_len += len(operand)
        else:
            raise OtsError("unsupported op 0x%02x" % tag)
        if msg_len > MAX_OPERAND:
            raise OtsError("result longer than %d bytes" % MAX_OPERAND)
        ops += 1
        if ops > MAX_OPS_ON_A_PATH:
            raise OtsError("more than %d operations on one path" % MAX_OPS_ON_A_PATH)
    if pos != len(data):
        raise OtsError("trailing bytes after the proof")
    return digest.hex(), out


def inspect_proof(data, fp=None):
    """(state, reason) for proof bytes, after a complete deserialisation:
    BITCOIN_ATTESTATION_PRESENT when an attestation node is a Bitcoin
    block-header attestation; PENDING when the only attestations are
    pending ones; INVALID otherwise, with the reason (bytes that are not
    one whole proof, a proof of another digest when fp is given, no usable
    attestation). Structural states only; see BITCOIN_ATTESTATION_PRESENT."""
    try:
        digest, attestations = proof_attestations(data)
    except OtsError as exc:
        return INVALID, str(exc).replace(" ", "_")
    if fp is not None and digest != fp:
        return INVALID, "digest"
    kinds = {kind for kind, _ in attestations}
    if "bitcoin" in kinds:
        return BITCOIN_ATTESTATION_PRESENT, "bitcoin"
    if "pending" in kinds:
        return PENDING, "pending"
    return INVALID, "no_usable_attestation"


def bitcoin_attestation_present(data):
    """True when the bytes are one whole proof with a Bitcoin block-header
    attestation node. A structural fact about the file, not a verification
    against Bitcoin."""
    return inspect_proof(data)[0] == BITCOIN_ATTESTATION_PRESENT

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

    # The shape: exactly one of the two doors. GATEWAY_URL is the hosted
    # shape (an L402 timestamp gateway, paid or free door); CALENDAR_URL is
    # the appliance shape (the box's own calendar, submitted to directly,
    # nothing paid anywhere).
    gateway = get("GATEWAY_URL")
    calendar = get("CALENDAR_URL")
    if gateway and calendar:
        raise ConfigError(
            "set exactly one of GATEWAY_URL and CALENDAR_URL — both are set; "
            "GATEWAY_URL is the hosted shape (an L402 timestamp gateway), "
            "CALENDAR_URL the appliance shape (the box's own calendar)"
        )
    if not gateway and not calendar:
        raise ConfigError(
            "set GATEWAY_URL, e.g. http://127.0.0.1:8000 — the L402 timestamp "
            "gateway this box buys proofs from (hosted shape) — or "
            "CALENDAR_URL, e.g. http://127.0.0.1:14788 — the calendar this box "
            "submits to directly (appliance shape); exactly one"
        )
    mode = "calendar" if calendar else "gateway"
    # The appliance defaults (2026-09-11): eight submissions in the air and
    # one upgrade pass an hour (each pass is one loopback GET per pending
    # proof). The hosted defaults are unchanged: serial, ten minutes.
    inflight_default = "8" if mode == "calendar" else "1"
    upgrade_secs_default = "3600" if mode == "calendar" else "600"

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
        # Finite as well as positive: float() reads 'inf', and time.sleep
        # refuses it later, outside the worker's catch (2026-09-18 cold
        # review R19).
        if not (math.isfinite(v) and v > 0):
            raise ConfigError(f"{key} must be a positive, finite number of seconds, got {raw!r}")
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
        "mode": mode,
        "gateway_url": gateway.rstrip("/") if gateway else None,
        "calendar_url": calendar.rstrip("/") if calendar else None,
        "phoenixd_url": get("PHOENIXD_URL", "http://127.0.0.1:9740").rstrip("/"),
        "phoenix_conf": get("PHOENIX_CONF",
                            os.path.expanduser("~/.phoenix/phoenix.conf")),
        "max_price_sats": uint("MAX_PRICE_SATS", "5000"),
        "daily_budget_sats": uint("DAILY_BUDGET_SATS", "200000"),
        "poll_secs": secs("POLL_SECS", "2"),
        "upgrade_secs": secs("UPGRADE_SECS", upgrade_secs_default),
        "heartbeat_secs": secs("HEARTBEAT_SECS", "10"),
        "l402_expiry_secs": secs("L402_EXPIRY_SECS", "3600"),
        # J9 (2026-09-08): a paid-but-unredeemed sidecar is retried every
        # pass this many times, then marked needs-attention and retried
        # once per redeem_attention_retry_secs — never dropped, never
        # re-paid, and no longer one log line per pass forever.
        "redeem_attempts_max": pint("REDEEM_ATTEMPTS_MAX", "300"),
        "redeem_attention_retry_secs": secs("REDEEM_ATTENTION_RETRY_SECS", "3600"),
        "breaker_failures": uint("CIRCUIT_BREAKER_FAILURES", "5"),
        "breaker_pause_secs": secs("CIRCUIT_BREAKER_PAUSE_SECS", "60"),
        "inflight": pint("INFLIGHT", inflight_default),
        # The upgrader's own window; defaults to INFLIGHT.
        "upgrade_inflight": pint("UPGRADE_INFLIGHT",
                                 get("INFLIGHT", inflight_default) or inflight_default),
        # Presented as a bearer on /upgrade so the gateway lifts its per-peer
        # throttle for this client (its UPGRADE_CLIENT_TOKEN). Unset = anonymous.
        "gateway_upgrade_token": get("GATEWAY_UPGRADE_TOKEN") or None,
        "log_cap_bytes": uint("LOG_CAP_BYTES", str(16 * 1024 * 1024)),
        "data_dir": data_dir,
        "debts_dir": os.path.join(data_dir, "debts"),
        "proofs_dir": os.path.join(data_dir, "proofs"),
        "pending_dir": os.path.join(data_dir, "pending"),
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
    never secrets, never gateway or phoenixd URLs.

    Rotation: once the log has reached LOG_CAP_BYTES, the next event renames
    it to `log.1` (replacing any previous `.1`) and starts a fresh `log`; one
    generation is kept. 0 disables rotation."""
    parts = [utc_now_iso(), event] + [f"{k}={v}" for k, v in kv.items()]
    with _LOG_LOCK:
        try:
            cap = cfg.get("log_cap_bytes", 0)
            if cap:
                try:
                    if os.path.getsize(cfg["log_path"]) >= cap:
                        os.replace(cfg["log_path"], cfg["log_path"] + ".1")
                except FileNotFoundError:
                    pass
            with open(cfg["log_path"], "a", encoding="utf-8") as f:
                f.write(" ".join(parts) + "\n")
        except OSError:
            pass  # a failing log must never take down intake or buying


# durable writes
def fsync_dir(path):
    """fsync a directory so a new entry or a rename is durable. Raises: a
    directory that cannot be synced is a failure the caller must see (the
    2026-09-15 review found a swallowed EIO reported as success)."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def fsync_existing(path):
    """fsync a file found on disk, then its directory. Existence is
    visibility, not durability: the write that made the file may have
    stopped, or failed, at its barrier, and this process cannot tell. A
    pass that acts on a file it finds (acknowledges the debt, clears the
    debt behind the proof, clears the marker behind the upgrade) repeats
    the barrier first, under the fingerprint's lock, and does not act if
    the barrier fails again (2026-09-18 cold review R02: the retry used to
    take the file's presence for the barrier having held). Raises OSError."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(os.path.dirname(path) or ".")


def write_all(fd, data):
    """Every byte, or an error: os.write may write less than it was given."""
    view = memoryview(data)
    while len(view):
        n = os.write(fd, view)
        if n <= 0:
            raise OSError(5, "write made no progress")
        view = view[n:]


# One lock per fingerprint: intake holds it from the debt's creation through
# its directory fsync; the buyer holds it over the marker, proof and debt
# transition; the upgrader takes it, without waiting, before it drops a
# marker whose proof is absent. Locks are never removed: one small object
# per fingerprint this process has seen.
_FP_LOCKS = {}
_FP_LOCKS_GUARD = threading.Lock()


def fp_lock(fp):
    with _FP_LOCKS_GUARD:
        lock = _FP_LOCKS.get(fp)
        if lock is None:
            lock = _FP_LOCKS[fp] = threading.Lock()
        return lock


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


def proof_digest(data):
    """The digest a detached proof is about (64 hex), or None when the bytes
    do not carry one: magic, version 1, the sha256 file-hash op (0x08), then
    the 32-byte digest — the layout the ots client writes. A proof is only
    ever stored here when this equals the fingerprint that was asked for."""
    head = len(OTS_MAGIC)
    if not data.startswith(OTS_MAGIC) or len(data) < head + 2 + 32:
        return None
    if data[head] != 0x01 or data[head + 1] != 0x08:
        return None
    return data[head + 2:head + 34].hex()


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


def http_get(url, timeout, headers=None):
    """GET returning (status, headers, body_bytes); 4xx/5xx are returned,
    not raised; only transport failures raise Unreachable."""
    req = urllib.request.Request(url, headers=dict(headers or {}), method="GET")
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
    headers = {"Content-Type": "application/json"}
    if cfg.get("gateway_upgrade_token"):
        headers["Authorization"] = "Bearer " + cfg["gateway_upgrade_token"]
    return http_post(cfg["gateway_url"] + "/upgrade", body.encode(), headers,
                     timeout=60)


# The appliance shape: the calendar protocol (opentimestamps-server fork,
# otsserver/rpc.py), spoken directly. Both functions answer in the shape
# their gateway counterparts answer, so everything after the transport —
# the proof_digest refusal, the pending marker, the atomic write, clear_debt,
# _apply_upgrade — is the same code in both shapes.
def calendar_submit(cfg, fp):
    """POST the 32 raw digest bytes to the calendar's counted door, /digest
    (never the operator lane, /operator/digest, which is the self-stamper's
    and is not a record), and turn the serialized pending timestamp it
    answers into the detached proof. Returns the (status, headers, body)
    triple gateway_challenge returns: on 200 the body is the proof, which
    _buy_challenged stores exactly as a free-door answer. An answer that is
    not a pending timestamp of this digest is logged
    calendar_answer_rejected and returned with an empty body, which
    _buy_challenged treats as challenge_failed: the debt stays and the next
    pass asks again. 503 (the aggregator wedged or gone) ends the pass as a
    gateway 503 does."""
    digest = bytes.fromhex(fp)
    status, headers, body = http_post(cfg["calendar_url"] + "/digest", digest,
                                      {"Content-Type": "application/octet-stream"},
                                      timeout=60)
    if status != 200:
        return status, headers, body
    try:
        ots = build_ots(digest, body)
        if parse_ots(ots).attestation[0] != "pending":
            raise OtsError("answer carries no pending attestation")
    except OtsError as exc:
        log_event(cfg, "calendar_answer_rejected", fp=fp,
                  reason=str(exc).replace(" ", "_"))
        return 200, headers, b""
    return 200, headers, ots


def calendar_upgrade(cfg, fp, ots_bytes):
    """Walk the pending proof to its commitment, ask the calendar for that
    commitment's timestamp (GET /timestamp/<hex>: 404 while pending, the
    path to the Bitcoin attestation once the anchor is deep) and splice it
    in. Returns the (status, headers, body) triple gateway_upgrade returns,
    with the JSON body _apply_upgrade already parses: pending, or anchored
    with the upgraded bytes. A proof this adapter cannot walk (a fork
    marker: several attestation paths, which a proof from one calendar
    never has) answers status "nonlinear"; an answer that does not splice
    answers "calendar_answer_rejected"; both land in
    upgrade_needs_attention with the marker kept."""
    def answer(obj):
        return 200, {}, json.dumps(obj).encode()

    try:
        proof = parse_ots(ots_bytes)
    except OtsError as exc:
        return answer({"status": "nonlinear" if "fork" in str(exc) else "invalid",
                       "bitcoin_anchored": False, "ots": None})
    if proof.attestation[0] == "bitcoin":
        return answer({"status": "anchored", "bitcoin_anchored": True,
                       "ots": base64.b64encode(ots_bytes).decode("ascii")})
    if proof.attestation[0] != "pending":
        return answer({"status": "no_attestations", "bitcoin_anchored": False,
                       "ots": None})
    status, headers, body = http_get(
        cfg["calendar_url"] + "/timestamp/" + proof.commitment.hex(), timeout=60)
    if status == 404:
        return answer({"status": "pending", "bitcoin_anchored": False,
                       "ots": base64.b64encode(ots_bytes).decode("ascii")})
    if status != 200:
        return status, headers, body
    try:
        upgraded = splice_upgrade(ots_bytes, body)
    except OtsError as exc:
        log_event(cfg, "calendar_answer_rejected", fp=fp,
                  reason=str(exc).replace(" ", "_"))
        return answer({"status": "calendar_answer_rejected",
                       "bitcoin_anchored": False, "ots": None})
    return answer({"status": "anchored", "bitcoin_anchored": True,
                   "ots": base64.b64encode(upgraded).decode("ascii")})


def submit_record(cfg, fp):
    """One submission, by shape: the gateway's /timestamp or the calendar's
    counted /digest."""
    if cfg["mode"] == "calendar":
        return calendar_submit(cfg, fp)
    return gateway_challenge(cfg, fp)


def upgrade_proof(cfg, fp, ots_bytes):
    """One upgrade ask, by shape: the gateway's /upgrade or the calendar's
    /timestamp/<commitment>."""
    if cfg["mode"] == "calendar":
        return calendar_upgrade(cfg, fp, ots_bytes)
    return gateway_upgrade(cfg, fp, ots_bytes)


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


def decode_invoice(cfg, password, bolt11):
    """(sats, payment_hash) from phoenixd's /decodeinvoice; either is None
    when it could not be read — never pay an amount that could not be read,
    never reconcile against a hash that was not the invoice's own."""
    d = phoenixd_call(cfg, password, "/decodeinvoice", bolt11, timeout=15)
    sats = amount_sats_from_decoded(d)
    h = d.get("paymentHash") if isinstance(d, dict) else None
    if isinstance(h, str) and HEX64.fullmatch(h.lower()):
        return sats, h.lower()
    return sats, None


def decode_invoice_sats(cfg, password, bolt11):
    """None on any failure — never pay an amount that could not be read."""
    return decode_invoice(cfg, password, bolt11)[0]


def wallet_payment_outcome(cfg, password, payment_hash):
    """What the wallet says became of an attempt to pay payment_hash, from
    GET /payments/outgoingbyhash/{hash} (phoenixd 0.8.0 and 0.9.1: the best
    record for that hash, 204 when there is none). Returns
    ("paid", preimage)  — isPaid true with a 64-hex preimage whose sha256 is
                          the hash;
    ("failed", None)    — 204 (phoenixd records an outgoing payment before
                          it sends, so no record means it never sent), or a
                          completed record that is not paid;
    ("unknown", None)   — a record still in flight, or an answer that is
                          neither. Transport failures raise Unreachable."""
    tok = base64.b64encode(b":" + password.encode()).decode("ascii")
    status, _, body = http_get(cfg["phoenixd_url"] + "/payments/outgoingbyhash/" + payment_hash,
                               timeout=20, headers={"Authorization": "Basic " + tok})
    if status == 204:
        return "failed", None
    if status != 200:
        return "unknown", None
    try:
        d = json.loads(body)
    except ValueError:
        return "unknown", None
    if not isinstance(d, dict):
        return "unknown", None
    p = d.get("preimage")
    if d.get("isPaid") is True and isinstance(p, str) and HEX64.fullmatch(p.lower()) \
            and sha256(bytes.fromhex(p)).hexdigest() == payment_hash:
        return "paid", p.lower()
    if d.get("isPaid") is False and d.get("completedAt") is not None:
        return "failed", None
    return "unknown", None


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
    """Create the debt durably: the file's bytes fsynced, then its
    directory. True if newly created, False if the fingerprint was already
    owed. The fingerprint's lock is held from creation through the
    directory fsync, so a duplicate request is answered only once the
    original is durable or gone: filename existence alone is never an
    acknowledgement. A debt that cannot be made durable (a write, file
    fsync or directory fsync error) is removed if it can be and the error
    raised; the door answers 500: acceptance not confirmed, retry safely,
    a debt may nonetheless remain. A debt found already on file is
    fsynced again, with its directory, before it is answered as owed: the
    file may be the remainder of a 500 whose barrier and whose cleanup
    both failed, and a retry that acknowledged it by its presence promised
    what nothing had made durable (2026-09-18 cold review R02). Must
    complete before 'received' goes out — the debt is the promise."""
    path = debt_path(cfg, fp)
    with fp_lock(fp):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            fsync_existing(path)
            return False
        try:
            try:
                write_all(fd, (fp + "\n").encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            fsync_dir(cfg["debts_dir"])
        except OSError:
            # The removal can fail too. Then a debt file remains behind a
            # 500: the buyer meets it and a retry is answered as owed,
            # which is the safe direction. Logged, so the state is seen;
            # the 500 promises only that acceptance was not confirmed
            # (docs/contracts.md, "What an HTTP success promises").
            try:
                os.unlink(path)
            except OSError as exc:
                log_event(cfg, "debt_cleanup_failed", fp=fp, err=type(exc).__name__)
            raise
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


# pending index: DATA_DIR/pending/<fp>, one empty marker per proof that still
# waits for its Bitcoin attestation. The marker is written BEFORE the proof
# (a proof without a marker would never be upgraded; a marker without a proof
# is dropped by the upgrader) and removed once the anchored bytes are on disk.
# The upgrader lists this directory instead of reading every proof file.
def pending_path(cfg, fp):
    return os.path.join(cfg["pending_dir"], fp)


def pending_mark(cfg, fp):
    """Create the marker and fsync its directory. Raises OSError: a marker
    that is not on disk means a proof nothing would ever upgrade, so the
    caller must not store the proof (store_proof)."""
    fd = os.open(pending_path(cfg, fp), os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(fd)
    fsync_dir(cfg["pending_dir"])


def store_proof(cfg, fp, data):
    """The one transition from owed to proof-on-disk, under the
    fingerprint's lock: the pending marker (fsynced with its directory),
    then the proof (atomic, fsynced), then the debt cleared. A marker that
    cannot be created is fatal to the completion: nothing is stored, the
    debt stays, `cannot_mark_pending` is logged and the next pass asks
    again. Returns True when the proof is on disk and the debt cleared."""
    with fp_lock(fp):
        try:
            pending_mark(cfg, fp)
        except OSError as exc:
            log_event(cfg, "cannot_mark_pending", fp=fp, err=type(exc).__name__)
            return False
        atomic_write(proof_path(cfg, fp), data)
        clear_debt(cfg, fp)
    return True


def proof_on_disk(cfg, fp):
    """True when a whole proof of fp is stored (INVALID bytes do not count:
    they are what the reconciliation sets aside)."""
    try:
        with open(proof_path(cfg, fp), "rb") as f:
            data = f.read()
    except OSError:
        return False
    return inspect_proof(data, fp)[0] != INVALID


def _drop_stale_marker(cfg, fp):
    """A marker whose proof is absent is dropped only when nothing can
    still write that proof: no debt, no sidecar, and no buyer mid-way (the
    fingerprint's lock is taken without waiting; held means in flight).
    The 2026-09-15 review's race: the upgrader dropped the marker between
    the buyer's marker and its proof write, stranding the proof forever."""
    lock = fp_lock(fp)
    if not lock.acquire(blocking=False):
        return
    try:
        if os.path.exists(proof_path(cfg, fp)) or os.path.exists(debt_path(cfg, fp)) \
                or os.path.exists(sidecar_path(cfg, fp)):
            return
        pending_clear(cfg, fp)
        log_event(cfg, "stale_marker_dropped", fp=fp)
    finally:
        lock.release()


def pending_clear(cfg, fp):
    try:
        os.unlink(pending_path(cfg, fp))
    except OSError:
        pass


def list_pending(cfg):
    """The fingerprints in the pending index. Raises OSError when the
    directory cannot be listed: work that cannot be seen is not no work
    (2026-09-18 cold review R16: the error used to read as an empty index,
    and the upgrader's pass ended as if nothing were pending). The
    upgrader's loop logs the error and asks again next pass; the start
    fails on it."""
    return sorted(n for n in os.listdir(cfg["pending_dir"]) if HEX64.fullmatch(n))


PENDING_BUILT = ".built"


def build_pending_index(cfg):
    """One scan of the proofs directory (a DATA_DIR from before the index):
    every pending proof gets a marker. Idempotent — a crash mid-scan leaves
    the .built flag absent and the next pass scans again. Returns (pending,
    scanned)."""
    pending = scanned = 0
    for fp in list_proofs(cfg):
        scanned += 1
        try:
            with open(proof_path(cfg, fp), "rb") as f:
                data = f.read()
        except OSError:
            continue
        if inspect_proof(data, fp)[0] == PENDING:
            try:
                pending_mark(cfg, fp)
            except OSError as exc:
                log_event(cfg, "cannot_mark_pending", fp=fp, err=type(exc).__name__)
                continue
            pending += 1
    fd = os.open(os.path.join(cfg["pending_dir"], PENDING_BUILT),
                 os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(fd)
    fsync_dir(cfg["pending_dir"])
    return pending, scanned


def reconcile_state(cfg):
    """Every start, before any thread: the debts, the proofs and the
    pending index are made to agree, so an installation stranded by the
    marker race or by a header-only "proof" (both possible before
    2026-09-15, .built or not) is repaired. Each proof is deserialised
    whole: a PENDING proof without a marker gets one back
    (`pending_marker_restored`); a proof with a Bitcoin attestation loses a
    stale marker; INVALID bytes get their debt re-created first and are
    then set aside as <fp>.ots.invalid-<time>, so the buyer fetches a
    proper proof (`proof_invalid_requeued`); an aside file left alone by
    an earlier version gets its debt back (`aside_requeued`). A marker
    with neither proof nor debt nor sidecar is dropped. A data directory
    from before the index (.built absent) gets its markers here, logged
    once as `pending_index_built`. Every step is idempotent: a stop
    anywhere leaves a state the next start repairs the same way. Returns
    the counts."""
    counts = collections.Counter()
    first_index = not os.path.exists(os.path.join(cfg["pending_dir"], PENDING_BUILT))
    scanned = pending = 0
    for fp in list_proofs(cfg):
        scanned += 1
        path = proof_path(cfg, fp)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            counts["unreadable"] += 1
            continue
        state, reason = inspect_proof(data, fp)
        marked = os.path.exists(pending_path(cfg, fp))
        if state == BITCOIN_ATTESTATION_PRESENT:
            if marked:
                pending_clear(cfg, fp)
                counts["markers_cleared"] += 1
        elif state == PENDING:
            pending += 1
            if not marked:
                pending_mark(cfg, fp)
                if not first_index:
                    log_event(cfg, "pending_marker_restored", fp=fp)
                    counts["markers_restored"] += 1
        else:
            # The debt first: it is the promise, made durable (file and
            # directory fsynced) before the bytes that failed to be a
            # proof are moved out of the way. A stop or a failed write
            # between the two leaves the invalid proof in place, found
            # again next start; never an aside file alone (2026-09-15/16
            # review F01).
            write_debt(cfg, fp)
            aside = path + ".invalid-%d" % int(time.time())
            os.replace(path, aside)
            pending_clear(cfg, fp)
            log_event(cfg, "proof_invalid_requeued", fp=fp, reason=reason)
            counts["invalid_requeued"] += 1
    # An aside file with neither a proof nor a debt for its fingerprint:
    # the code before 2026-09-16 moved the bytes before it wrote the debt
    # and stopped between the two. The bytes were once stored as this
    # fingerprint's proof, so the record was acknowledged; the debt is
    # recreated and the buyer fetches a proper proof.
    for fp in sorted({name[:64] for name in os.listdir(cfg["proofs_dir"])
                      if HEX64.fullmatch(name[:64]) and name[64:].startswith(".ots.invalid-")}):
        if not (os.path.exists(proof_path(cfg, fp)) or os.path.exists(debt_path(cfg, fp))):
            write_debt(cfg, fp)
            log_event(cfg, "aside_requeued", fp=fp)
            counts["aside_requeued"] += 1
    for fp in list_pending(cfg):
        if not (os.path.exists(proof_path(cfg, fp)) or os.path.exists(debt_path(cfg, fp))
                or os.path.exists(sidecar_path(cfg, fp))):
            pending_clear(cfg, fp)
            counts["stale_markers_dropped"] += 1
    fsync_dir(cfg["pending_dir"])
    fsync_dir(cfg["proofs_dir"])
    fd = os.open(os.path.join(cfg["pending_dir"], PENDING_BUILT), os.O_WRONLY | os.O_CREAT, 0o600)
    os.close(fd)
    fsync_dir(cfg["pending_dir"])
    if first_index:
        # A data directory from before the index: this was its one scan.
        log_event(cfg, "pending_index_built", pending=pending, scanned=scanned)
    return dict(counts)


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


def write_sidecar(path, macaroon, invoice, preimage=None, attempts=0, attention=None,
                  payment_hash=None, amount_sats=None):
    """The in-flight purchase record. payment_hash and amount_sats (since
    2026-09-15) are the invoice's own, decoded by phoenixd, so a retry can
    ask the wallet what became of the payment and reserve the amount again;
    attempts counts definite redeem refusals of a paid preimage; attention
    is the UTC time the ceiling was reached (the operator's signal: the box
    holds a paid, unredeemed proof)."""
    d = {"macaroon": macaroon, "invoice": invoice}
    if isinstance(payment_hash, str):
        d["payment_hash"] = payment_hash
    if isinstance(amount_sats, int) and not isinstance(amount_sats, bool):
        d["amount_sats"] = amount_sats
    if preimage:
        d["preimage"] = preimage
    if attempts:
        d["attempts"] = attempts
    if attention:
        d["attention"] = attention
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


def _redeem(cfg, fp, macaroon, preimage, amt, flags, sidecar=None):
    """sidecar is the stored in-flight record when this is a retry of a paid
    preimage; a definite refusal is counted on it (J9)."""
    try:
        status, headers, body = gateway_redeem(cfg, fp, macaroon, preimage)
    except Unreachable:
        return _mark_down(cfg, flags, "gateway")
    _mark_up(cfg, flags, "gateway")
    if status == 200:
        if looks_like_ots(body):
            state, reason = inspect_proof(body, fp)
            if state == INVALID and reason == "digest":
                # A proof of somebody else's digest is not ours to store: the
                # sidecar keeps the preimage and the next pass asks again.
                log_event(cfg, "proof_wrong_digest", fp=fp, note="paid",
                          got=(proof_digest(body) or "none")[:12])
                return True
            if state == INVALID:
                # Bytes that are not one whole proof: never stored, the
                # sidecar keeps the preimage and the next pass asks again.
                log_event(cfg, "proof_invalid", fp=fp, note="paid", reason=reason)
                return True
            if not store_proof(cfg, fp, body):
                return True
            flags["attention"].discard(fp)
            log_event(cfg, "bought", fp=fp,
                      sats=amt if amt is not None else "unknown", state=state)
            return True
        log_event(cfg, "redeem_failed", fp=fp, status=status,
                  note="body_not_ots_paid_but_unredeemed")
        return True
    if status == 429:
        wait = _retry_after_secs(headers)
        flags["retry_at"][0] = time.time() + wait
        log_event(cfg, "rate_limited", wait_secs=wait)
        return False
    # Paid but not redeemed. The sidecar (macaroon + preimage) stays — the
    # gateway's rule is that settlement outranks expiry — and is retried
    # every pass up to REDEEM_ATTEMPTS_MAX definite refusals, then once per
    # REDEEM_ATTENTION_RETRY_SECS under a needs-attention mark. A 503 is
    # the gateway saying "not now", not a refusal: it ends the pass and
    # counts nothing.
    if status == 503:
        log_event(cfg, "redeem_failed", fp=fp, status=status, note="paid_but_unredeemed")
        return False
    attempts = (sidecar or {}).get("attempts", 0)
    attempts = attempts + 1 if isinstance(attempts, int) else 1
    attention = (sidecar or {}).get("attention") if sidecar else None
    if attention is None and attempts >= cfg["redeem_attempts_max"]:
        attention = utc_now_iso()
        log_event(cfg, "redeem_needs_attention", fp=fp, status=status, attempts=attempts,
                  note="paid_preimage_kept_retry_every_%ds" % cfg["redeem_attention_retry_secs"])
    elif attention is None:
        log_event(cfg, "redeem_failed", fp=fp, status=status, note="paid_but_unredeemed")
    if sidecar is not None:
        try:
            write_sidecar(sidecar_path(cfg, fp), macaroon, sidecar.get("invoice", ""),
                          preimage, attempts=attempts, attention=attention,
                          payment_hash=sidecar.get("payment_hash"), amount_sats=sidecar.get("amount_sats"))
        except OSError:
            log_event(cfg, "cannot_write_sidecar", fp=fp)
    return True


def _pay_and_redeem(cfg, password, fp, macaroon, invoice, amt, flags, payment_hash=None):
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
        write_sidecar(sidecar_path(cfg, fp), macaroon, invoice, preimage,
                      payment_hash=payment_hash, amount_sats=amt)
    except OSError:
        # Still redeem now; if that fails too, the retry path re-pays this
        # same stored invoice and phoenixd's own dedupe is the last line.
        log_event(cfg, "cannot_write_sidecar", fp=fp)
    return _redeem(cfg, fp, macaroon, preimage, amt, flags)


def finish_sidecar(cfg, password, fp, sc, age, flags):
    """Resume an in-flight purchase after a crash or failed attempt. With a
    preimage: redeem only — never pay again. Without one: the wallet is
    asked first what became of the payment (settled: redeem with its
    preimage, no payment, no reservation; unknown: wait); only a
    definitely unpaid invoice is paid again, and it reserves TODAY's budget
    before the payinvoice call — the budget counts every call, not every
    invoice (2026-09-15 review, A7: an invoice reserved yesterday could
    settle today with today's whole budget still open). The STORED invoice
    is re-paid, never a fresh challenge, until L402_EXPIRY_SECS; then the
    challenge is abandoned loudly (the one edge where a double charge cannot
    be ruled out)."""
    macaroon, invoice, preimage = sc.get("macaroon"), sc.get("invoice"), sc.get("preimage")

    if isinstance(preimage, str) and isinstance(macaroon, str):
        if sc.get("attention") and age < cfg["redeem_attention_retry_secs"]:
            # At the ceiling: the paid preimage waits, quietly, for its
            # hourly retry (age is the sidecar's mtime, rewritten on every
            # counted refusal).
            flags["attention"].add(fp)
            return True
        return _redeem(cfg, fp, macaroon, preimage, None, flags, sidecar=sc)

    if isinstance(macaroon, str) and isinstance(invoice, str):
        if age <= cfg["l402_expiry_secs"]:
            return _retry_stored_invoice(cfg, password, fp, sc, macaroon, invoice, flags)
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


def _retry_stored_invoice(cfg, password, fp, sc, macaroon, invoice, flags):
    """A sidecar holding an invoice and no preimage: this process does not
    know whether the earlier payinvoice call settled. The wallet does."""
    payment_hash = sc.get("payment_hash") if isinstance(sc.get("payment_hash"), str) else None
    amt = sc.get("amount_sats")
    if not isinstance(amt, int) or isinstance(amt, bool):
        amt = None
    if payment_hash is None or amt is None:
        # A sidecar from before 2026-09-15 carries neither: read them off the
        # stored invoice itself.
        try:
            decoded_amt, decoded_hash = decode_invoice(cfg, password, invoice)
        except Unreachable:
            return _mark_down(cfg, flags, "phoenixd")
        _mark_up(cfg, flags, "phoenixd")
        amt = amt if amt is not None else decoded_amt
        payment_hash = payment_hash or decoded_hash
        if payment_hash is None or amt is None:
            if fp not in flags["corrupt_logged"]:
                flags["corrupt_logged"].add(fp)
                log_event(cfg, "sidecar_needs_attention", fp=fp, note="stored_invoice_undecodable")
            return True
    try:
        outcome, preimage = wallet_payment_outcome(cfg, password, payment_hash)
    except Unreachable:
        return _mark_down(cfg, flags, "phoenixd")
    _mark_up(cfg, flags, "phoenixd")
    if outcome == "paid":
        # Settled at the wallet, answer lost: the preimage is stored and
        # redeemed; nothing is paid and nothing reserved.
        try:
            write_sidecar(sidecar_path(cfg, fp), macaroon, invoice, preimage,
                          payment_hash=payment_hash, amount_sats=amt)
        except OSError:
            log_event(cfg, "cannot_write_sidecar", fp=fp)
        log_event(cfg, "payment_reconciled", fp=fp, sats=amt, note="settled_at_wallet")
        flags["corrupt_logged"].discard(fp)
        return _redeem(cfg, fp, macaroon, preimage, amt, flags, sidecar=sc)
    if outcome == "unknown":
        # Still in flight, or the wallet could not say: wait; never pay
        # again on a guess.
        if fp not in flags["corrupt_logged"]:
            flags["corrupt_logged"].add(fp)
            log_event(cfg, "payment_outcome_unknown", fp=fp, sats=amt, note="awaiting_wallet")
        return True
    flags["corrupt_logged"].discard(fp)
    # Definitely unpaid: this retry is a payinvoice call, so it reserves
    # today's budget first — the same preflight, ceiling and reservation as
    # a fresh challenge, against today's ledger.
    verdict, day, spent = _budget_preflight(cfg, flags)
    if verdict != "ok":
        return verdict == "skip"
    today = utc_today()
    already = spent if day == today else 0
    remaining = cfg["daily_budget_sats"] - already
    if amt > remaining:
        log_event(cfg, "skip", fp=fp, reason="exceeds_daily_budget", amt=amt, remaining=remaining,
                  note="retry_of_stored_invoice")
        return True
    try:
        write_ledger(cfg["ledger_path"], today, already + amt)
    except OSError:
        log_event(cfg, "cannot_write_ledger", fp=fp)
        return False
    log_event(cfg, "payment_retry_reserved", fp=fp, sats=amt)
    return _pay_and_redeem(cfg, password, fp, macaroon, invoice, amt, flags, payment_hash=payment_hash)


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
    if proof_on_disk(cfg, fp):
        # One record, one payment, one proof: a re-POSTed or already-bought
        # fingerprint costs nothing. Only a whole proof of this fingerprint
        # counts; INVALID bytes are the reconciliation's to set aside. The
        # proof is on disk, not known to be durable: the pass that wrote it
        # may have failed at its directory fsync and left the debt for this
        # reason. The barrier is repeated before the debt goes; if it fails
        # again the debt stays and the next pass asks again.
        with fp_lock(fp):
            try:
                fsync_existing(proof_path(cfg, fp))
            except OSError as exc:
                log_event(cfg, "proof_sync_failed", fp=fp, err=type(exc).__name__)
                return True
            clear_debt(cfg, fp)
        log_event(cfg, "already_bought", fp=fp)
        return True

    sc, age = load_sidecar(sidecar_path(cfg, fp))
    if sc is not None:
        if cfg["mode"] == "calendar":
            # A purchase left in flight by a gateway-mode life of this
            # DATA_DIR. Nothing here can pay or redeem it: the debt waits,
            # logged once, for the operator to settle or remove the sidecar
            # (README, "Switching shapes").
            if fp not in flags["corrupt_logged"]:
                flags["corrupt_logged"].add(fp)
                log_event(cfg, "sidecar_needs_attention", fp=fp,
                          note="left_by_gateway_mode")
            return True
        return finish_sidecar(cfg, password, fp, sc, age, flags)

    verdict, day, spent = _budget_preflight(cfg, flags)
    if verdict != "ok":
        return verdict == "skip"  # "stop" ends the pass; "skip" keeps the debt

    try:
        status, headers, body = submit_record(cfg, fp)
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
        # (L402_ENABLED=false), or the calendar's answer. The bytes are
        # deserialised whole and their attestation nodes inspected before
        # anything is stored or the debt touched.
        state, reason = inspect_proof(body, fp)
        if state == INVALID and reason == "digest":
            log_event(cfg, "proof_wrong_digest", fp=fp, note="free",
                      got=(proof_digest(body) or "none")[:12])
            return True  # the debt stays; the next pass asks again
        if state == INVALID:
            log_event(cfg, "proof_invalid", fp=fp, note="free", reason=reason)
            return True  # the debt stays; the next pass asks again
        if not store_proof(cfg, fp, body):
            return True
        log_event(cfg, "proof_free", fp=fp, state=state)
        return True
    if status == 429:
        wait = _retry_after_secs(headers)
        flags["retry_at"][0] = time.time() + wait
        log_event(cfg, "rate_limited", wait_secs=wait)
        return False
    if status == 402 and cfg["mode"] == "calendar":
        # A calendar never asks for payment: a 402 means CALENDAR_URL points
        # at a gateway. Refused here, before any payment machinery; the
        # debt stays.
        log_event(cfg, "challenge_failed", fp=fp, status=402,
                  note="calendar_answered_402")
        return True
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
        amt, payment_hash = decode_invoice(cfg, password, invoice)
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
        write_sidecar(sidecar_path(cfg, fp), macaroon, invoice,
                      payment_hash=payment_hash, amount_sats=amt)
    except OSError:
        log_event(cfg, "cannot_write_sidecar", fp=fp)
        return False
    return _pay_and_redeem(cfg, password, fp, macaroon, invoice, amt, flags, payment_hash=payment_hash)


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
    is owed again next pass, unpaid and unreserved."""
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
                if proof_on_disk(cfg, fp):
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
                outstanding[pool.submit(submit_record, cfg, fp)] = (fp, day, spent)
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
        "attention": set(),   # fps whose paid preimage sits at the redeem ceiling
        "corrupt_logged": set(),
        # The circuit breaker lives in memory only, by design: a process
        # killed while paused starts closed and re-trips if the fault holds.
        "breaker": {"failures": 0, "open": False, "wait": 0.0, "until": 0.0},
    }
    hb["breaker"] = flags["breaker"]  # the heartbeat reports open/closed
    hb["attention"] = flags["attention"]  # ... and how many paid proofs wait at the ceiling
    while True:
        hb["buyer"] = time.time()
        try:
            buyer_pass(cfg, password, flags)
        except Exception as e:  # the loop must survive anything
            log_event(cfg, "buyer_error", err=type(e).__name__)
        time.sleep(cfg["poll_secs"])


# the upgrader
def _apply_upgrade(cfg, fp, path, body):
    """One /upgrade answer for fp. The file is replaced only when the
    response says bitcoin_anchored and the returned bytes, deserialised
    whole, carry a Bitcoin attestation node and are a proof of this
    fingerprint; the marker is cleared after those bytes are on disk and
    `bitcoin_attestation_present` is logged. True when that happened."""
    try:
        resp = json.loads(body)
    except ValueError:
        log_event(cfg, "upgrade_failed", fp=fp, status="bad_json")
        return False
    if not isinstance(resp, dict) or resp.get("status") == "pending":
        return False  # normal: Bitcoin has not confirmed yet
    if resp.get("bitcoin_anchored") is True and isinstance(resp.get("ots"), str):
        try:
            new_bytes = base64.b64decode(resp["ots"], validate=True)
        except ValueError:
            log_event(cfg, "upgrade_failed", fp=fp, status="bad_base64")
            return False
        state, reason = inspect_proof(new_bytes, fp)
        if state == INVALID and reason == "digest":
            log_event(cfg, "proof_wrong_digest", fp=fp, note="upgrade",
                      got=(proof_digest(new_bytes) or "none")[:12])
            return False  # the pending proof and its marker stay
        if state == BITCOIN_ATTESTATION_PRESENT:
            with fp_lock(fp):
                try:
                    atomic_write(path, new_bytes)
                except OSError:
                    log_event(cfg, "upgrade_failed", fp=fp, status="write_failed")
                    return False
                pending_clear(cfg, fp)
            log_event(cfg, BITCOIN_ATTESTATION_PRESENT, fp=fp)
            return True
        log_event(cfg, "upgrade_failed", fp=fp,
                  status="anchored_reply_without_attestation", reason=reason)
        return False
    # invalid / mismatch / no_attestations: our artifact is wrong — loud.
    log_event(cfg, "upgrade_needs_attention", fp=fp, status=resp.get("status"))
    return False


def upgrade_pass(cfg, flags):
    """POST each still-pending proof to the gateway's /upgrade (JSON in, JSON
    out, ots base64 both ways), working from the pending index rather than
    the proofs directory, up to UPGRADE_INFLIGHT calls in the air. The
    worker threads do only the HTTP call; every answer, file write and
    marker is handled here, on the upgrader thread. A 429, a 503 or an
    unreachable gateway stops new submissions; the answers already in
    flight land, then the pass ends."""
    if not os.path.exists(os.path.join(cfg["pending_dir"], PENDING_BUILT)):
        pending, scanned = build_pending_index(cfg)
        log_event(cfg, "pending_index_built", pending=pending, scanned=scanned)
    checked = 0
    newly_anchored = 0
    queue = list_pending(cfg)
    idx = 0
    outstanding = {}   # future -> (fp, path)
    stop = False
    n = cfg["upgrade_inflight"]
    with ThreadPoolExecutor(max_workers=n, thread_name_prefix="upgrade") as pool:
        while True:
            while not stop and idx < len(queue) and len(outstanding) < n:
                fp = queue[idx]
                idx += 1
                path = proof_path(cfg, fp)
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                except FileNotFoundError:
                    _drop_stale_marker(cfg, fp)  # never while a debt exists or a buyer is mid-way
                    continue
                except OSError:
                    continue
                if bitcoin_attestation_present(data):
                    # Finished by an earlier pass, whose write may have failed
                    # at its directory fsync and left the marker for this
                    # reason: the barrier is repeated before the marker goes,
                    # and a marker behind a barrier that fails again stays.
                    with fp_lock(fp):
                        try:
                            fsync_existing(path)
                        except OSError as exc:
                            log_event(cfg, "upgrade_sync_failed", fp=fp, err=type(exc).__name__)
                            continue
                        pending_clear(cfg, fp)
                    continue
                checked += 1
                outstanding[pool.submit(upgrade_proof, cfg, fp, data)] = (fp, path)
            if not outstanding:
                break
            done, _ = wait_futures(outstanding, return_when=FIRST_COMPLETED)
            for fut in done:
                fp, path = outstanding.pop(fut)
                exc = fut.exception()
                if exc is not None:
                    if isinstance(exc, Unreachable):
                        _mark_down(cfg, flags, "upgrade_gateway")
                        stop = True
                        continue
                    raise exc
                _mark_up(cfg, flags, "upgrade_gateway")
                status, headers, body = fut.result()
                if status == 429:
                    if not stop:
                        log_event(cfg, "upgrade_rate_limited",
                                  wait_secs=_retry_after_secs(headers))
                    stop = True
                    continue
                if status != 200:
                    log_event(cfg, "upgrade_failed", fp=fp, status=status)
                    if status == 503:
                        stop = True
                    continue
                if _apply_upgrade(cfg, fp, path, body):
                    newly_anchored += 1
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
    line = "{} pid={} buyer={} breaker={} upgrader={} attention={}\n".format(
        utc_now_iso(), os.getpid(),
        _ts_or_never(hb.get("buyer")),
        "paused" if br.get("open") else "ok",
        _ts_or_never(hb.get("upgrader")),
        len(hb.get("attention") or ()))
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
            try:
                self.send_response(code)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(payload)
            except OSError as exc:
                # The client went away mid-reply. Logged as a fixed event,
                # never through the server's error path (which names the peer).
                log_event(cfg, "reply_failed", err=type(exc).__name__)

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
            if not proof_on_disk(cfg, fp):
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


class DoorServer(ThreadingHTTPServer):
    """The base class's handle_error prints 'Exception occurred during
    processing of request from (IP, port)' and a traceback to stderr, which
    the unit keeps: a client identity on disk (2026-09-15 review, A11).
    Here the exception class alone is logged, as a fixed event."""

    def __init__(self, address, handler, cfg):
        self.cfg = cfg
        super().__init__(address, handler)

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        log_event(self.cfg, "request_error", err=type(exc).__name__)


# main
def main():
    os.umask(0o077)
    try:
        cfg = resolve_config(os.environ)
        # The appliance shape pays nothing: no phoenixd, no password in memory.
        password = (read_phoenix_password(cfg["phoenix_conf"])
                    if cfg["mode"] == "gateway" else None)
        os.makedirs(cfg["debts_dir"], exist_ok=True)
        os.makedirs(cfg["proofs_dir"], exist_ok=True)
        os.makedirs(cfg["pending_dir"], exist_ok=True)
    except ConfigError as e:
        print(f"api-endpoint: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"api-endpoint: cannot prepare DATA_DIR: {e}", file=sys.stderr)
        return 2

    try:
        reconciled = reconcile_state(cfg)
    except OSError as e:
        print(f"api-endpoint: cannot reconcile DATA_DIR: {e}", file=sys.stderr)
        return 2
    if reconciled:
        log_event(cfg, "reconciled", **reconciled)

    try:
        server = DoorServer((cfg["listen_host"], cfg["listen_port"]),
                            make_handler(cfg), cfg)
    except OSError as e:
        print(f"api-endpoint: cannot bind LISTEN_ADDR "
              f"{cfg['listen_host']}:{cfg['listen_port']}: {e}", file=sys.stderr)
        return 2

    log_event(cfg, "startup",
              listen=f"{cfg['listen_host']}:{cfg['listen_port']}",
              mode=cfg["mode"],
              max_price_sats=cfg["max_price_sats"],
              daily_budget_sats=cfg["daily_budget_sats"],
              poll_secs=cfg["poll_secs"],
              upgrade_secs=cfg["upgrade_secs"],
              debts=len(list_debts_oldest_first(cfg)),
              proofs=len(list_proofs(cfg)),
              pending=len(list_pending(cfg)),
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
