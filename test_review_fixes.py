"""The 2026-09-15 independent review's adapter findings, as regressions.

A1: the buyer/upgrader race stranded an unanchored proof (a marker whose
proof was absent was dropped while the debt existed; a marker that could
not be created was ignored). A2: intake acknowledged a debt on filename
existence while the original write was unfinished, and directory fsync
errors were swallowed. A6: a nine-byte scan called any bytes anchored, and
a header-only file was stored as a proof. A11: a client disconnect went
through the inherited server error path, which prints the peer to stderr.

Each test here fails against da72b6b and passes now. Failure injection at
the write boundary and a killed process are what these tests do; a power
cut is not simulated.
"""
import contextlib
import errno
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import api_endpoint as a
from test_api_endpoint import IntegrationBase, post_record

BITCOIN_TAG = a.BITCOIN_TAG
PENDING_TAG = a.PENDING_TAG


def flags():
    return {**{k: a.StateChange() for k in ("gateway", "phoenixd", "ledger", "budget")},
            "retry_at": [0.0], "attention": set(), "corrupt_logged": set(),
            "breaker": {"failures": 0, "open": False, "wait": 0.0, "until": 0.0}}


def pending_attestation(uri=b"http://127.0.0.1:14788/"):
    payload = a.varuint(len(uri)) + uri
    return b"\x00" + PENDING_TAG + a.varuint(len(payload)) + payload


def bitcoin_attestation(height):
    payload = a.varuint(height)
    return b"\x00" + BITCOIN_TAG + a.varuint(len(payload)) + payload


def pending(fp):
    return a.build_ots(bytes.fromhex(fp), pending_attestation())


def anchored(fp, height=850000):
    return a.build_ots(bytes.fromhex(fp), b"\xf0\x01\x33\x08" + bitcoin_attestation(height))


def forked(fp, height=850000):
    """What the gateway's /upgrade answers: the pending attestation kept
    beside the Bitcoin path under a fork marker."""
    body = b"\xff" + pending_attestation() + b"\xf0\x01\x33\x08" + bitcoin_attestation(height)
    return a.OTS_MAGIC + a.varuint(a.OTS_VERSION) + bytes([a.OP_SHA256]) + bytes.fromhex(fp) + body


def pending_answer():
    return 200, {}, json.dumps({"status": "pending", "bitcoin_anchored": False, "ots": None}).encode()


class UnitBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = a.resolve_config({"LISTEN_ADDR": "127.0.0.1:8402", "CALENDAR_URL": "http://unused",
                                     "DATA_DIR": self.tmp.name}, script_dir=self.tmp.name)
        for key in ("proofs_dir", "pending_dir", "debts_dir"):
            Path(self.cfg[key]).mkdir()
        Path(self.cfg["pending_dir"], a.PENDING_BUILT).touch()
        self.fp = "ab" * 32

    def store(self, data, fp=None):
        fp = fp or self.fp
        a.write_debt(self.cfg, fp)
        a._buy_challenged(self.cfg, None, fp, 200, {}, data, a.utc_today(), 0, flags())

    def log(self):
        try:
            return Path(self.cfg["log_path"]).read_text()
        except FileNotFoundError:
            return ""

    def exists(self, kind, fp=None):
        fp = fp or self.fp
        return Path({"proof": a.proof_path, "debt": a.debt_path, "marker": a.pending_path}[kind](self.cfg, fp)).exists()


class TestProofStates(UnitBase):
    """A6: the structural state comes from a whole deserialisation and the
    attestation nodes, never from the bytes."""

    def test_states_are_decided_by_attestation_nodes(self):
        self.assertEqual(a.inspect_proof(pending(self.fp), self.fp), (a.PENDING, "pending"))
        self.assertEqual(a.inspect_proof(anchored(self.fp), self.fp), (a.BITCOIN_ATTESTATION_PRESENT, "bitcoin"))
        self.assertEqual(a.inspect_proof(forked(self.fp), self.fp), (a.BITCOIN_ATTESTATION_PRESENT, "bitcoin"))
        self.assertTrue(a.bitcoin_attestation_present(forked(self.fp)))
        self.assertFalse(a.bitcoin_attestation_present(pending(self.fp)))
        self.assertEqual(a.inspect_proof(anchored(self.fp), "cd" * 32), (a.INVALID, "digest"))
        header_only = a.OTS_MAGIC + b"\x01\x08" + bytes.fromhex(self.fp)
        self.assertEqual(a.inspect_proof(header_only, self.fp)[0], a.INVALID)
        self.assertEqual(a.inspect_proof(anchored(self.fp) + b"\x00", self.fp), (a.INVALID, "trailing_bytes_after_the_proof"))
        self.assertEqual(a.inspect_proof(b"not a proof", self.fp)[0], a.INVALID)

    def test_the_tag_bytes_inside_a_digest_or_an_operand_do_not_count(self):
        fp = (a.BITCOIN_ATTESTATION + b"x" * 23).hex()
        self.assertFalse(a.bitcoin_attestation_present(pending(fp)))
        operand = a.BITCOIN_ATTESTATION + b"\x07"
        with_operand = a.build_ots(bytes.fromhex(self.fp), b"\xf0" + a.varuint(len(operand)) + operand + pending_attestation())
        self.assertEqual(a.inspect_proof(with_operand, self.fp), (a.PENDING, "pending"))

    def test_the_byte_scan_is_gone(self):
        self.assertFalse(hasattr(a, "is_anchored"))


class TestIntake(UnitBase):
    """A2: the debt is the promise; the promise is durable or it is not made."""

    def test_directory_fsync_error_is_an_error_and_leaves_no_debt(self):
        real = os.fsync

        def failed_dir_sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, "injected directory I/O error")
            return real(fd)
        with patch.object(a.os, "fsync", failed_dir_sync):
            with self.assertRaises(OSError):
                a.write_debt(self.cfg, self.fp)
        self.assertFalse(self.exists("debt"))
        self.assertTrue(a.write_debt(self.cfg, self.fp))   # storage back: the debt is made

    def test_a_duplicate_waits_for_the_original(self):
        ready, resume = threading.Event(), threading.Event()
        real = os.fsync
        errors, order = [], []

        def block_fsync(fd):
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                ready.set()
                resume.wait(5)
                raise OSError(errno.EIO, "debt fsync failed")
            return real(fd)

        def first():
            try:
                a.write_debt(self.cfg, self.fp)
            except OSError:
                errors.append("first")
            order.append("first done")
        dup_done = threading.Event()
        result = {}

        def duplicate():
            try:
                result["value"] = a.write_debt(self.cfg, self.fp)
            except OSError:
                result["error"] = True
            order.append("dup done")
            dup_done.set()
        with patch.object(a.os, "fsync", block_fsync):
            t = threading.Thread(target=first)
            t.start()
            self.assertTrue(ready.wait(5))
            d = threading.Thread(target=duplicate)
            d.start()
            time.sleep(0.5)
            self.assertFalse(dup_done.is_set(), "answered while the original was unfinished")
            resume.set()
            t.join(5)
            d.join(5)
        self.assertEqual(errors, ["first"])
        self.assertEqual(order[0], "first done")
        self.assertNotEqual(result.get("value"), False, "filename existence alone is no acknowledgement")
        self.assertFalse(self.exists("debt"))

    def test_a_short_write_of_the_debt_is_completed(self):
        real = os.write
        with patch.object(a.os, "write", side_effect=lambda fd, data: real(fd, data[:3])):
            self.assertTrue(a.write_debt(self.cfg, self.fp))
        self.assertEqual(Path(a.debt_path(self.cfg, self.fp)).read_text(), self.fp + "\n")


class TestCompletion(UnitBase):
    """A1 and A6: marker, proof and debt change hands under the lock; the
    marker is fatal when absent; only a whole proof is ever stored."""

    def test_the_marker_survives_the_upgrader_between_marker_and_proof_write(self):
        ready, resume = threading.Event(), threading.Event()
        real_write = a.atomic_write
        failures = []

        def pause_write(path, data):
            if path == a.proof_path(self.cfg, self.fp):
                ready.set()
                if not resume.wait(5):
                    raise RuntimeError("test synchronization timed out")
            real_write(path, data)

        def buyer():
            try:
                self.store(pending(self.fp))
            except Exception as exc:
                failures.append(exc)
        with patch.object(a, "atomic_write", pause_write), \
             patch.object(a, "upgrade_proof", return_value=pending_answer()) as upgrade:
            t = threading.Thread(target=buyer)
            t.start()
            self.assertTrue(ready.wait(5))
            a.upgrade_pass(self.cfg, {"upgrade_gateway": a.StateChange()})   # mid-transition: the marker stays
            resume.set()
            t.join(5)
            self.assertFalse(failures)
            a.upgrade_pass(self.cfg, {"upgrade_gateway": a.StateChange()})
            upgrade.assert_called_once()
        self.assertTrue(self.exists("proof"))
        self.assertFalse(self.exists("debt"))
        self.assertTrue(self.exists("marker"))

    def test_a_marker_without_proof_is_kept_while_the_debt_exists_and_dropped_when_nothing_can_write_it(self):
        a.write_debt(self.cfg, self.fp)
        a.pending_mark(self.cfg, self.fp)
        with patch.object(a, "upgrade_proof", return_value=pending_answer()):
            a.upgrade_pass(self.cfg, {"upgrade_gateway": a.StateChange()})
        self.assertTrue(self.exists("marker"), "a debt exists: the proof is still coming")
        a.clear_debt(self.cfg, self.fp)
        with patch.object(a, "upgrade_proof", return_value=pending_answer()):
            a.upgrade_pass(self.cfg, {"upgrade_gateway": a.StateChange()})
        self.assertFalse(self.exists("marker"))
        self.assertIn("stale_marker_dropped", self.log())

    def test_marker_creation_failure_is_fatal_to_the_completion(self):
        real_open = os.open

        def broken_marker(path, *args, **kwargs):
            if path == a.pending_path(self.cfg, self.fp):
                raise OSError(errno.ENOSPC, "injected marker write failure")
            return real_open(path, *args, **kwargs)
        with patch.object(a.os, "open", broken_marker):
            self.store(pending(self.fp))
        self.assertFalse(self.exists("proof"))
        self.assertTrue(self.exists("debt"))
        self.assertFalse(self.exists("marker"))
        self.assertIn("cannot_mark_pending", self.log())
        # Storage back: the next pass completes it.
        a._buy_challenged(self.cfg, None, self.fp, 200, {}, pending(self.fp), a.utc_today(), 0, flags())
        self.assertTrue(self.exists("proof"))
        self.assertTrue(self.exists("marker"))
        self.assertFalse(self.exists("debt"))

    def test_the_marker_directory_is_fsynced_before_the_debt_is_cleared(self):
        events = []
        real_fsync, real_unlink = os.fsync, os.unlink

        def record_fsync(fd):
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode) and os.path.samestat(st, os.stat(self.cfg["pending_dir"])):
                events.append("pending_dir_fsync")
            return real_fsync(fd)

        def record_unlink(path):
            if path == a.debt_path(self.cfg, self.fp):
                events.append("debt_cleared")
            return real_unlink(path)
        with patch.object(a.os, "fsync", record_fsync), patch.object(a.os, "unlink", record_unlink):
            self.store(pending(self.fp))
        self.assertIn("pending_dir_fsync", events)
        self.assertLess(events.index("pending_dir_fsync"), events.index("debt_cleared"))

    def test_a_header_only_answer_is_refused_and_the_debt_kept(self):
        data = a.OTS_MAGIC + b"\x01\x08" + bytes.fromhex(self.fp)
        self.store(data)
        self.assertFalse(self.exists("proof"))
        self.assertTrue(self.exists("debt"))
        self.assertIn("proof_invalid", self.log())

    def test_a_pending_proof_with_the_tag_in_its_digest_is_still_pending(self):
        fp = (a.BITCOIN_ATTESTATION + b"x" * 23).hex()
        self.store(pending(fp), fp)
        with patch.object(a, "upgrade_proof", return_value=pending_answer()) as upgrade:
            a.upgrade_pass(self.cfg, {"upgrade_gateway": a.StateChange()})
            upgrade.assert_called_once()
        self.assertTrue(self.exists("marker", fp))

    def test_an_upgrade_answer_is_deserialised_whole_before_the_marker_goes(self):
        self.store(pending(self.fp))
        bad = anchored(self.fp) + b"\x00"   # trailing bytes: not one whole proof
        answer = (200, {}, json.dumps({"status": "anchored", "bitcoin_anchored": True,
                                       "ots": __import__("base64").b64encode(bad).decode()}).encode())
        with patch.object(a, "upgrade_proof", return_value=answer):
            a.upgrade_pass(self.cfg, {"upgrade_gateway": a.StateChange()})
        self.assertTrue(self.exists("marker"))
        self.assertEqual(Path(a.proof_path(self.cfg, self.fp)).read_bytes(), pending(self.fp))
        self.assertIn("anchored_reply_without_attestation", self.log())
        good = (200, {}, json.dumps({"status": "anchored", "bitcoin_anchored": True,
                                     "ots": __import__("base64").b64encode(forked(self.fp)).decode()}).encode())
        with patch.object(a, "upgrade_proof", return_value=good):
            a.upgrade_pass(self.cfg, {"upgrade_gateway": a.StateChange()})
        self.assertFalse(self.exists("marker"))
        self.assertIn("bitcoin_attestation_present fp=" + self.fp, self.log())
        self.assertNotIn(" anchored fp=", self.log())

    def test_already_bought_needs_a_whole_proof(self):
        Path(a.proof_path(self.cfg, self.fp)).write_bytes(a.OTS_MAGIC + b"\x01\x08" + bytes.fromhex(self.fp))
        a.write_debt(self.cfg, self.fp)
        with patch.object(a, "submit_record", return_value=(200, {}, pending(self.fp))):
            a.buy_one(self.cfg, None, self.fp, flags())
        self.assertEqual(Path(a.proof_path(self.cfg, self.fp)).read_bytes(), pending(self.fp),
                         "the header-only bytes were replaced by a proof, not taken for one")
        self.assertFalse(self.exists("debt"))
        self.assertNotIn("already_bought", self.log())


class TestReconciliation(UnitBase):
    """Installations already stranded by the race, .built present or not,
    are repaired at every start."""

    def test_every_kind_of_stranding_is_repaired_once(self):
        stranded, stale, invalid, fine = "aa" * 32, "bb" * 32, "cc" * 32, "dd" * 32
        Path(a.proof_path(self.cfg, stranded)).write_bytes(pending(stranded))      # no marker, no debt: never upgraded
        Path(a.proof_path(self.cfg, stale)).write_bytes(anchored(stale))
        a.pending_mark(self.cfg, stale)                                              # marker on a finished proof
        Path(a.proof_path(self.cfg, invalid)).write_bytes(a.OTS_MAGIC + b"\x01\x08" + bytes.fromhex(invalid))
        Path(a.proof_path(self.cfg, fine)).write_bytes(pending(fine))
        a.pending_mark(self.cfg, fine)
        a.pending_mark(self.cfg, "ee" * 32)                                          # nothing behind it
        counts = a.reconcile_state(self.cfg)
        self.assertEqual(counts, {"markers_restored": 1, "markers_cleared": 1, "invalid_requeued": 1,
                                  "stale_markers_dropped": 1})
        self.assertTrue(self.exists("marker", stranded))
        self.assertFalse(self.exists("marker", stale))
        self.assertFalse(self.exists("proof", invalid))
        self.assertTrue(any(p.name.startswith(invalid + ".ots.invalid-") for p in Path(self.cfg["proofs_dir"]).iterdir()))
        self.assertTrue(self.exists("debt", invalid))
        self.assertTrue(self.exists("marker", fine))
        self.assertFalse(self.exists("marker", "ee" * 32))
        self.assertIn("pending_marker_restored fp=" + stranded, self.log())
        self.assertIn("proof_invalid_requeued fp=" + invalid, self.log())
        self.assertEqual(a.reconcile_state(self.cfg), {}, "a second pass finds nothing to do")
        self.assertTrue(Path(self.cfg["pending_dir"], a.PENDING_BUILT).exists())


class TestReconciliationAtStartup(IntegrationBase):
    def test_the_real_service_repairs_a_stranded_data_dir_before_opening(self):
        os.makedirs(self.data("proofs"))
        os.makedirs(self.data("pending"))
        os.makedirs(self.data("debts"))
        Path(self.data("pending", a.PENDING_BUILT)).touch()     # .built exists: the old one-time scan would not run
        stranded, invalid = "aa" * 32, "cc" * 32
        Path(self.proof_file(stranded)).write_bytes(pending(stranded))
        Path(self.proof_file(invalid)).write_bytes(a.OTS_MAGIC + b"\x01\x08" + bytes.fromhex(invalid))
        self.start_service()
        log = self.read_service_log()
        self.assertIn("reconciled", log)
        self.assertIn("pending_marker_restored fp=" + stranded, log)
        self.assertIn("proof_invalid_requeued fp=" + invalid, log)
        self.assertTrue(any(p.startswith(invalid + ".ots.invalid-") for p in os.listdir(self.data("proofs"))))
        self.assertLess(log.index("reconciled"), log.index("startup"), "repaired before the door opens")


class TestQuietServer(unittest.TestCase):
    """A11: no client address ever reaches stderr."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = a.resolve_config({"LISTEN_ADDR": "127.0.0.1:8402", "CALENDAR_URL": "http://unused",
                                     "DATA_DIR": self.tmp.name}, script_dir=self.tmp.name)
        for key in ("proofs_dir", "pending_dir", "debts_dir"):
            Path(self.cfg[key]).mkdir()

    def test_a_disconnected_client_leaves_no_identity_on_stderr(self):
        class DisconnectedSocket:
            def settimeout(self, value):
                pass

            def makefile(self, *args):
                return io.BytesIO(b"POST /record HTTP/1.0\r\nContent-Length: 1\r\n\r\na")

            def sendall(self, payload):
                raise BrokenPipeError("injected disconnect before headers")

            def shutdown(self, *args):
                pass

            def close(self):
                pass
        server = a.DoorServer.__new__(a.DoorServer)
        server.RequestHandlerClass = a.make_handler(self.cfg)
        server.cfg = self.cfg
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            server.process_request_thread(DisconnectedSocket(), ("192.0.2.123", 43210))
        self.assertEqual(captured.getvalue(), "")
        log = Path(self.cfg["log_path"]).read_text()
        self.assertIn("reply_failed err=BrokenPipeError", log)
        self.assertNotIn("192.0.2.123", log)

    def test_handle_error_names_the_exception_class_alone(self):
        server = a.DoorServer.__new__(a.DoorServer)
        server.cfg = self.cfg
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            try:
                raise RuntimeError("secret record content 192.0.2.9")
            except RuntimeError:
                server.handle_error(None, ("192.0.2.9", 5))
        self.assertEqual(captured.getvalue(), "")
        log = Path(self.cfg["log_path"]).read_text()
        self.assertIn("request_error err=RuntimeError", log)
        self.assertNotIn("192.0.2.9", log)
        self.assertNotIn("secret", log)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestOldSidecarReservation(UnitBase):
    """A7 (carried, fixed 2026-09-15): an unpaid sidecar from an earlier day
    was re-paid against its old reservation, so today's whole budget stayed
    open beside it, and the retry never asked the wallet whether the earlier
    call had in fact settled. Now the wallet is asked first, and a
    definitely unpaid invoice reserves today's budget before payinvoice."""

    def old_sidecar(self, with_hash=True):
        self.cfg.update(mode="gateway", daily_budget_sats=10)
        a.write_debt(self.cfg, self.fp)
        h = "ee" * 32
        if with_hash:
            a.write_sidecar(a.sidecar_path(self.cfg, self.fp), "mac", "invoice", payment_hash=h, amount_sats=10)
        else:
            a.write_sidecar(a.sidecar_path(self.cfg, self.fp), "mac", "invoice")
        a.write_ledger(self.cfg["ledger_path"], "2000-01-01", 10)   # yesterday's reservation
        return h

    def test_a_definitely_unpaid_old_sidecar_reserves_todays_budget_before_retry(self):
        h = self.old_sidecar()
        order = []
        with patch.object(a, "wallet_payment_outcome", return_value=("failed", None)) as wallet, \
             patch.object(a, "pay_invoice", side_effect=lambda *args: (order.append(("pay", a.read_ledger(self.cfg["ledger_path"]))), "cd" * 32)[1]) as pay, \
             patch.object(a, "gateway_redeem", return_value=(200, {}, pending(self.fp))):
            a.buy_one(self.cfg, None, self.fp, flags())
        wallet.assert_called_once_with(self.cfg, None, h)
        pay.assert_called_once()
        # Today's reservation was on disk BEFORE the payinvoice call ...
        self.assertEqual(order, [("pay", (a.utc_today(), 10))])
        self.assertEqual(a.read_ledger(self.cfg["ledger_path"]), (a.utc_today(), 10))
        # ... and today's budget is spent by it: no further purchase today.
        self.assertEqual(a._budget_preflight(self.cfg, flags())[0], "skip")
        self.assertTrue(os.path.exists(a.proof_path(self.cfg, self.fp)))

    def test_a_settled_old_sidecar_is_redeemed_with_the_wallets_preimage_and_never_repaid(self):
        h = self.old_sidecar()
        preimage = "ab" * 32
        with patch.object(a, "wallet_payment_outcome", return_value=("paid", preimage)), \
             patch.object(a, "pay_invoice") as pay, \
             patch.object(a, "gateway_redeem", return_value=(200, {}, pending(self.fp))) as redeem:
            a.buy_one(self.cfg, None, self.fp, flags())
        pay.assert_not_called()
        redeem.assert_called_once_with(self.cfg, self.fp, "mac", preimage)
        self.assertEqual(a.read_ledger(self.cfg["ledger_path"]), ("2000-01-01", 10))   # nothing reserved
        self.assertTrue(os.path.exists(a.proof_path(self.cfg, self.fp)))

    def test_an_unknown_outcome_waits_without_paying_or_reserving(self):
        h = self.old_sidecar()
        with patch.object(a, "wallet_payment_outcome", return_value=("unknown", None)), \
             patch.object(a, "pay_invoice") as pay, \
             patch.object(a, "gateway_redeem") as redeem:
            self.assertTrue(a.buy_one(self.cfg, None, self.fp, flags()))
        pay.assert_not_called()
        redeem.assert_not_called()
        self.assertEqual(a.read_ledger(self.cfg["ledger_path"]), ("2000-01-01", 10))
        self.assertTrue(os.path.exists(a.sidecar_path(self.cfg, self.fp)))
        self.assertTrue(os.path.exists(a.debt_path(self.cfg, self.fp)))
        self.assertIn("payment_outcome_unknown", open(os.path.join(self.cfg["data_dir"], "log")).read())

    def test_todays_budget_gates_the_retry(self):
        self.old_sidecar()
        a.write_ledger(self.cfg["ledger_path"], a.utc_today(), 5)   # 5 left of 10, the retry needs 10
        with patch.object(a, "wallet_payment_outcome", return_value=("failed", None)), \
             patch.object(a, "pay_invoice") as pay:
            self.assertTrue(a.buy_one(self.cfg, None, self.fp, flags()))
        pay.assert_not_called()
        self.assertEqual(a.read_ledger(self.cfg["ledger_path"]), (a.utc_today(), 5))
        self.assertIn("retry_of_stored_invoice", open(os.path.join(self.cfg["data_dir"], "log")).read())

    def test_a_sidecar_from_before_the_hash_was_stored_is_decoded_first(self):
        self.old_sidecar(with_hash=False)
        with patch.object(a, "decode_invoice", return_value=(10, "ff" * 32)) as decode, \
             patch.object(a, "wallet_payment_outcome", return_value=("failed", None)) as wallet, \
             patch.object(a, "pay_invoice", return_value="cd" * 32), \
             patch.object(a, "gateway_redeem", return_value=(200, {}, pending(self.fp))):
            a.buy_one(self.cfg, None, self.fp, flags())
        decode.assert_called_once_with(self.cfg, None, "invoice")
        wallet.assert_called_once_with(self.cfg, None, "ff" * 32)
        self.assertEqual(a.read_ledger(self.cfg["ledger_path"]), (a.utc_today(), 10))

    def test_wallet_outcome_rules(self):
        with patch.object(a, "http_get", return_value=(204, {}, b"")):
            self.assertEqual(a.wallet_payment_outcome(self.cfg, "pw", "aa" * 32), ("failed", None))
        preimage = "12" * 32
        h = a.sha256(bytes.fromhex(preimage)).hexdigest()
        with patch.object(a, "http_get", return_value=(200, {}, json.dumps({"isPaid": True, "preimage": preimage}).encode())):
            self.assertEqual(a.wallet_payment_outcome(self.cfg, "pw", h), ("paid", preimage))
            # A preimage that is not this hash's is not a settlement of it.
            self.assertEqual(a.wallet_payment_outcome(self.cfg, "pw", "bb" * 32), ("unknown", None))
        with patch.object(a, "http_get", return_value=(200, {}, json.dumps({"isPaid": False, "completedAt": 5}).encode())):
            self.assertEqual(a.wallet_payment_outcome(self.cfg, "pw", h), ("failed", None))
        with patch.object(a, "http_get", return_value=(200, {}, json.dumps({"isPaid": False, "completedAt": None}).encode())):
            self.assertEqual(a.wallet_payment_outcome(self.cfg, "pw", h), ("unknown", None))
        with patch.object(a, "http_get", return_value=(500, {}, b"boom")):
            self.assertEqual(a.wallet_payment_outcome(self.cfg, "pw", h), ("unknown", None))


class TestReconciliationOrder(UnitBase):
    """F01 (2026-09-15/16 review): the reconciliation moved an invalid
    proof aside and only then wrote the debt. A failed debt write, or a
    stop between the two, left an aside file nobody reads and no debt: a
    promised proof, lost. Now the debt is durable before the bytes move,
    and an aside file found alone recreates the debt. Exception injection
    at the write boundary; not a power cut."""

    def aside_files(self):
        return sorted(p.name for p in Path(self.cfg["proofs_dir"]).iterdir() if ".ots.invalid-" in p.name)

    def test_the_debt_is_durable_before_an_invalid_proof_is_moved_aside(self):
        Path(a.proof_path(self.cfg, self.fp)).write_bytes(b"invalid older proof")
        with patch.object(a, "write_debt", side_effect=OSError(errno.ENOSPC, "synthetic ENOSPC")):
            with self.assertRaises(OSError):
                a.reconcile_state(self.cfg)
        self.assertTrue(self.exists("proof"), "nothing moved while the debt could not be written")
        self.assertEqual(self.aside_files(), [])
        counts = a.reconcile_state(self.cfg)          # storage back: the next start repairs it
        self.assertEqual(counts.get("invalid_requeued"), 1, counts)
        self.assertTrue(self.exists("debt"))
        self.assertFalse(self.exists("proof"))
        self.assertEqual(len(self.aside_files()), 1)
        self.assertEqual(a.list_debts_oldest_first(self.cfg), [self.fp])

    def test_the_debt_is_fsynced_before_the_bytes_move(self):
        Path(a.proof_path(self.cfg, self.fp)).write_bytes(b"invalid older proof")
        events = []
        real_fsync, real_replace = os.fsync, os.replace

        def record_fsync(fd):
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode) and os.path.samestat(st, os.stat(self.cfg["debts_dir"])):
                events.append("debts_dir_fsync")
            return real_fsync(fd)

        def record_replace(src, dst):
            if src == a.proof_path(self.cfg, self.fp):
                events.append("moved_aside")
            return real_replace(src, dst)
        with patch.object(a.os, "fsync", record_fsync), patch.object(a.os, "replace", record_replace):
            a.reconcile_state(self.cfg)
        self.assertIn("debts_dir_fsync", events)
        self.assertIn("moved_aside", events)
        self.assertLess(events.index("debts_dir_fsync"), events.index("moved_aside"))

    def test_a_stranded_aside_file_recreates_the_debt(self):
        Path(self.cfg["proofs_dir"], self.fp + ".ots.invalid-1700000000").write_bytes(b"x")
        counts = a.reconcile_state(self.cfg)
        self.assertEqual(counts, {"aside_requeued": 1})
        self.assertTrue(self.exists("debt"))
        self.assertIn("aside_requeued fp=" + self.fp, self.log())
        self.assertEqual(a.reconcile_state(self.cfg), {}, "a second pass finds nothing to do")
        # With a whole proof beside it the aside file is history, not a debt.
        other = "bb" * 32
        Path(self.cfg["proofs_dir"], other + ".ots.invalid-1700000000").write_bytes(b"x")
        Path(a.proof_path(self.cfg, other)).write_bytes(anchored(other))
        self.assertEqual(a.reconcile_state(self.cfg), {})
        self.assertFalse(self.exists("debt", other))


class TestParserBounds(UnitBase):
    """F13 and F03 (2026-09-15/16 review): a final fork marker indexed
    past the end and raised IndexError out of the startup reconciliation;
    attestation payloads were read for their first field only, so bytes
    the public client refuses cleared debts. inspect_proof never raises,
    and every payload is consumed to its end."""

    def test_a_trailing_fork_marker_is_invalid_not_a_crash(self):
        data = a.OTS_MAGIC + b"\x01\x08" + bytes.fromhex(self.fp) + b"\xff"
        self.assertEqual(a.inspect_proof(data, self.fp)[0], a.INVALID)
        Path(a.proof_path(self.cfg, self.fp)).write_bytes(data)
        counts = a.reconcile_state(self.cfg)
        self.assertEqual(counts.get("invalid_requeued"), 1, counts)
        self.assertTrue(self.exists("debt"))

    def test_attestation_payloads_are_consumed_whole(self):
        head = a.OTS_MAGIC + b"\x01\x08" + bytes.fromhex(self.fp)
        uri = b"http://127.0.0.1:14788/"
        cases = {
            "bitcoin_payload_trailing_byte": head + b"\x00" + BITCOIN_TAG + b"\x02\x01\x00",
            "bitcoin_payload_empty": head + b"\x00" + BITCOIN_TAG + b"\x00",
            "pending_payload_trailing_byte": head + b"\x00" + PENDING_TAG
                + a.varuint(len(uri) + 2) + a.varuint(len(uri)) + uri + b"\x00",
            "pending_uri_invalid_utf8": head + b"\x00" + PENDING_TAG + b"\x02\x01\xff",
            "pending_uri_disallowed_character": head + b"\x00" + PENDING_TAG
                + a.varuint(len(uri) + 2) + a.varuint(len(uri) + 1) + uri + b" ",
        }
        for name, data in cases.items():
            with self.subTest(name):
                self.assertEqual(a.inspect_proof(data, self.fp)[0], a.INVALID)
                with self.assertRaises(a.OtsError):
                    a.parse_ots(data)
                # The free door and the paid redeem refuse them: the debt stays.
                a.write_debt(self.cfg, self.fp)
                a._buy_challenged(self.cfg, None, self.fp, 200, {}, data, a.utc_today(), 0, flags())
                self.assertFalse(self.exists("proof"))
                self.assertTrue(self.exists("debt"))
                a.clear_debt(self.cfg, self.fp)

    def test_inspect_proof_never_raises(self):
        import random
        rng = random.Random(20260916)
        shapes = [pending(self.fp), anchored(self.fp), forked(self.fp)]
        for data in shapes:
            for cut in range(len(data) + 1):
                self.assertIsInstance(a.inspect_proof(data[:cut], self.fp), tuple)
            self.assertEqual(a.inspect_proof(data + b"\x00", self.fp)[0], a.INVALID)
        for _ in range(3000):
            data = bytearray(rng.choice(shapes))
            for _ in range(rng.randint(1, 3)):
                kind = rng.random()
                pos = rng.randrange(len(data)) if data else 0
                if kind < 0.5 and data:
                    data[pos] = rng.randrange(256)
                elif kind < 0.8:
                    data.insert(pos, rng.randrange(256))
                elif data:
                    del data[pos]
            self.assertIsInstance(a.inspect_proof(bytes(data), self.fp), tuple)
        for _ in range(500):
            self.assertIsInstance(a.inspect_proof(rng.randbytes(rng.randrange(0, 200)), self.fp), tuple)


class TestSmoke(unittest.TestCase):
    """F21 (2026-09-15/16 review): the smoke script called
    api_endpoint.is_anchored, removed on 2026-09-15."""

    def test_the_smoke_script_names_only_functions_that_exist(self):
        import re
        source = Path(__file__).with_name("smoke.sh").read_text()
        # The file name api_endpoint.py is not a reference to a function.
        names = sorted(set(re.findall(r"api_endpoint\.([A-Za-z_][A-Za-z0-9_]*)", source)) - {"py"})
        missing = [n for n in names if not hasattr(a, n)]
        self.assertEqual(missing, [], "smoke.sh names functions the adapter no longer has")
        self.assertIn("inspect_proof", names, "the smoke must check the whole proof, not its header")
        self.assertNotIn("is_anchored", names)


class TestIntakeCleanup(UnitBase):
    """Close-gate correction (2026-09-16): a debt that could not be made
    durable is removed and the door answers 500, but the removal can fail
    too, and its error was suppressed. The 500 therefore promises only
    that acceptance was not confirmed; a debt file may remain, which is
    the safe direction (the buyer meets it, the client's retry is answered
    received). The leftover is now logged, so the state is observable."""

    def test_a_failed_cleanup_after_a_failed_debt_write_is_logged_and_the_error_still_raised(self):
        real_fsync, real_unlink = os.fsync, os.unlink

        def failed_file_sync(fd):
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, "injected debt fsync failure")
            return real_fsync(fd)

        def failed_unlink(path):
            if path == a.debt_path(self.cfg, self.fp):
                raise OSError(errno.EIO, "injected unlink failure")
            return real_unlink(path)
        with patch.object(a.os, "fsync", failed_file_sync), patch.object(a.os, "unlink", failed_unlink):
            with self.assertRaises(OSError):
                a.write_debt(self.cfg, self.fp)
        self.assertTrue(self.exists("debt"), "the leftover the door could not remove")
        self.assertIn("debt_cleanup_failed fp=" + self.fp, self.log())
        # The leftover is a debt like any other: the buyer meets it, and a
        # duplicate request is answered as already owed.
        self.assertFalse(a.write_debt(self.cfg, self.fp))
