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
