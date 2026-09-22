# Contracts

What the adapter promises, who owns unfinished work at each handoff, what
durable evidence lets it forget, and which records are authoritative.
Every statement is made by code in `api_endpoint.py` and pinned by a test
named here; a change to any of them changes this file first
(CONTRIBUTING.md). Written 2026-09-16 against the 2026-09-15/16 reviews;
corrected 2026-09-18 for the cold review's R02, R09, R16 and R19, each
named where it changed a table.

The words:

- **Fingerprint** (`fp`): the SHA-256 of a record's bytes, 64 lowercase
  hex. The adapter never keeps the bytes; the fingerprint is the record's
  only name here.
- **Submission**: one `POST /record`. Two submissions of the same bytes
  are one fingerprint and one obligation; the second is answered
  `received` and creates nothing (`new_debt=false`).
- **Debt**: the durable promise, `debts/<fp>`. It exists from before the
  `received` reply until a whole proof of the fingerprint is on disk.
- **Occurrence**: not a concept here. The adapter promises one proof per
  fingerprint, not one per submission; counting occurrences is the
  calendar's (receipts) and the gateway's (bills).

## 1. What an HTTP success promises

| Request | Success | The promise | What it does not promise |
|---|---|---|---|
| `POST /record` | `200 received <fp>` | The debt file for `<fp>` is on disk, its bytes and its directory fsynced, before the reply is written, under the fingerprint's lock; or a whole proof of `<fp>` already exists. A debt found already on file is fsynced again, with its directory, before the reply: its presence is visibility, the barrier is the acknowledgement (2026-09-18 cold review R02). From here the adapter owns the obligation until `proofs/<fp>.ots` holds a whole proof of `<fp>`. | Not when the proof will exist; not that the calendar or gateway has been told yet; nothing about the bytes but their hash. |
| `POST /record` | `500 cannot record the debt; not received` | Acceptance was not confirmed: the debt could not be written or synced, and the adapter tried to remove it. The client must retry, and can do so safely. | Not that nothing exists: the removal can fail too (logged `debt_cleanup_failed`), and a debt file may remain. Such a debt is met by the buyer like any other; the retry repeats its barrier and is answered `received` as already owed only when that holds, else 500 again (R02: the retry used to acknowledge the file by its presence). Work may already exist; it is never duplicated. |
| `POST /record` | 400 / 404 / 405 / 411 | Refused before any write. | — |

**Ambiguous outcomes.** A client that times out after the debt's directory
fsync and before the reply holds no acknowledgement for a promise the
adapter will keep; its retry is answered `received` with `new_debt=false`.
A client whose connection drops mid-body gets no reply and no debt (the
fingerprint was never computed). Neither case loses or duplicates a
proof.

## 2. Records: authoritative, evidence, rebuildable

| Record | Kind | Authoritative for | Loss or damage |
|---|---|---|---|
| `debts/<fp>` | authoritative | An obligation not yet met. Existence is the fact; content is the fingerprint again. | A lost debt is a lost promise; nothing rebuilds it except the client's retry. The `received` reply is sent only after it is durable, so a lost debt means a lost disk, not a crash. |
| `proofs/<fp>.ots` | authoritative | The proof handed to the operator: `pending` (names the calendar) or `bitcoin_attestation_present`. Only bytes that parse whole as a proof of `<fp>` are ever written here; anything else found here at start is set aside. | Set aside as `<fp>.ots.invalid-<time>` and the debt recreated (A4). |
| `pending/<fp>` | rebuildable index | Which proofs still wait for a Bitcoin attestation; the upgrader reads this instead of every proof. | Rebuilt at every start from the proofs (A4); a marker without a proof is dropped only when no debt, no sidecar and no buyer mid-way can still write one. |
| `pending/.built` | flag | The index has been built once. | Absent: the next start scans every proof. |
| `debts/<fp>.l402` | authoritative (gateway mode) | An in-flight purchase: the challenge, the invoice's own hash and amount, the preimage once paid. | The payment session's contract; see README "The debt lifecycle". In calendar mode it is never written, and one left by a gateway-mode life is skipped and logged. |
| `ledger` | authoritative (gateway mode) | Sats reserved today. | A corrupt ledger pauses purchases, never intake, and is never overwritten. |
| `<fp>.ots.invalid-<time>` | evidence | Bytes once stored as a proof that were not one. | A start that finds one with neither a proof nor a debt for its fingerprint recreates the debt (A4). |
| `log`, `heartbeat` | observation | What happened, and that the loops are alive. | Loss changes nothing durable. |
| the fingerprint locks (`_FP_LOCKS`) | in-memory | Serialising the three files of one fingerprint inside one process. | A second process on the same `DATA_DIR` is not excluded: one adapter per `DATA_DIR` is a deployment rule, not a code guarantee (section 7). |

## 3. Who owns unfinished work

| Handoff | Before | After | Owner in between | Evidence that lets the previous owner forget |
|---|---|---|---|---|
| client → door | bytes in flight | fingerprint computed | nobody durable | none needed: no reply yet |
| door → debt | fingerprint | `debts/<fp>` fsynced with its directory | the debt | the directory fsync returning; only then `received` |
| debt → buyer | debt | submitted to the calendar (`POST /digest`) or the gateway | the debt, still: a submission whose answer is lost is submitted again next pass; the calendar dedupes inside its horizon | never before `store_proof` |
| answer → proof | proof bytes in memory | `pending/<fp>` fsynced, `proofs/<fp>.ots` written atomically and its directory fsynced, `debts/<fp>` unlinked, in that order under the lock | the debt until the proof's directory fsync returns; then the proof file | the directory fsync after the rename, then the debt's unlink: a proof visible after its rename is not known durable until that fsync returns, so a pass that finds a proof beside a debt repeats the barrier before the debt goes (A2). From the unlink `proof_on_disk` is the fact, and the debt would only be recreated by the reconciliation if the proof turned out not to parse; a repeated `POST` for a fingerprint whose proof is on disk repeats the proof's barrier under the lock, and a debt still beside it gets its own, before `received` (A1) |
| pending proof → upgrader | marker | `GET /timestamp/<commitment>` answered 200 | the marker | the anchored bytes written atomically over the proof and their directory fsynced, then the marker cleared; a pass that finds the anchored proof with its marker standing repeats the fsync before it clears (A3) |
| adapter → operator | files under `DATA_DIR` | the operator copies proofs out | the operator | outside this contract |

## 4. Workflow 1: acceptance → durable debt → pending proof and upgrade tracking → anchored proof

### A1. Acceptance

| | |
|---|---|
| Authoritative state | `debts/<fp>` |
| Preconditions | `Content-Length` present; body non-empty (or `X-Digest: sha256` with 64 hex chars); the fingerprint's lock taken; for a fingerprint whose proof is already on disk, the proof's barrier (its file, then its directory) repeated under the lock, and a debt still beside it its own |
| Side effects | the debt file (`O_EXCL`, fsync, directory fsync), or, for a fingerprint whose proof is on disk, no debt and the repeated barriers; one `received` log line |
| Acknowledgement point | the reply, after `write_debt` returns, or after the proof's barrier (and any remaining debt's) has returned |
| Ambiguous outcomes | reply lost after the fsync (the promise stands; the retry is a no-op); crash between `O_EXCL` create and the fsync (an empty or torn debt file may exist: its content is unused, its name is the fact; the next start's reconciliation and the buyer treat it as owed, which is the safe direction); a 500 whose cleanup also failed (a debt file remains, logged `debt_cleanup_failed`; owed like any other; the client's retry fsyncs it with its directory under the lock and is answered as owed only when that barrier holds, else 500 again: 2026-09-18 cold review R02, the retry used to acknowledge the file by its presence alone); a proof visible after the buyer's rename whose directory fsync failed, beside a debt whose barrier and cleanup both failed: a repeated `POST` acknowledges only once both barriers hold, else `500 cannot confirm the proof; not received`, logged `intake_error reason=proof_sync_failed`, and no debt is written; the visible bytes alone never answer |
| Recovery | none needed |
| Tests | `test_review_fixes.TestIntake`, `TestIntakeCleanup`, `TestResumedBarriers` (the barrier failing on the write and again on the retry, each injection counted, then holding), `TestVisibleProofIntake` (a proof on disk answering only once its barrier and the remaining debt's hold, on the real files), `test_api_endpoint` door tests |

### A2. The buyer: debt → pending proof (calendar mode)

| | |
|---|---|
| Authoritative state | the debt until `store_proof` completes; then the proof |
| Preconditions | a whole proof of `<fp>` is not already on disk (`proof_on_disk`); the calendar answers 200 with a pending timestamp of exactly this digest |
| Side effects, in order under the lock | (1) `pending/<fp>` created and its directory fsynced; (2) `proofs/<fp>.ots` written to a temporary name, fsynced, renamed, directory fsynced; (3) the sidecar (if any) and the debt unlinked |
| Acknowledgement point | (2)'s directory fsync, then (3): the debt goes only after the proof's barrier returned. The rename in (2) is visibility, not acknowledgement |
| Ambiguous outcomes | a stop after (1): marker without proof, debt present (kept: a debt exists); a stop after (2), or (2)'s directory fsync failing after the rename (`store_proof` raises, the debt stays): proof and debt both present, the proof visible and its durability unknown; `already_bought` fsyncs the proof and its directory again, under the lock, and clears the debt only when that returns, else logs `proof_sync_failed` and keeps the debt for the next pass; no second submission either way (2026-09-18 cold review R02: the debt used to go on the proof's presence); a calendar answer that is not the protocol (402, a non-pending timestamp, garbage): the debt stays, logged, asked again next pass; 503 or unreachable: the pass ends, every debt stays |
| Recovery | the next pass, or the next start's reconciliation |
| Tests | `test_api_endpoint.TestCalendarMode`, `test_review_fixes.TestCompletion`, `TestResumedBarriers`, `test_sigkill_mid_burst_every_acked_record_bought`, `test_inflight_sigkill_mid_flight_converges_one_proof_each` |

### A3. The upgrader: pending → bitcoin_attestation_present

| | |
|---|---|
| Authoritative state | the proof file; the marker is the index |
| Preconditions | the marker exists; the proof parses as pending and linear; the calendar answers 200 for the commitment |
| Side effects | the spliced bytes, deserialised whole and checked to be a proof of `<fp>` with a Bitcoin attestation node, written atomically over the proof and their directory fsynced, under the lock; then the marker cleared; `bitcoin_attestation_present` logged |
| Acknowledgement point | the directory fsync after the atomic write's rename: the rename is visibility (2026-09-18 cold review R02; this row used to name the rename) |
| Ambiguous outcomes | a stop after the write and before the marker clear, or a directory fsync that failed after the rename (`upgrade_failed status=write_failed`, the marker kept): the next pass reads the proof, sees the attestation, fsyncs the file and its directory again under the lock and clears the marker only when that returns, else logs `upgrade_sync_failed` and keeps the marker (R02: the marker used to go on the attestation's presence); a 404: pending, nothing written; an answer that does not splice: `upgrade_needs_attention`, marker kept; a fork-marked proof (never from one calendar): `nonlinear`, marker kept; a marker whose proof is absent: silent while a debt, a sidecar or a buyer mid-way can still write it, else kept and reported `proof_missing` every pass (A4) |
| Recovery | the next pass; the next start's reconciliation clears a marker on a finished proof, and its final directory fsyncs are that pass's barrier |
| Tests | `test_calendar_mode_upgrade_404_stays_pending_then_anchored_bytes_spliced`, `test_upgrade_replaces_only_on_anchored_and_then_stops`, `test_review_fixes.TestCompletion`, `TestResumedBarriers` |

### A4. Start: the reconciliation

| | |
|---|---|
| Authoritative state | the proofs; the debts; the markers |
| Preconditions | before the door, the buyer and the upgrader start |
| Side effects, per proof | parses whole with a Bitcoin attestation: a stale marker is cleared; pending: a missing marker is restored; anything else: **the debt is written and fsynced first, then the bytes are moved aside** as `<fp>.ots.invalid-<time>`, then the marker cleared (2026-09-15 review F01). Per aside file with neither proof nor debt: the debt is recreated (`aside_requeued`). Per marker with neither proof, debt nor sidecar: **kept and reported** (`proof_missing`, counted as `proofs_missing` in `reconciled`): the marker is the last sign of a promise whose proof is gone, an external deletion or an incomplete restore; no debt is written for it, since a proof bought now would carry a later bound and is not the one promised, and only a copy of the original put back as `proofs/<fp>.ots` resolves it, after which the upgrader resumes from the marker (2026-09-21 year-of-operation review, scenario 18: the marker used to be dropped here and by the upgrader, and the promise vanished without a trace). |
| Acknowledgement point | `reconciled` in the log, then `startup` |
| Ambiguous outcomes | a stop after the debt write and before the move: the invalid proof is found again next start and moved beside the existing debt; a failed debt write: the start fails (exit 2) with the proof still in place, so the next start repeats the repair; a pending index that cannot be listed: the start fails (exit 2, `cannot reconcile DATA_DIR`) rather than treating the index as empty (2026-09-18 cold review R16); a parser exception on any bytes: the bytes are INVALID, never a crash (2026-09-15 review F13) |
| Recovery | re-run: every step is idempotent; a missing promised proof is reported at every start until a copy of the original is back, never resolved by the adapter itself |
| Tests | `test_review_fixes.TestReconciliation`, `TestReconciliationAtStartup`, `TestMissingPromisedProof` (the loss at both entry points, the present-proof control, the copy put back resuming the upgrade) |

### A5. Gateway mode: the paid purchase

Owned by the payment session. The transitions (challenge, reserve, pay,
redeem, the sidecar's states, expiry and wallet reconciliation) will be
written here as section 9 with their failure tests; until then README
"The debt lifecycle" is the description and `test_api_endpoint` its pins.
Findings F04, F15, F16 of the 2026-09-15/16 review are theirs.

## 5. Invariants

| Invariant | Where it holds | Where it is checked |
|---|---|---|
| Conservation of obligations | every `received` has a debt or a whole proof; the debt goes only after the proof is on disk; an invalid proof found at start recreates the debt before it is moved; an aside file alone recreates it; a marker whose proof is gone and that nothing can rewrite stays, reported, until a copy of the original is back | A1, A2, A4 tests; `test_review_fixes.TestMissingPromisedProof` |
| Ambiguity is a state | bytes that do not parse are INVALID, not a crash and not a proof; a calendar answer that is not the protocol keeps the debt; a lost answer is asked again; a corrupt ledger pauses, never resets; a pending index that cannot be listed is an error the upgrader logs every pass (`upgrader_error`) and asks again, and the start refuses, never an empty index (R16); a file found on disk is visible, not known durable, until its barrier is repeated (R02), the door included: a proof on disk answers a `POST` only after its barrier | A1, A2, A4; `test_corrupt_ledger_pauses_purchases_never_intake`; `test_review_fixes.TestPendingIndexListing`, `TestResumedBarriers`, `TestVisibleProofIntake` |
| Recovery is interruptible | every reconciliation step leaves a state the next start repairs the same way | A4 tests |
| Concurrency preserves decisions | one fingerprint is in flight at most once; the marker, proof and debt change hands under the fingerprint's lock; the upgrader never drops a marker whose proof is absent: silent while a debt exists or a buyer holds the lock, reported otherwise | `TestInflight`, `TestCompletion`, `TestMissingPromisedProof` |
| Safety includes progress | a 503, a rate limit or an unreachable door ends the pass and keeps every debt; the next pass tries again; one bad proof (set aside) never blocks the others | A2, A4 |
| External effects have retry semantics | a resubmission inside the calendar's dedupe horizon is the same commitment; outside it a second one (the calendar's stated over-count); in gateway mode the payment session's rules | `TestCalendarMode` |
| Time, capacity, observation | the log rotates at a byte cap; a failing log never stops intake; the heartbeat says which loops are alive, not that they are healthy | `test_log_rotates_to_dot1_at_cap_and_replaces_previous` |
| Anchored is not irreversible | the adapter records a structural state of the bytes; whether the block still stands is the calendar's detector and the verifier's business | README "Verify" |

## 6. The proof parser: three claims kept apart

`api_endpoint.py` carries two readers: `parse_ots` (linear proofs, the
shape one calendar emits, with the commitment and the splice point for
an upgrade) and `proof_attestations` (any proof, forks included, listing
its attestation nodes). Both make only claim (1) below; `inspect_proof`
adds (2); nothing here makes (3).

1. **Parses**: one whole detached proof by the rules of the public
   client pinned in the tests (`opentimestamps` 0.4.x): every byte
   consumed; every attestation payload consumed to its end; a pending
   URI of at most 1000 bytes from `A–Z a–z 0–9 - . _ / :`; operands of
   1–4096 bytes; no message over 4096 bytes on any path; a fork marker
   followed by an operation or an attestation, never another fork; at
   most 255 operations on any path. Two narrowings, stated: only
   `sha256`, `append` and `prepend` are accepted (the public client knows
   more), and a varuint longer than ten bytes is refused. The attestation
   tags the client knows are four, and each payload is read as the
   client reads it: pending (a URI), and the block-header attestations of
   Bitcoin, Litecoin and Ethereum (one varuint height, read to the
   payload's end); any other tag is unknown and its payload opaque, up to
   8192 bytes. That is the supported subset, stated: parity with the
   client on what parses, and Bitcoin alone on what counts (2026-09-18
   cold review R09: the Litecoin and Ethereum tags used to be read as
   opaque unknowns, so an empty or trailing payload the client refuses
   parsed, and beside a Bitcoin node made a proof
   `bitcoin_attestation_present`). `parse_ots` is linear only, by
   design.
2. **Contains a Bitcoin attestation** (`bitcoin_attestation_present`):
   after (1), an attestation node carries the Bitcoin tag. A fact about
   the file. A Litecoin or Ethereum attestation is not one: it reads as
   unknown, no usable attestation, and no claim about that chain is made.
3. **Verifies against Bitcoin**: never claimed here.

`inspect_proof` never raises: any bytes give `INVALID` with a reason, or
one of the two states. The corpus that pins (1) and (2) against the
library is `proof_corpus.py` with `test_proof_corpus.py`; it is the same
corpus the calendar fork carries for its readers, and a change to one is
a change to both until the readers are one implementation. The library
is the oracle and the suite needs it: without the `opentimestamps`
package the corpus tests fail, they do not skip.

## 7. Configuration and locking

One configuration function, `resolve_config`: invocation environment,
then `.env` beside the script, then defaults; an empty string is unset;
every malformed or missing setting is a startup error naming what to
set. Every interval (`POLL_SECS`, `UPGRADE_SECS`, `HEARTBEAT_SECS`,
`L402_EXPIRY_SECS`, `REDEEM_ATTENTION_RETRY_SECS`,
`CIRCUIT_BREAKER_PAUSE_SECS`) is a positive, finite number of seconds
(2026-09-18 cold review R19: `inf` used to pass the check and stop the
buyer at its first `time.sleep`, outside its catch). No setting is read
anywhere else.

| Tool | Used for | Where |
|---|---|---|
| per-fingerprint lock (in-process) | the three files of one fingerprint change hands atomically with respect to the other threads; a duplicate `POST` waits for the original's durability; a barrier repeated over a file found on disk (`fsync_existing`) is taken under it too | `write_debt` (the duplicate's fsync of the existing debt), `store_proof`, `buy_one` (`already_bought`'s fsync and the debt's clearing), `_apply_upgrade`, `upgrade_pass` (the marker cleared behind an anchored proof), `_report_missing_proof` |
| whole-run lock | not used: one process owns `DATA_DIR`. Two adapters on one `DATA_DIR` are not excluded by code; the deployment runs one unit per `DATA_DIR`. Stated as a limit. | — |
| atomic file replace | every file that is rewritten (`proofs/<fp>.ots`, `ledger`, `.l402`, `heartbeat`): unique temporary name in the same directory, fsync, rename, directory fsync | `atomic_write` |

## 8. Not yet written

Section 9, gateway mode (the payment session); the parser consolidation
into one production implementation once the corpus has run against all
three readers.
