# Contracts

What the adapter promises, who owns unfinished work at each handoff, what
durable evidence lets it forget, and which records are authoritative.
Every statement is made by code in `api_endpoint.py` and pinned by a test
named here; a change to any of them changes this file first
(CONTRIBUTING.md). Written 2026-09-16 against the 2026-09-15/16 reviews.

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
| `POST /record` | `200 received <fp>` | The debt file for `<fp>` is on disk, its bytes and its directory fsynced, before the reply is written, under the fingerprint's lock; or a whole proof of `<fp>` already exists. From here the adapter owns the obligation until `proofs/<fp>.ots` holds a whole proof of `<fp>`. | Not when the proof will exist; not that the calendar or gateway has been told yet; nothing about the bytes but their hash. |
| `POST /record` | `500 cannot record the debt; not received` | Acceptance was not confirmed: the debt could not be written or synced, and the adapter tried to remove it. The client must retry, and can do so safely. | Not that nothing exists: the removal can fail too (logged `debt_cleanup_failed`), and a debt file may remain. Such a debt is met by the buyer like any other, and the retry is answered `received` as already owed. Work may already exist; it is never duplicated. |
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
| answer → proof | proof bytes in memory | `pending/<fp>` fsynced, `proofs/<fp>.ots` written atomically, `debts/<fp>` unlinked, in that order under the lock | the proof file | the debt's unlink: from here `proof_on_disk` is the fact and the debt would only be recreated by the reconciliation if the proof turned out not to parse |
| pending proof → upgrader | marker | `GET /timestamp/<commitment>` answered 200 | the marker | the anchored bytes written atomically over the proof, then the marker cleared |
| adapter → operator | files under `DATA_DIR` | the operator copies proofs out | the operator | outside this contract |

## 4. Workflow 1: acceptance → durable debt → pending proof and upgrade tracking → anchored proof

### A1. Acceptance

| | |
|---|---|
| Authoritative state | `debts/<fp>` |
| Preconditions | `Content-Length` present; body non-empty (or `X-Digest: sha256` with 64 hex chars); the fingerprint's lock taken |
| Side effects | the debt file (`O_EXCL`, fsync, directory fsync); one `received` log line |
| Acknowledgement point | the reply, after `write_debt` returns |
| Ambiguous outcomes | reply lost after the fsync (the promise stands; the retry is a no-op); crash between `O_EXCL` create and the fsync (an empty or torn debt file may exist: its content is unused, its name is the fact; the next start's reconciliation and the buyer treat it as owed, which is the safe direction); a 500 whose cleanup also failed (a debt file remains, logged `debt_cleanup_failed`; owed like any other; the client's retry is answered as owed) |
| Recovery | none needed |
| Tests | `test_review_fixes.TestIntake`, `test_api_endpoint` door tests |

### A2. The buyer: debt → pending proof (calendar mode)

| | |
|---|---|
| Authoritative state | the debt until `store_proof` completes; then the proof |
| Preconditions | a whole proof of `<fp>` is not already on disk (`proof_on_disk`); the calendar answers 200 with a pending timestamp of exactly this digest |
| Side effects, in order under the lock | (1) `pending/<fp>` created and its directory fsynced; (2) `proofs/<fp>.ots` written to a temporary name, fsynced, renamed, directory fsynced; (3) the sidecar (if any) and the debt unlinked |
| Acknowledgement point | (3): the debt is gone |
| Ambiguous outcomes | a stop after (1): marker without proof, debt present (kept: a debt exists); after (2): proof and debt both present (`already_bought` clears the debt next pass, no second submission); a calendar answer that is not the protocol (402, a non-pending timestamp, garbage): the debt stays, logged, asked again next pass; 503 or unreachable: the pass ends, every debt stays |
| Recovery | the next pass, or the next start's reconciliation |
| Tests | `test_api_endpoint.TestCalendarMode`, `test_review_fixes.TestCompletion`, `test_sigkill_mid_burst_every_acked_record_bought`, `test_inflight_sigkill_mid_flight_converges_one_proof_each` |

### A3. The upgrader: pending → bitcoin_attestation_present

| | |
|---|---|
| Authoritative state | the proof file; the marker is the index |
| Preconditions | the marker exists; the proof parses as pending and linear; the calendar answers 200 for the commitment |
| Side effects | the spliced bytes, deserialised whole and checked to be a proof of `<fp>` with a Bitcoin attestation node, written atomically over the proof under the lock; then the marker cleared; `bitcoin_attestation_present` logged |
| Acknowledgement point | the atomic write's rename |
| Ambiguous outcomes | a stop after the write and before the marker clear: the next pass reads the proof, sees the attestation, clears the marker; a 404: pending, nothing written; an answer that does not splice: `upgrade_needs_attention`, marker kept; a fork-marked proof (never from one calendar): `nonlinear`, marker kept |
| Recovery | the next pass; the next start's reconciliation clears a marker on a finished proof |
| Tests | `test_calendar_mode_upgrade_404_stays_pending_then_anchored_bytes_spliced`, `test_upgrade_replaces_only_on_anchored_and_then_stops`, `test_review_fixes.TestCompletion` |

### A4. Start: the reconciliation

| | |
|---|---|
| Authoritative state | the proofs; the debts; the markers |
| Preconditions | before the door, the buyer and the upgrader start |
| Side effects, per proof | parses whole with a Bitcoin attestation: a stale marker is cleared; pending: a missing marker is restored; anything else: **the debt is written and fsynced first, then the bytes are moved aside** as `<fp>.ots.invalid-<time>`, then the marker cleared (2026-09-15 review F01). Per aside file with neither proof nor debt: the debt is recreated (`aside_requeued`). Per marker with neither proof, debt nor sidecar: dropped. |
| Acknowledgement point | `reconciled` in the log, then `startup` |
| Ambiguous outcomes | a stop after the debt write and before the move: the invalid proof is found again next start and moved beside the existing debt; a failed debt write: the start fails (exit 2) with the proof still in place, so the next start repeats the repair; a parser exception on any bytes: the bytes are INVALID, never a crash (2026-09-15 review F13) |
| Recovery | re-run: every step is idempotent |
| Tests | `test_review_fixes.TestReconciliation`, `TestReconciliationAtStartup` |

### A5. Gateway mode: the paid purchase

Owned by the payment session. The transitions (challenge, reserve, pay,
redeem, the sidecar's states, expiry and wallet reconciliation) will be
written here as section 9 with their failure tests; until then README
"The debt lifecycle" is the description and `test_api_endpoint` its pins.
Findings F04, F15, F16 of the 2026-09-15/16 review are theirs.

## 5. Invariants

| Invariant | Where it holds | Where it is checked |
|---|---|---|
| Conservation of obligations | every `received` has a debt or a whole proof; the debt goes only after the proof is on disk; an invalid proof found at start recreates the debt before it is moved; an aside file alone recreates it | A1, A2, A4 tests |
| Ambiguity is a state | bytes that do not parse are INVALID, not a crash and not a proof; a calendar answer that is not the protocol keeps the debt; a lost answer is asked again; a corrupt ledger pauses, never resets | A2, A4; `test_corrupt_ledger_pauses_purchases_never_intake` |
| Recovery is interruptible | every reconciliation step leaves a state the next start repairs the same way | A4 tests |
| Concurrency preserves decisions | one fingerprint is in flight at most once; the marker, proof and debt change hands under the fingerprint's lock; the upgrader never drops a marker while a debt exists or a buyer holds the lock | `TestInflight`, `TestCompletion` |
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
   more), and a varuint longer than ten bytes is refused.
2. **Contains a Bitcoin attestation** (`bitcoin_attestation_present`):
   after (1), an attestation node carries the Bitcoin tag. A fact about
   the file.
3. **Verifies against Bitcoin**: never claimed here.

`inspect_proof` never raises: any bytes give `INVALID` with a reason, or
one of the two states. The corpus that pins (1) and (2) against the
library is `proof_corpus.py` with `test_proof_corpus.py`; it is the same
corpus the calendar fork carries for its readers, and a change to one is
a change to both until the readers are one implementation.

## 7. Configuration and locking

One configuration function, `resolve_config`: invocation environment,
then `.env` beside the script, then defaults; an empty string is unset;
every malformed or missing setting is a startup error naming what to
set. No setting is read anywhere else.

| Tool | Used for | Where |
|---|---|---|
| per-fingerprint lock (in-process) | the three files of one fingerprint change hands atomically with respect to the other threads; a duplicate `POST` waits for the original's durability | `write_debt`, `store_proof`, `_apply_upgrade`, `_drop_stale_marker` |
| whole-run lock | not used: one process owns `DATA_DIR`. Two adapters on one `DATA_DIR` are not excluded by code; the deployment runs one unit per `DATA_DIR`. Stated as a limit. | — |
| atomic file replace | every file that is rewritten (`proofs/<fp>.ots`, `ledger`, `.l402`, `heartbeat`): unique temporary name in the same directory, fsync, rename, directory fsync | `atomic_write` |

## 8. Not yet written

Section 9, gateway mode (the payment session); the parser consolidation
into one production implementation once the corpus has run against all
three readers.
