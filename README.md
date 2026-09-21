# api-endpoint

api-endpoint is a client adapter: one process, one Python file, standard
library only. Client systems POST records to a local door; each record is
SHA-256-fingerprinted in memory (raw bytes are never written and never
logged), and each fingerprint gets its own OpenTimestamps proof, from an
L402 timestamp gateway or from a calendar, written to disk beside a debt
that records the promise until the proof exists. The client system posts
bytes and, later, a proof file exists; it never sees an invoice, a
macaroon or a preimage.

## Configurations

One door, chosen by which URL is set; exactly one of the two.

- **`GATEWAY_URL`**: the proof comes from an L402 timestamp gateway (the
  `timestamp-gateway` repository), through its 402 flow, paid from a
  phoenixd on this host. The gateway's free door, its anchor billing and
  the standing payer that settled those bills (once in the `auto-anchor`
  repository) were retired on 2026-09-18; the adapter still stores a 200
  that carries a proof, which is what the calendar answers.
- **`CALENDAR_URL`**: the fingerprint is submitted directly to a calendar
  (the `opentimestamps-server` fork) through its counted `/digest`, and
  nothing is paid anywhere. The fork's README, "Install: single host",
  installs the calendar, this adapter and the fork's tools on one host.

Everything after the transport is the same code in both: the debt before
"received", the pending index, `INFLIGHT`, the crash paths, the
wrong-digest refusal.

## What the adapter guarantees

Each rule is made by the code and pinned by the tests "Tests" names.

- "received" is sent only after the debt is durable: the debt file is
  written and fsynced, and its directory fsynced, before the reply, under
  the fingerprint's lock, so a duplicate request is answered only once
  the original is durable or gone; a debt that cannot be written or
  synced (its directory included) is removed, and the reply is a 500 and
  no promise ("The door"). A debt found already on file is fsynced
  again, with its directory, before it is answered as owed: a file's
  presence is never the acknowledgement, the barrier is.
- A fingerprint is in flight at most once, and payments are never
  concurrent ("Concurrency").
- The budget counts attempts, not successes: spend is recorded, against
  the current UTC day, before each `payinvoice` call — a fresh challenge
  and the retry of a stored invoice alike — and never refunded within
  the day. A retry first asks the wallet what became of the earlier call
  (`GET /payments/outgoingbyhash`): a settled one is redeemed with the
  wallet's preimage and pays nothing; an unknown one waits; only a
  definitely unpaid one is paid again, after today's reservation
  ("The debt lifecycle").
- A run of consecutive payment failures trips the circuit breaker:
  purchasing pauses, then one probe payment per exponentially doubled
  wait decides whether it resumes. The breaker lives in memory only: a
  restart starts closed and re-trips if the fault persists.
- A corrupt ledger pauses purchases, never intake, and never silently
  resets to zero.
- Debts are never dropped: intake keeps accepting while purchasing is
  paused, and the backlog drains oldest-first when it resumes.
- A paid preimage is never dropped and never re-paid: settlement outranks
  expiry ("The debt lifecycle").
- A proof is stored only if it deserialises whole, its attestation nodes
  inspected, and is a proof of the fingerprint this adapter asked for, on
  a 200 that carries a proof, on a paid redeem and on an upgrade alike; anything else
  is refused and logged `proof_wrong_digest` or `proof_invalid`, and the
  debt stays. Its pending marker is on disk (directory fsynced) before
  the proof, and if the marker cannot be made nothing is stored.
- The words: a proof is `pending` while its only attestations name a
  calendar, and `bitcoin_attestation_present` once an attestation node
  names a Bitcoin block. Both are structural states of the bytes.
  "Verified" is reserved for replaying the proof against the Bitcoin
  block header, which this adapter never does ("Verify").
- Every start reconciles the debts, the proofs and the pending index, so
  a proof stranded without its marker, or bytes stored as a proof that
  are not one, are repaired before the door opens ("Recover").
- The phoenixd password lives only in memory and an Authorization
  header: no subprocesses, so never in argv; never logged.
- No client address reaches the log or stderr: per-request logging is
  off, a reply that fails mid-write is logged as `reply_failed` with the
  exception class alone, and the server's error path (which the standard
  library would use to print the peer and a traceback) is replaced by a
  `request_error` line naming the exception class alone ("Tests",
  `test_review_fixes.py`).

## Requirements

- `python3`; the adapter imports nothing outside the standard library.
  The tests need the `opentimestamps` package as well: it is the parser
  corpus's oracle, and the suite fails without it rather than skipping.
- With `GATEWAY_URL`: a phoenixd on this host that pays the invoices, and
  its `phoenix.conf` readable by the adapter (the full `http-password`;
  paying needs it).
- With `CALENDAR_URL`: the calendar's `/digest` and `/timestamp/` reachable
  from this host.
- systemd user units, if the adapter runs as a service (`deploy/`).

## Install

```bash
LISTEN_ADDR=127.0.0.1:8402 GATEWAY_URL=http://... python3 api_endpoint.py
LISTEN_ADDR=127.0.0.1:8402 CALENDAR_URL=http://127.0.0.1:14788 DATA_DIR=... python3 api_endpoint.py
```

As a service, with `CALENDAR_URL` (`deploy/api-endpoint.service`, a user
unit; `deploy/api-endpoint.env.example`):

```bash
mkdir -p ~/appliance && cp deploy/api-endpoint.env.example ~/appliance/api-endpoint.env
cp deploy/api-endpoint.service ~/.config/systemd/user/ && systemctl --user daemon-reload
systemctl --user enable --now api-endpoint.service
```

`DATA_DIR` must be set in that file: the default is the script's own
directory.

## Operate

### The door

`POST /record`, the only route.

- **Default:** the body is the record. It is streamed through SHA-256 in
  chunks (memory stays flat whatever the size), never stored. Requires
  `Content-Length`; chunked transfer is refused with 411.
- **Pre-hashed:** send `X-Digest: sha256` and a body of exactly 64 hex
  characters. Anything else under that header is a 400.
- **Reply:** `200 received <fingerprint>`, sent only after the debt is
  durable. A debt that cannot be written gets
  `500 cannot record the debt; not received`.
- Every other method or path: 405 or 404, naming the one route.

Whatever can reach `LISTEN_ADDR` can submit records and, with
`GATEWAY_URL`, spend the budget; the address is the door's only guard.

### The filesystem

| Path | Meaning |
|---|---|
| `debts/<fp>` | owed fingerprint; written and fsynced before "received" goes out |
| `debts/<fp>.l402` | in-flight purchase: the L402 challenge with the invoice's own `payment_hash` and `amount_sats` (decoded by phoenixd), plus the preimage once paid; `attempts` / `attention` once the gateway keeps refusing that preimage |
| `proofs/<fp>.ots` | the proof: `pending` while its attestations name a calendar, `bitcoin_attestation_present` once an attestation node names a Bitcoin block (decided by deserialising the whole file, never by scanning its bytes) |
| `pending/<fp>` | empty marker for a proof still waiting for its Bitcoin attestation, written and fsynced before the proof and removed once bytes with the attestation are on disk; the upgrader works from this index and never re-reads the proofs directory, and never drops a marker whose proof is absent: silent while a debt, a sidecar or a buyer mid-way can still write it, else the marker is kept and `proof_missing` logged every pass ("Recover"); every start reconciles the index against the proofs ("Recover") |
| `ledger` | one line `YYYY-MM-DD SPENT_SATS` per UTC day: attempts, not successes |
| `heartbeat` | one line: time, pid, buyer and upgrader last-pass times, breaker state, `attention=N` paid-but-refused sidecars at the retry ceiling |
| `log` | append-only fixed-format events |

### Configuration

Precedence: invocation environment, then `.env` beside the script, then
defaults.

| Setting | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | (required) | host:port of the door, e.g. `127.0.0.1:8402` |
| `GATEWAY_URL` | one of the two | the L402 timestamp gateway this adapter buys proofs from |
| `CALENDAR_URL` | one of the two | the calendar this adapter submits to directly, e.g. `http://127.0.0.1:14788`. Exactly one of `GATEWAY_URL` and `CALENDAR_URL` is set; both or neither is a startup error naming both |
| `MAX_PRICE_SATS` | 5000 | refuse any single quote above this |
| `DAILY_BUDGET_SATS` | 200000 | refuse to exceed this per UTC day |
| `PHOENIXD_URL` | `http://127.0.0.1:9740` | the paying phoenixd |
| `PHOENIX_CONF` | `~/.phoenix/phoenix.conf` | where `http-password` is read from |
| `DATA_DIR` | the script's directory | where the filesystem above lives |
| `POLL_SECS` | 2 | buyer pass cadence |
| `UPGRADE_SECS` | 600 with `GATEWAY_URL`, 3600 with `CALENDAR_URL` | upgrader pass cadence (with `CALENDAR_URL` each pass is one loopback GET per pending proof) |
| `HEARTBEAT_SECS` | 10 | heartbeat cadence |
| `L402_EXPIRY_SECS` | 3600 | age past which an unpaid in-flight challenge is abandoned and re-challenged, logged |
| `CIRCUIT_BREAKER_FAILURES` | 5 | consecutive payment failures before purchasing pauses |
| `CIRCUIT_BREAKER_PAUSE_SECS` | 60 | initial pause; doubles per failed probe, capped at 3600 |
| `INFLIGHT` | 1 with `GATEWAY_URL`, 8 with `CALENDAR_URL` | submissions the buyer may hold in the air at once (strict positive integer); 1 is the serial pass |
| `UPGRADE_INFLIGHT` | = `INFLIGHT` | upgrade calls the upgrader may hold in the air at once (strict positive integer) |
| `GATEWAY_UPGRADE_TOKEN` | (unset) | the gateway's `UPGRADE_CLIENT_TOKEN`, presented as a bearer on `/upgrade` so this client is not throttled by the gateway's per-peer verify budget; unset, the calls are anonymous and throttled |
| `REDEEM_ATTEMPTS_MAX` | 300 | definite refusals of a paid preimage (every pass) before the sidecar is marked needs-attention |
| `REDEEM_ATTENTION_RETRY_SECS` | 3600 | how often a needs-attention sidecar is retried after that |
| `LOG_CAP_BYTES` | 16777216 | once `log` reaches this many bytes the next event renames it to `log.1` (replacing any previous `.1`) and starts fresh; 0 never rotates |

Every interval (`POLL_SECS`, `UPGRADE_SECS`, `HEARTBEAT_SECS`,
`L402_EXPIRY_SECS`, `REDEEM_ATTENTION_RETRY_SECS`,
`CIRCUIT_BREAKER_PAUSE_SECS`) is a positive, finite number of seconds;
`inf` is refused at startup like any other malformed value.

With `CALENDAR_URL` the payment settings (`PHOENIXD_URL`, `PHOENIX_CONF`,
`MAX_PRICE_SATS`, `L402_EXPIRY_SECS`, the breaker, the redeem ceilings,
`GATEWAY_UPGRADE_TOKEN`) are parsed and never used: `phoenix.conf` is not
read, no password is held, and the ledger and the `.l402` sidecars are
never written. `DAILY_BUDGET_SATS` is still compared with the ledger before
each submission; with nothing ever paid the ledger stays empty and the
check passes.

### The buyer

Every `POLL_SECS` the buyer takes the debts oldest first, each to its
next durable state. With `GATEWAY_URL` the submission is `POST
/timestamp`: a 200 that carries a proof is stored without a charge
(written atomically, the debt cleared, logged `proof_free`; the
gateway's free door, which answered so, was retired on 2026-09-18, and
the path remains for the calendar's answer); a 402 enters the paid
machinery (budget preflight, decode, ceilings, reserve, sidecar, pay,
redeem, breaker). A fingerprint whose proof already exists has its debt
cleared without another submission (`already_bought`), once the proof
and its directory have been fsynced again: the proof's presence says it
was written, not that the write's barrier held, and a pass whose
directory fsync failed leaves exactly this state (`proof_sync_failed`
and the debt kept while the barrier keeps failing).

With `CALENDAR_URL` the submission is the 32 raw digest bytes to the
calendar's counted `POST /digest`, never the operator lane
`/operator/digest`, so every record this adapter submits is counted in the
calendar's receipts. The calendar answers the serialized pending timestamp;
the adapter prefixes the detached-file header (magic, version, the sha256
op, the digest) and stores the result exactly as any 200 that carries a
proof, with the same whole-proof check, pending marker, atomic write and
`clear_debt`. The bytes are what the `ots` client writes for a single
calendar; the parser that builds and later upgrades them is a copy of the
one in the fork's `ops/selfstamp.py`, and both are held to one corpus of
proof bytes (`proof_corpus.py`, the same file in both trees) against the
opentimestamps library as the oracle: every byte consumed, every
attestation payload consumed to its end, the library's size limits at
their boundaries, two stated narrowings (only `sha256`, `append` and
`prepend`; a varuint of at most ten bytes), and the four attestation
tags the library knows read as it reads them (pending, and the Bitcoin,
Litecoin and Ethereum block-header tags; only Bitcoin counts, the other
two read as unknown). `docs/contracts.md`, "The proof parser", is the
contract. Answers that are not the
protocol are refused and the debt stays: a 402 (the URL points at a
gateway) is `challenge_failed … note=calendar_answered_402` and touches no
payment machinery; a 200 that is not a pending timestamp of this digest is
`calendar_answer_rejected`; a 503 ends the pass as a gateway 503 does.
There is no rate limiter on this path, and `INFLIGHT` sets records per
second: the calendar commits one round a second, and each submission waits
for its round.

### Concurrency

At `INFLIGHT=1` the buyer runs the serial pass: one debt at a time, oldest
first, each to completion. With `INFLIGHT=n` a pass may hold up to n
submissions in the air at once, and only submissions: the worker threads
do nothing but the HTTP call, and every answer is handled on the buyer
thread, so proof writes, `clear_debt`, the ledger, the log and the breaker
are touched by one thread exactly as at 1. A 200 that carries a proof
completes as at 1. The first sign of the paid door, a 402 or a sidecar already on disk,
ends the concurrent phase: the answers already in flight are collected,
then that debt and every remaining debt go one at a time through the same
paid machinery (budget preflight, decode, ceilings, reserve, sidecar, pay,
redeem, breaker). A collected 402 is not re-challenged; it is paid against
a fresh ledger read. A pass that has seen a 402 stays serial to its end;
the next pass starts concurrent again. A pass drains before it returns, so
a fingerprint is in flight at most once. `Retry-After` and the breaker
gate every new submission as they gate every serial debt; a stop (429,
503, gateway unreachable, ledger unreadable) lets the answers already in
flight land, then ends the pass, and any debt whose answer was lost or
deferred is owed again next pass. A failure in flight leaves its debt in
place; there is no separate retry logic.

### The debt lifecycle

owed (`debts/<fp>`) → in flight (`debts/<fp>.l402`: challenged, then paid)
→ proof (`proofs/<fp>.ots`, `pending`, with a `pending/<fp>` marker) →
`bitcoin_attestation_present`: the upgrader polls for every marker,
`UPGRADE_INFLIGHT` at a time, until the proof, deserialised whole, has an
attestation node that names a Bitcoin block, and the marker goes once
those bytes are on disk. The marker, the proof and the debt change hands
under the fingerprint's lock, and a marker whose proof is absent is never
dropped while a debt exists. Debts and sidecars carry everything across a
death; there is no shutdown sequence.

A sidecar holding an invoice and no preimage — the process died between
the `payinvoice` call and its answer, or the call failed — is not re-paid
on a guess. The wallet is asked first (`GET
/payments/outgoingbyhash/<payment_hash>`, the hash stored in the sidecar
at challenge time): a payment it reports succeeded is redeemed with the
preimage it holds, logged `payment_reconciled`, nothing paid and nothing
reserved; one still in flight, or a wallet that cannot say, waits
(`payment_outcome_unknown … note=awaiting_wallet`); one it reports failed
or never sent (204: phoenixd records an outgoing payment before it sends)
is definitely unpaid, and the retry reserves today's budget (the same
preflight, ceiling and ledger write as a fresh challenge, logged
`payment_retry_reserved`) before paying the stored invoice again. Until
2026-09-15 the retry paid against the reservation of the day the invoice
was minted, so an invoice reserved yesterday could settle today with
today's whole budget still open (review finding A7); the sidecars of
that era carry no hash or amount and are decoded from their stored
invoice first. A stale unpaid challenge past `L402_EXPIRY_SECS` is
abandoned and re-challenged, logged `rechallenge_after_unknown_payment …
note=possible_double_charge`: the one edge where a double charge cannot
be ruled out.

A paid preimage the gateway keeps refusing (after an L402 secret rotation
every stored macaroon is a 401) is never dropped and never re-paid:
settlement outranks expiry. It is retried every pass up to
`REDEEM_ATTEMPTS_MAX` definite refusals (a 503 is "not now": it ends the
pass and counts nothing), then the sidecar carries `attempts` and an
`attention` time, one `redeem_needs_attention` line is logged, the
heartbeat's `attention=N` counts such sidecars, and the retry continues
once per `REDEEM_ATTENTION_RETRY_SECS` without further log lines. A
gateway that accepts the token again heals it on the next slow retry; to
retry at once, delete the `attention` key from the sidecar.

### The upgrader

Every `UPGRADE_SECS` the upgrader asks about each proof in the pending
index, `UPGRADE_INFLIGHT` at a time (the worker threads do only the HTTP
call; every answer, file write and marker is handled on the upgrader
thread). With `GATEWAY_URL` it POSTs the proof to `/upgrade` (JSON in and
out, the proof base64 both ways, `GATEWAY_UPGRADE_TOKEN` as a bearer when
set). With `CALENDAR_URL` it walks the pending proof to its commitment and
asks `GET /timestamp/<commitment>`: 404 while the anchor is not yet deep,
the path to the Bitcoin attestation once it is, spliced in at the
attestation marker. In both, the file is replaced only when the answer is
anchored, its bytes deserialise whole with an attestation node that names
a Bitcoin block, and they are a proof of the same digest
(`proof_wrong_digest` otherwise, the pending proof and its marker kept);
the marker is cleared after those bytes are on disk and
`bitcoin_attestation_present` is logged. A proof the adapter cannot walk
(a fork marker, which a proof from one calendar never has) is logged
`upgrade_needs_attention status=nonlinear` with its marker kept. A proof
found already anchored with its marker still standing (a pass that died,
or whose directory fsync failed, between the write and the marker) is
fsynced with its directory again before the marker goes
(`upgrade_sync_failed`, marker kept, while that fails). A pending index
that cannot be listed is an error, logged `upgrader_error` and asked
again next pass, never a pass that found nothing to do.

### Switching configurations

A `DATA_DIR` that lived with `GATEWAY_URL` can hold in-flight purchases
(`debts/<fp>.l402`); with `CALENDAR_URL` nothing can pay or redeem them,
so such a debt is skipped, logged once
(`sidecar_needs_attention … note=left_by_gateway_mode`), and waits for the
operator to settle it under `GATEWAY_URL` or remove the sidecar.

### Log rotation

The `log` file is append-only. Once it reaches `LOG_CAP_BYTES` (16 MiB by
default) the next event renames it to `log.1`, replacing any previous
`.1`, and starts a fresh `log`, so at most two generations exist on disk.
The check runs under the log lock on the single writer path, and each
event opens, appends and closes the file, so an external rename-based
logrotate is safe as well; `LOG_CAP_BYTES=0` hands rotation to it
entirely.

## Verify

A proof is `bitcoin_attestation_present` when, deserialised whole, one of
its attestation nodes names a Bitcoin block; until then it is `pending`,
a receipt naming a calendar, and `pending/<fp>` exists. Both are
structural states of the file: neither replays the proof against the
Bitcoin block header, so neither is "verified", and the adapter never
uses that word. The `heartbeat` line carries the buyer's and upgrader's
last passes, the breaker state and the count of sidecars at the retry
ceiling; the `log` carries each event. Verifying a proof against Bitcoin
is the calendar's and gateway's documentation (fork README, "Verify": the
claim kit, or `ots verify`).

## Recover

Debts and sidecars carry everything across a death; there is no shutdown
sequence. Every start, before the door opens, reconciles `DATA_DIR`
(`reconciled …` in the log, with counts): each proof is deserialised
whole; a `pending` proof without its marker gets it back
(`pending_marker_restored`); a proof with a Bitcoin attestation loses a
stale marker; bytes that are not one whole proof of their fingerprint
get their debt re-created first, durably, and are then set aside as
`<fp>.ots.invalid-<time>`, so the buyer fetches a proper proof
(`proof_invalid_requeued`); an aside file found with neither a proof nor
a debt for its fingerprint (left by the code before 2026-09-16, which
moved the bytes before it wrote the debt) gets its debt back
(`aside_requeued`); a marker with neither proof nor debt is kept and
reported (`proof_missing`, counted in `reconciled` as `proofs_missing`,
at every start and by the upgrader every pass until it is resolved): it
is the last sign of a promise whose proof is gone, an accidental
deletion or an incomplete restore, and the adapter never buys a proof in
its place, since one bought now carries a later bound and is not the one
promised; a copy of the original put back as `proofs/<fp>.ots` is what
resolves it, and the upgrader then resumes from the marker (2026-09-21
year-of-operation review, scenario 18: the marker used to be dropped,
and the promise vanished without a trace).
Every step is idempotent, so a stop anywhere in the repair is repaired
again the same way at the next start; a parser given any bytes answers
`INVALID`, never an exception (2026-09-15/16 review F01, F13). This
repairs an installation stranded by the marker race or by a header-only
"proof" that earlier releases accepted, whether or not `.built` exists.
Then the buyer starts with the
breaker closed and the debts oldest first, resuming in-flight sidecars as
above. What to keep is `DATA_DIR`: the proofs, the debts and sidecars,
the pending markers, the ledger, and the log. The durability tests inject
errors and interrupted writes at the write boundaries and kill the
process; a power cut is not simulated, and the fsyncs are what a power
cut relies on.

## What it does not do

- Store, log, or otherwise keep a record's bytes; only the SHA-256 leaves
  the request.
- Guard the door: `LISTEN_ADDR` is the only guard, and whatever can reach
  it can submit records and, with `GATEWAY_URL`, spend the budget; there
  is no rate limiter on the calendar path.
- Rule out a double charge in one edge: an unpaid in-flight challenge
  whose payment outcome stayed unknown past `L402_EXPIRY_SECS` is
  re-challenged, and the log says so.
- Keep the breaker across a restart: it starts closed and re-trips if the
  fault persists.
- Upgrade a proof with a fork marker; it is logged and kept.
- Exercised only in the test suite, not against live systems: `INFLIGHT`
  greater than 1 against a live phoenixd, gateway-side rate limiting under
  a real burst, sustained volume on the paid door, long-horizon breaker
  behaviour against a real gateway outage, restart with a large debt
  backlog, and `CALENDAR_URL` against a live calendar through a live
  anchor cycle.

## Tests

The suite, 99 tests in three files, needs no network, no phoenixd and
no calendar (both are faked in-process), and needs the `opentimestamps`
package, the parser corpus's oracle: without it the corpus tests fail
rather than skip.

```bash
python3 -m unittest discover -v
```

What it pins, by test name. The door contract, including the 411, 400 and
405 refusals and the durable-debt-before-received ordering; the budget,
breaker and ledger rules; attestation-present-versus-pending detection
against real proofs (`test_anchored_detector_against_real_proofs`, on the two proofs in
`fixtures/`). The crash and money invariants:
`test_sigkill_mid_burst_every_acked_record_bought`,
`test_kill_inside_pay_to_redeem_window_exactly_one_payment`,
`test_corrupt_ledger_pauses_purchases_never_intake`. A proof of somebody
else's digest refused on every path:
`test_free_door_wrong_digest_refused_then_bought`,
`test_paid_redeem_wrong_digest_refused`,
`test_upgrade_wrong_digest_refused_keeps_pending`. The backlog finishing
and the pending index built once:
`test_upgrade_backlog_finishes_with_the_client_token`,
`test_pending_index_built_once_from_the_proofs_dir`. A paid preimage the
gateway keeps refusing hitting the ceiling once, never re-paid, and
healing on the slow retry:
`test_ceiling_marks_attention_once_and_keeps_the_preimage`,
`test_at_the_ceiling_the_retry_is_slow_and_a_fixed_gateway_heals_it`,
`test_503_counts_nothing`. Log rotation:
`test_log_rotates_to_dot1_at_cap_and_replaces_previous`,
`test_log_cap_zero_never_rotates`,
`test_log_cap_knob_default_and_validation`.

`INFLIGHT=8` against a stub free gateway that measures how many
submissions it holds per fingerprint and in total (each test also checks
the overlap really happened): SIGKILL mid-flight then restart converges to
exactly one proof per acknowledged record with no debt lost and a
proof-written-debt-uncleared straggler absorbed by `already_bought` without
another submission
(`test_inflight_sigkill_mid_flight_converges_one_proof_each`); no
fingerprint is ever in flight twice at once, within a pass, across passes
after a transient 500, or under a duplicate POST
(`test_inflight_fingerprint_in_flight_at_most_once`); a door that flips
from proofs to 402 mid-pass sends the pass serial with one challenge, one
invoice, one reservation, one payment and one redeem per paid debt,
payments never overlapping, oldest first
(`test_inflight_door_flips_to_paid_mid_pass_goes_serial`); 429 stops new
submissions until `Retry-After` elapses and buying then resumes
(`test_inflight_429_stops_new_submissions`); the breaker trips on the
third refused payment and freezes submissions
(`test_inflight_breaker_trips_and_stops_submissions`); the setting is a
strict positive integer defaulting to 1
(`test_inflight_knob_strict_positive_int_default_one`).

`test_review_fixes.py` holds the 2026-09-15 and 2026-09-16 reviews'
findings as regressions, each failing on the code before the fix: the
structural states decided by attestation nodes and never by a byte scan;
intake's per-fingerprint lock, directory-fsync errors propagated, short
writes completed; the marker kept while a debt exists, fatal when it
cannot be made, fsynced before the debt is cleared; header-only and
trailing-byte answers refused; the debt durable before an invalid proof
is moved aside, and a stranded aside file requeued; a failed cleanup
after a failed debt write logged (`debt_cleanup_failed`: the 500
promises only that acceptance was not confirmed); a trailing fork
marker and every attestation payload not consumed whole refused as
`INVALID`, and `inspect_proof` never raising over thousands of mutated
and random inputs; the smoke script naming only functions that exist;
the startup reconciliation, on the objects and with the
real service; and the quiet server on a client disconnect. The
2026-09-18 cold review's findings are there too: a file found on disk
fsynced again, with its directory, before intake acknowledges it, the
buyer clears the debt behind it or the upgrader clears the marker behind
it, the barrier failing on the write and again on the retry and then
holding (`TestResumedBarriers`); a pending index that cannot be listed
raised, logged by the upgrader's loop every pass and refused at the start,
never read as empty (`TestPendingIndexListing`); every interval a
positive, finite number (`TestIntervalConfig`).

`CALENDAR_URL`, against a fake calendar speaking the fork's protocol:
exactly one of the two URLs, and the calendar-mode defaults
(`test_calendar_mode_config_exactly_one_url`); every submission is the 32
raw digest bytes to the counted `/digest` and the stored proof is the
header plus the calendar's answer
(`test_calendar_mode_submits_raw_digest_to_counted_digest_path`); no
`phoenix.conf`, no phoenixd call, no ledger, no sidecar
(`test_calendar_mode_never_reads_phoenix_or_writes_ledger_or_sidecar`); a
402, a 503 and a non-protocol 200 each keep the debt and pay nothing
(`test_calendar_mode_402_is_refused_without_payment`,
`test_calendar_mode_503_stops_the_pass_and_keeps_the_debt`,
`test_calendar_mode_garbage_answer_keeps_debt`); the upgrade stays pending
on 404, splices the Bitcoin path once mined, keeps the digest, clears the
marker and never asks again
(`test_calendar_mode_upgrade_404_stays_pending_then_anchored_bytes_spliced`);
a non-linear proof keeps its marker
(`test_calendar_mode_nonlinear_proof_needs_attention_keeps_marker`);
`INFLIGHT=8` overlaps and never holds one fingerprint twice
(`test_calendar_mode_inflight_eight_hits_digest_once_per_fingerprint`); the
proof bytes round-trip through the opentimestamps library
(`test_ots_parser_cross_checks_with_the_library`).

`test_proof_corpus.py` runs the corpus in `proof_corpus.py` against
both readers and against the library, which the suite requires: what
parses for one parses for the other, with the two narrowings named;
every strict prefix and one-byte extension of every valid proof is
invalid for both; each of the four attestation tags the library knows
is read as it reads it, a valid, an empty, a trailing and an
unterminated payload each, alone and beside a Bitcoin node. The integration tests wait for the log line a
transition ends with (`bought`, `proof_free`, `already_bought`,
`bitcoin_attestation_present`), never for a file that appears midway
(2026-09-15/16 review F22: assertions raced the proof's rename).

The live smoke, `GATEWAY_URL=http://... ./smoke.sh`, buys exactly one
proof through the whole door, debt, pay, proof path and leaves it in
`proofs/`. A well-formed pending proof is the pass; anchoring arrives later
through the upgrader.

Measured: `INFLIGHT=24` against a live gateway sustained about 20 free
proofs a second where the serial path sustains 1; on 2026-09-09, 2.7
million pending proofs were upgraded against the live gateway and its
calendar at about 150 a second.
