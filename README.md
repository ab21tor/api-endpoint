# api-endpoint

The client adapter that hides Lightning. Client systems POST records to a
local door; each record is SHA-256-fingerprinted **in memory** — raw bytes
are never written and never logged — and each fingerprint buys its own
OpenTimestamps proof from an L402 timestamp gateway, paid via the payer
phoenixd. The client system never sees an invoice, a macaroon, or a
preimage: it POSTs bytes and, later, a proof file exists.

One route. Everything else is the filesystem.

## The one route

`POST /record`

- **Default:** the body is the record. It is streamed through SHA-256 in
  chunks (memory stays flat whatever the size), never stored. Requires
  `Content-Length` (chunked transfer is refused with 411).
- **Pre-hashed:** send `X-Digest: sha256` and a body of exactly 64 hex
  characters. Anything else under that header is a 400.
- **Reply:** `200 received <fingerprint>` — sent only after the debt is
  durable (see below). A body that cannot be made durable gets
  `500 cannot record the debt; not received`: no debt, no promise.
- Every other method or path: 405/404 naming the one route.

## The filesystem is the API

| Path | Meaning |
|---|---|
| `debts/<fp>` | owed fingerprint; written and fsynced **before** "received" goes out — the debt is the promise |
| `debts/<fp>.l402` | in-flight purchase: the L402 challenge, plus the preimage once paid |
| `proofs/<fp>.ots` | the bought proof; anchored once its bytes carry a Bitcoin block-header attestation |
| `ledger` | one line `YYYY-MM-DD SPENT_SATS` per UTC day — attempts, not successes |
| `heartbeat` | one line: time, pid, buyer/upgrader last-pass times, breaker state |
| `log` | append-only fixed-format events |

## Config

Precedence: invocation env > `.env` beside the script > defaults.

| Knob | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | (required) | host:port of the door, e.g. `127.0.0.1:8402` |
| `GATEWAY_URL` | (required) | the L402 timestamp gateway |
| `MAX_PRICE_SATS` | 5000 | refuse any single quote above this |
| `DAILY_BUDGET_SATS` | 200000 | refuse to exceed this per UTC day |
| `PHOENIXD_URL` | `http://127.0.0.1:9740` | payer phoenixd |
| `PHOENIX_CONF` | `~/.phoenix/phoenix.conf` | http-password source |
| `DATA_DIR` | script's directory | where the filesystem API lives |
| `POLL_SECS` | 2 | buyer pass cadence |
| `UPGRADE_SECS` | 600 | upgrader pass cadence (slow, free) |
| `HEARTBEAT_SECS` | 10 | heartbeat cadence |
| `L402_EXPIRY_SECS` | 3600 | age past which an unpaid in-flight challenge is abandoned and re-challenged, loudly |
| `CIRCUIT_BREAKER_FAILURES` | 5 | consecutive payment failures before purchasing pauses |
| `CIRCUIT_BREAKER_PAUSE_SECS` | 60 | initial pause; doubles per failed probe, capped at 3600 |
| `INFLIGHT` | 1 | gateway submissions the buyer may hold in the air at once (strict positive int); 1 = the serial pass |
| `LOG_CAP_BYTES` | 16777216 | once `log` reaches this many bytes the next event renames it to `log.1` (replacing any previous `.1`) and starts fresh; 0 = never rotate |

## Money rules

- The budget counts **attempts**, not successes: spend is recorded before
  each payinvoice call and never refunded intra-day. Fail closed.
- A run of consecutive payment failures trips the circuit breaker:
  purchasing pauses, then one probe payment per exponentially-doubled wait
  decides whether it resumes. The breaker lives in memory only — a restart
  starts closed and re-trips if the fault persists.
- A corrupt ledger pauses purchases, never intake, and never silently
  resets to zero.
- Debts are never dropped. Intake keeps accepting while purchasing is
  paused; the backlog drains oldest-first when it resumes.
- The phoenixd password lives only in memory and an Authorization header —
  no subprocesses, so never in argv; never logged.

## Concurrency: `INFLIGHT`

At the default, `INFLIGHT=1`, the buyer runs the serial pass unchanged:
one debt at a time, oldest first, each to completion. With `INFLIGHT=n`
(n > 1) a pass may hold up to n `/timestamp` submissions in the air at
once — only submissions. The worker threads do nothing but the HTTP call;
every answer is handled on the buyer thread, so proof writes, `clear_debt`,
the ledger, the log and the breaker are touched by one thread exactly as
at 1. A free-door answer (200 + proof) completes as today: atomic proof
write, debt cleared, `proof_free`. The first sign of the paid door — a 402,
or a sidecar already on disk — ends the concurrent phase: the answers
already in flight are collected, then that debt and every remaining debt
go one at a time through the same paid machinery as at 1 (budget preflight,
decode, ceilings, reserve, sidecar, pay, redeem, breaker). A collected 402
is not re-challenged; it is paid against a fresh ledger read. Payments are
never concurrent. A pass that has seen a 402 stays serial to its end; the
next pass starts concurrent again. A fingerprint is in flight at most once:
a pass drains before it returns. Retry-After and the breaker gate every
new submission as they gate every serial debt; a stop (429, 503, gateway
unreachable, ledger unreadable) lets the answers already in flight land,
then ends the pass, and any debt whose answer was lost or deferred is
owed again next pass. A failure in flight leaves its debt in place;
there is no new retry logic.

Proven at `INFLIGHT=8` against a stub free gateway that measures how many
submissions it holds per fingerprint and in total (each test also checks
the overlap really happened): SIGKILL mid-flight then restart converges to
exactly one proof per acknowledged record with no debt lost and a
proof-written-debt-uncleared straggler absorbed by `already_bought` without
another submission (`test_inflight_sigkill_mid_flight_converges_one_proof_each`);
no fingerprint is ever in flight twice at once — within a pass, across
passes after a transient 500, or under a duplicate POST
(`test_inflight_fingerprint_in_flight_at_most_once`); a door that flips
from proofs to 402 mid-pass sends the pass serial with one challenge, one
invoice, one reservation, one payment and one redeem per paid debt,
payments never overlapping, oldest first
(`test_inflight_door_flips_to_paid_mid_pass_goes_serial`); 429 stops new
submissions until Retry-After elapses and buying then resumes
(`test_inflight_429_stops_new_submissions`); the breaker trips on the
third refused payment and freezes submissions
(`test_inflight_breaker_trips_and_stops_submissions`); the knob is a strict
positive integer defaulting to 1
(`test_inflight_knob_strict_positive_int_default_one`). `INFLIGHT=24` has
run against a live gateway and sustained about 20 free proofs per second
where the serial path sustains 1. **Unproven: `INFLIGHT` > 1 against a
live phoenixd, and gateway-side rate limiting under a real burst — the
stub never throttles unless told to.**

## Debt lifecycle

owed (`debts/<fp>`) → in-flight (`debts/<fp>.l402`: challenged, then paid)
→ proof (`proofs/<fp>.ots`, pending) → anchored (the free upgrader loop
polls `/upgrade` until the proof's bytes carry a Bitcoin block-header
attestation). A stale unpaid challenge past `L402_EXPIRY_SECS` is
abandoned and re-challenged, loudly. Debts and sidecars carry everything
across a death; there is no shutdown sequence.

## Running it

```bash
LISTEN_ADDR=127.0.0.1:8402 GATEWAY_URL=http://... python3 api_endpoint.py
```

The suite (26 tests, no network, no phoenixd):

```bash
python3 -m unittest test_api_endpoint -v
```

The live smoke (`GATEWAY_URL=http://... ./smoke.sh`) buys exactly **one**
real proof through the whole door→debt→pay→proof path and leaves it in
`proofs/` as evidence. A well-formed *pending* proof is the pass —
anchoring arrives later via the upgrader.

## Log rotation

The `log` file is append-only, roughly a few hundred bytes per record
across its lifecycle events (about 34 MB a day at the live demo's volume).
It rotates itself: once it reaches `LOG_CAP_BYTES` (16 MiB by default) the
next event renames it to `log.1`, replacing any previous `.1`, and starts a
fresh `log`, so at most two generations exist on disk. This is the same
cap-and-rename shape the demo feeder uses for its manifest. The check runs
under the log lock on the single writer path, and `log_event` still
opens-appends-closes per line, so an external rename-based logrotate
remains safe if longer retention is wanted; set `LOG_CAP_BYTES=0` to hand
rotation to it entirely. Proven by `test_log_rotates_to_dot1_at_cap_and_replaces_previous`,
`test_log_cap_zero_never_rotates` and `test_log_cap_knob_default_and_validation`.

## Claims, labelled

Proven by the 29-test suite and the live smoke: the door contract
(including 411/400/405 refusals and the durable-debt-before-received
ordering), the budget/breaker/ledger rules, anchored-vs-pending detection
against real fixture proofs, the `INFLIGHT` pins listed above, and one
live pending purchase within the ceiling. The four crash/money invariants,
by test name:
`test_sigkill_mid_burst_every_acked_record_bought`,
`test_kill_inside_pay_to_redeem_window_exactly_one_payment`,
`test_corrupt_ledger_pauses_purchases_never_intake`,
`test_anchored_detector_against_real_proofs`.

**Unproven: the live anchored upgrade end-to-end (the upgrader has only
been proven against fixtures, not a live anchor cycle), sustained volume,
long-horizon breaker behaviour against a real gateway outage, and restart
with a large debt backlog.**
