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

The suite (20 tests, no network, no phoenixd):

```bash
python3 -m unittest test_api_endpoint -v
```

The live smoke (`GATEWAY_URL=http://... ./smoke.sh`) buys exactly **one**
real proof through the whole door→debt→pay→proof path and leaves it in
`proofs/` as evidence. A well-formed *pending* proof is the pass —
anchoring arrives later via the upgrader.

## Log rotation

The `log` file is append-only and unbounded by design — roughly a few
hundred bytes per record across its lifecycle events, which is gigabytes
per year at sustained volume. Nothing in the daemon reads it back, and
`log_event` opens-appends-closes per line, so plain rename-based logrotate
is safe with no signal, no copytruncate, and no restart — the next event
creates a fresh `log`:

```
/path/to/data-dir/log {
    monthly
    rotate 12
    compress
    missingok
    notifempty
}
```

## Claims, labelled

Proven by the 20-test suite and the live smoke: the door contract
(including 411/400/405 refusals and the durable-debt-before-received
ordering), the budget/breaker/ledger rules, anchored-vs-pending detection
against real fixture proofs, and one live pending purchase within the
ceiling. The four crash/money invariants, by test name:
`test_sigkill_mid_burst_every_acked_record_bought`,
`test_kill_inside_pay_to_redeem_window_exactly_one_payment`,
`test_corrupt_ledger_pauses_purchases_never_intake`,
`test_anchored_detector_against_real_proofs`.

**Unproven: the live anchored upgrade end-to-end (the upgrader has only
been proven against fixtures, not a live anchor cycle), sustained volume,
long-horizon breaker behaviour against a real gateway outage, and restart
with a large debt backlog.**
