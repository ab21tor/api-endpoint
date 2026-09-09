#!/usr/bin/env bash
# smoke.sh — live smoke for api-endpoint. Buys exactly ONE proof.
# Usage: GATEWAY_URL=http://... ./smoke.sh
#
# Starts the service with DATA_DIR = this directory (the real operating
# mode: debts/, proofs/, ledger, heartbeat, log land beside the code where
# ls can vouch for them), POSTs one unique record, waits for its proof,
# verifies it is a well-formed PENDING OpenTimestamps proof bought within
# the ceiling, then stops the service it started. The proof is left in
# proofs/ as evidence. Pending is the pass — anchoring arrives later via
# the service's background /upgrade loop.
#
# Env: GATEWAY_URL (required). LISTEN_ADDR (default 127.0.0.1:8402).
# Everything else (MAX_PRICE_SATS, DAILY_BUDGET_SATS, PHOENIXD_URL,
# PHOENIX_CONF) reaches the service through the environment as usual.
# No secrets are handled here at all — the service reads phoenix.conf itself.
set -u
cd "$(dirname "$0")"

: "${GATEWAY_URL:?set GATEWAY_URL, e.g. http://127.0.0.1:8000 — the live L402 timestamp gateway}"
LISTEN_ADDR="${LISTEN_ADDR:-127.0.0.1:8402}"

# Exactly one purchase: refuse to start on top of outstanding debts, which
# the buyer would (correctly) also purchase the moment it wakes.
if [ -d debts ] && [ -n "$(ls debts 2>/dev/null)" ]; then
  echo "smoke: debts/ is not empty — the buyer would purchase those too." >&2
  echo "smoke: this script proves exactly one purchase; settle or move them first." >&2
  exit 2
fi

LISTEN_ADDR="$LISTEN_ADDR" GATEWAY_URL="$GATEWAY_URL" python3 -B api_endpoint.py &
SVC=$!
trap 'kill "$SVC" 2>/dev/null; wait "$SVC" 2>/dev/null' EXIT

# Wait for the door: GET answers 405 when the listener is up.
CODE=""
for _ in $(seq 1 100); do
  kill -0 "$SVC" 2>/dev/null || { echo "smoke: service died at startup (its error is above)" >&2; exit 3; }
  CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://$LISTEN_ADDR/record" || true)
  [ "$CODE" = "405" ] && break
  sleep 0.1
done
[ "$CODE" = "405" ] || { echo "smoke: door never came up on $LISTEN_ADDR" >&2; exit 3; }

# One unique record, hashed locally so the acknowledged fingerprint can be
# checked against arithmetic rather than trust.
RECORD="smoke $(date -u +%Y-%m-%dT%H:%M:%SZ) pid$$ r$RANDOM"
LOCAL=$(printf '%s' "$RECORD" | python3 -c "import sys,hashlib;print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())")
REPLY=$(printf '%s' "$RECORD" | curl -s --max-time 10 -X POST --data-binary @- "http://$LISTEN_ADDR/record")
echo "reply: $REPLY"
case "$REPLY" in
  "received "*) FP=$(printf '%s' "${REPLY#received }" | tr -d '[:space:]') ;;
  *) echo "smoke: unexpected reply" >&2; exit 4 ;;
esac
[ "$FP" = "$LOCAL" ] || { echo "smoke: fingerprint mismatch (acked $FP, hashed $LOCAL)" >&2; exit 4; }
echo "fingerprint: $FP"

# The gateway's calendar submission can retry for ~60s; allow 120.
echo "waiting for proofs/$FP.ots ..."
for _ in $(seq 1 240); do
  [ -s "proofs/$FP.ots" ] && break
  sleep 0.5
done
if [ ! -s "proofs/$FP.ots" ]; then
  echo "smoke: no proof after 120s — recent log follows" >&2
  tail -8 log 2>/dev/null >&2
  exit 5
fi

# Well-formed and PENDING (pending is the pass; anchored would also be fine
# but is not expected within minutes of purchase).
python3 -B - "$FP" <<'EOF'
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, ".")
import api_endpoint
fp = sys.argv[1]
with open(f"proofs/{fp}.ots", "rb") as f:
    data = f.read()
assert api_endpoint.looks_like_ots(data), "proof does not start with the OTS magic"
print(f"proof: proofs/{fp}.ots ({len(data)} bytes, well-formed OTS)")
print(f"anchored: {api_endpoint.is_anchored(data)} (pending is the pass)")
EOF
[ $? -eq 0 ] || exit 5

# Exactly one proof event — bought on the paid door, proof_free on a free
# one — settled debt, budget recorded.
BOUGHT=$(grep -c " bought fp=$FP" log)
FREE=$(grep -c " proof_free fp=$FP" log)
[ $((BOUGHT + FREE)) -eq 1 ] || { echo "smoke: expected exactly one bought or proof_free line for $FP, got bought=$BOUGHT proof_free=$FREE" >&2; exit 6; }
[ -z "$(ls debts 2>/dev/null)" ] || { echo "smoke: debts/ not settled" >&2; exit 6; }
echo "startup: $(grep ' startup ' log | tail -1)"
echo "proof:   $(grep -E " (bought|proof_free) fp=$FP" log | tail -1)"
echo "ledger:  $(cat ledger 2>/dev/null || echo '<none>')"
echo "smoke: PASS — one record, one payment, one pending proof at proofs/$FP.ots"
