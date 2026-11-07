#!/usr/bin/env bash
# End-to-end smoke test: real binary + local fake upstream. Run cargo build first.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${KEYSINK_BIN:-$ROOT/target/debug/keysink}"
UP_PORT="${UP_PORT:-19090}"
GW_PORT="${GW_PORT:-18787}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/keysink-smoke.XXXXXX")"
VAULT="$TMP/vault"

if [[ ! -x "$BIN" ]]; then
  echo "$BIN not found; run cargo build first" >&2
  exit 1
fi

GATEWAY_PID=""
cleanup() {
  if [[ -n "$GATEWAY_PID" ]]; then kill "$GATEWAY_PID" 2>/dev/null || true; fi
  kill "$UP_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

wait_health() {
  for _ in $(seq 1 50); do
    if curl -sf "http://127.0.0.1:$GW_PORT/__keysink/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "gateway did not start" >&2
  cat "$TMP/gw.log" >&2 || true
  return 1
}

ks() { "$BIN" --home "$VAULT" "$@"; }
# route add/rotate prints the vkey only once, so the smoke test grabs it from stdout.
new_vkey() { sed -n 's/^vkey: //p'; }

python3 "$ROOT/scripts/fake_upstream.py" "$UP_PORT" >"$TMP/up.log" 2>&1 &
UP_PID=$!
sleep 0.3

echo "== init vault =="
printf 'test-pass\n' | ks init --password-stdin >/dev/null
VKEY="$(printf 'real-key-123\n' | ks route add echo --base-url "http://127.0.0.1:$UP_PORT" \
  --auth bearer --header 'x-static: from-keysink' | new_vkey)"
# stat permission output differs between GNU and BSD; use python3 (which smoke
# already depends on) for a portable check
python3 -c 'import os,sys; sys.exit(0 if oct(os.stat(sys.argv[1]).st_mode)[-3:]=="600" else 1)' \
  "$VAULT/vault.key"

echo "== export needs master password =="
if ks export --output "$TMP/e1.age" --password-stdin <<< '' >/dev/null 2>&1; then
  echo "export succeeded with an empty password" >&2
  exit 1
fi
if ks export --output "$TMP/e2.age" --password-stdin <<< 'wrong' >/dev/null 2>&1; then
  echo "export succeeded with a wrong password" >&2
  exit 1
fi

"$BIN" --home "$VAULT" serve --listen "127.0.0.1:$GW_PORT" >"$TMP/gw.log" 2>&1 &
GATEWAY_PID=$!
wait_health

echo "== echo passthrough =="
RESP="$(curl -sS -X POST "http://127.0.0.1:$GW_PORT/echo?x=1&y=2" \
  -H "Authorization: Bearer $VKEY" \
  -H 'Content-Type: application/json' \
  -d '{"stream":false,"hello":"world"}')"
echo "$RESP" | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("path:", d["path"])
print("auth:", d["headers"].get("authorization"))
print("static:", d["headers"].get("x-static"))
print("body:", d["body"])
assert d["path"]=="/echo?x=1&y=2", d["path"]
assert d["headers"].get("authorization")=="Bearer real-key-123"
assert d["headers"].get("x-static")=="from-keysink"
assert "ks_" not in json.dumps(d), "vkey leaked upstream"
'

echo "== invalid vkey =="
CODE="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$GW_PORT/echo" -H 'Authorization: Bearer ks_invalid')"
test "$CODE" = "401"

echo "== sse =="
SSE="$(curl -sS -N -X POST "http://127.0.0.1:$GW_PORT/sse" \
  -H "Authorization: Bearer $VKEY" -H 'Content-Type: application/json' -d '{"stream":true}')"
echo "$SSE" | grep -q 'data: \[DONE\]'
echo "$SSE" | grep -q '"i":2'

echo "== retry 429 =="
RETRY="$(curl -sS -X POST "http://127.0.0.1:$GW_PORT/retry" \
  -H "Authorization: Bearer $VKEY" -H 'Content-Type: application/json' -d '{"stream":false}')"
echo "$RETRY" | grep -q '"retry_count": 2'

echo "== sse terminator split across chunks =="
SPLIT="$(curl -sS -N -X POST "http://127.0.0.1:$GW_PORT/sse_split" \
  -H "Authorization: Bearer $VKEY" -H 'Content-Type: application/json' -d '{"stream":true}')"
echo "$SPLIT" | grep -q 'data: \[DONE\]'
if echo "$SPLIT" | grep -q 'ended prematurely'; then
  echo "SSE terminator split across chunks misjudged as truncation" >&2
  exit 1
fi

echo "== truncated sse =="
TRUNC="$(curl -sS -N -X POST "http://127.0.0.1:$GW_PORT/truncate" \
  -H "Authorization: Bearer $VKEY" -H 'Content-Type: application/json' -d '{"stream":true}')"
echo "$TRUNC" | grep -q 'upstream stream ended prematurely'

echo "== client abort mid-sse leaves gateway alive =="
# Client disconnects mid-stream (curl killed by timeout); the gateway must survive (SIGPIPE regression case)
curl -sS -N --max-time 0.08 -X POST "http://127.0.0.1:$GW_PORT/sse" \
  -H "Authorization: Bearer $VKEY" -H 'Content-Type: application/json' \
  -d '{"stream":true}' >/dev/null 2>&1 || true
sleep 0.5
curl -sf "http://127.0.0.1:$GW_PORT/__keysink/health" >/dev/null || {
  echo "gateway unreachable after client disconnect (suspected SIGPIPE)" >&2
  exit 1
}

echo "== route update keeps vkey =="
ks route update echo --note updated >/dev/null
# No grep -q: it exits on first match while keysink (SIGPIPE fatal by default)
# may still have pending output; under pipefail the whole pipeline then dies
# with 141 spuriously. grep without -q reads its input to EOF — deterministic.
ks route show echo | grep 'updated' >/dev/null
# The vkey cannot be read back, so verify directly that the old vkey still works
CODE="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$GW_PORT/echo" \
  -H "Authorization: Bearer $VKEY" -H 'Content-Type: application/json' -d '{}')"
test "$CODE" = "200"
ks route update echo --clear-headers >/dev/null
ks route show echo | grep 'x-static' >/dev/null && { echo "--clear-headers did not take effect" >&2; exit 1; }
ks route update echo --header 'x-static: from-keysink' >/dev/null

echo "== hot reload (route add) =="
HOTOUT="$(printf 'real-key-123\n' | ks route add echo2 --base-url "http://127.0.0.1:$UP_PORT" --auth x-api-key)"
VKEY2="$(echo "$HOTOUT" | new_vkey)"
# Gateway already running: route add must report the actual listen address (gateway.addr runtime file)
# ${GW_PORT} is delimited explicitly: old bash (macOS 3.2) would parse a
# directly following fullwidth character into the variable name
echo "$HOTOUT" | grep -q "gateway: http://127.0.0.1:${GW_PORT} (running)" || {
  echo "route add did not report the running listen address: $HOTOUT" >&2
  exit 1
}
sleep 1.5
RESP2="$(curl -sS -X POST "http://127.0.0.1:$GW_PORT/echo2" -H "x-api-key: $VKEY2" \
  -H 'Content-Type: application/json' -d '{}')"
echo "$RESP2" | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d["headers"].get("x-api-key")=="real-key-123", d["headers"].get("x-api-key")
assert "authorization" not in d["headers"]
'

echo "== route-only key + export strips key values =="
VKEY3="$(printf 'inline-key-xyz\n' | ks route add inline-route \
  --base-url "http://127.0.0.1:$UP_PORT" --route-key --auth bearer | new_vkey)"
sleep 1.5
ks route show inline-route | grep 'route-only' >/dev/null
RESP3="$(curl -sS -X POST "http://127.0.0.1:$GW_PORT/inline" -H "Authorization: Bearer $VKEY3" \
  -H 'Content-Type: application/json' -d '{}')"
echo "$RESP3" | grep -q 'Bearer inline-key-xyz'
ks export --output "$TMP/vault-export.age" --password-stdin <<< 'test-pass' >/dev/null
if grep -q 'inline-key-xyz\|real-key-123' "$TMP/vault-export.age"; then
  echo "export file contains key values" >&2
  exit 1
fi

echo "== rekey while running =="
ks rekey --yes >/dev/null
sleep 1.5
RESP3="$(curl -sS -X POST "http://127.0.0.1:$GW_PORT/echo" -H "Authorization: Bearer $VKEY" \
  -H 'Content-Type: application/json' -d '{}')"
echo "$RESP3" | grep -q 'real-key-123'

echo "== audit default off =="
test ! -e "$VAULT/audit.jsonl"

echo "== audit opt-in =="
kill "$GATEWAY_PID" 2>/dev/null || true
wait "$GATEWAY_PID" 2>/dev/null || true
"$BIN" --home "$VAULT" serve --listen "127.0.0.1:$GW_PORT" --audit-log "$TMP/audit.jsonl" >"$TMP/gw2.log" 2>&1 &
GATEWAY_PID=$!
wait_health
curl -sS -o /dev/null -X POST "http://127.0.0.1:$GW_PORT/echo" -H "Authorization: Bearer $VKEY" \
  -H 'Content-Type: application/json' -d '{}'
curl -sS -o /dev/null "http://127.0.0.1:$GW_PORT/echo" \
  -H 'Authorization: Bearer ks_rejected000000000000000000000000000000000000000'
# The audit writer batches lines in a BufWriter that flushes after FLUSH_IDLE
# (50ms); the greps race that flush on a fast machine, so poll for the content.
# Rejection rows go to their own rotation chain (`<file>.rej`), so the 401 row
# belongs there, not in the real-traffic file.
wait_audit() {
  local file="$1" needle="$2"
  for _ in $(seq 1 50); do
    grep -q "$needle" "$file" 2>/dev/null && return 0
    sleep 0.1
  done
  echo "audit assertion failed: $needle not found in $file" >&2
  return 1
}
wait_audit "$TMP/audit.jsonl" '"route":"echo"'
wait_audit "$TMP/audit.jsonl.rej" '"route":"-"'
wait_audit "$TMP/audit.jsonl.rej" '"status":401'
if grep -q 'real-key-123\|ks_' "$TMP/audit.jsonl" "$TMP/audit.jsonl.rej"; then
  echo "audit log leaked a secret or vkey" >&2
  exit 1
fi
# Rejection rows must stay off the real-traffic chain: that separation is what
# stops an unauthenticated flood from rotating the forensic trail away.
if grep -q '"rejected":true' "$TMP/audit.jsonl"; then
  echo "a rejection row landed on the real-traffic audit chain" >&2
  exit 1
fi

echo "== per-route proxy overrides =="
# Route pinned to a dead proxy: must be 502 even though the upstream is reachable (per-route takes precedence)
ks route update echo --proxy http://127.0.0.1:1 >/dev/null
sleep 1.5
CODE="$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$GW_PORT/echo" \
  -H "Authorization: Bearer $VKEY" -H 'Content-Type: application/json' -d '{}')"
test "$CODE" = "502"
ks route update echo --clear-proxy >/dev/null
sleep 1.5
CODE="$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$GW_PORT/echo" \
  -H "Authorization: Bearer $VKEY" -H 'Content-Type: application/json' -d '{}')"
test "$CODE" = "200"

echo "== system proxy fallback vs route direct =="
kill "$GATEWAY_PID" 2>/dev/null || true
wait "$GATEWAY_PID" 2>/dev/null || true
VKEYD="$(printf 'real-key-123\n' | ks route add direct-route --base-url "http://127.0.0.1:$UP_PORT" \
  --auth bearer --proxy direct | new_vkey)"
# Gateway running with a dead system proxy: routes without proxy fall back to
# the system proxy → 502; direct routes bypass it → 200.
#
# NO_PROXY in the ambient environment wins over ALL_PROXY for loopback targets
# (curl/reqwest semantics), which silently makes the fallback route go direct
# and the assertion moot. Clear it for this run so the case tests what it says.
ALL_PROXY=http://127.0.0.1:1 NO_PROXY= no_proxy= \
  "$BIN" --home "$VAULT" serve --listen "127.0.0.1:$GW_PORT" >"$TMP/gw3.log" 2>&1 &
GATEWAY_PID=$!
wait_health
CODE="$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$GW_PORT/echo" \
  -H "Authorization: Bearer $VKEY" -H 'Content-Type: application/json' -d '{}')"
test "$CODE" = "502"
CODE="$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$GW_PORT/direct" \
  -H "Authorization: Bearer $VKEYD" -H 'Content-Type: application/json' -d '{}')"
test "$CODE" = "200"
kill "$GATEWAY_PID" 2>/dev/null || true
wait "$GATEWAY_PID" 2>/dev/null || true
GATEWAY_PID=""

echo "== doctor =="
ks doctor >/dev/null

echo "ALL SMOKE TESTS PASSED"
