#!/usr/bin/env bash
set -euo pipefail

# XSY-0029 partition reunion stress harness.
#
# This script starts two real x0x-symphonyd daemons, each pointed at its own
# x0xd daemon, then drives the ignored phased Rust test:
#   create -> partitioned_claim -> healed_verify
#
# Required prerequisites:
#   * two running x0xd daemons that can gossip/replicate the chosen TaskList;
#   * cargo can build x0x-symphonyd from this checkout;
#   * curl and python3 are available for setup glue;
#   * a real partition method supplied by the operator.
#
# Partition honesty:
#   The Rust test never cuts the network itself. This script either runs
#   SYMPHONY_PARTITION_CUT_CMD / SYMPHONY_PARTITION_HEAL_CMD or pauses for the
#   operator to cut/heal the partition manually. Use tc, iptables/nftables,
#   pfctl, or docker network disconnect/connect as appropriate for your lab.
#   Stopping one daemon is only a process-stop simulation: it can exercise stale
#   takeover/restart behavior, but it does NOT prove the live dual-claim network
#   split required by ADR-0002. For XSY-0029 acceptance, prefer a true split
#   between the two x0xd peers while both symphony daemons stay alive.
#
# Required environment:
#   SYMPHONY_PARTITION_X0XD_A_URL or X0XD_A_URL   x0xd for daemon A
#   SYMPHONY_PARTITION_X0XD_B_URL or X0XD_B_URL   x0xd for daemon B
#
# Optional environment:
#   SYMPHONY_PARTITION_X0XD_A_TOKEN / X0XD_A_TOKEN   bearer token for x0xd A
#   SYMPHONY_PARTITION_X0XD_B_TOKEN / X0XD_B_TOKEN   bearer token for x0xd B
#   SYMPHONY_PARTITION_LIST_ID                       shared TaskList id
#   SYMPHONY_PARTITION_RUN_DIR                       scratch/proof directory
#   SYMPHONY_PARTITION_CUT_CMD                       command that induces split
#   SYMPHONY_PARTITION_HEAL_CMD                      command that heals split
#   SYMPHONY_PARTITION_WAIT_SECONDS                  phase retry timeout
#   CARGO                                            cargo executable
#
# Example true split hooks for Docker networks (adapt names):
#   SYMPHONY_PARTITION_CUT_CMD='docker network disconnect x0x-net-a x0xd-b'
#   SYMPHONY_PARTITION_HEAL_CMD='docker network connect x0x-net-a x0xd-b'
#   bash scripts/partition-stress.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_BIN="${CARGO:-cargo}"
PYTHON_BIN="${PYTHON:-python3}"
UTC_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${SYMPHONY_PARTITION_RUN_DIR:-$ROOT_DIR/proofs/XSY-0029/$UTC_STAMP-partition-stress}"
LIST_ID="${SYMPHONY_PARTITION_LIST_ID:-symphony-partition-$UTC_STAMP}"
WAIT_SECONDS="${SYMPHONY_PARTITION_WAIT_SECONDS:-30}"
START_TIMEOUT_SECONDS="${SYMPHONY_PARTITION_START_TIMEOUT_SECONDS:-60}"

X0XD_A_URL="${SYMPHONY_PARTITION_X0XD_A_URL:-${X0XD_A_URL:-}}"
X0XD_B_URL="${SYMPHONY_PARTITION_X0XD_B_URL:-${X0XD_B_URL:-}}"
X0XD_A_TOKEN="${SYMPHONY_PARTITION_X0XD_A_TOKEN:-${X0XD_A_TOKEN:-}}"
X0XD_B_TOKEN="${SYMPHONY_PARTITION_X0XD_B_TOKEN:-${X0XD_B_TOKEN:-}}"

A_DIR="$RUN_DIR/a"
B_DIR="$RUN_DIR/b"
A_DATA_DIR="$A_DIR/data"
B_DATA_DIR="$B_DIR/data"
A_WORKFLOW="$A_DIR/WORKFLOW.md"
B_WORKFLOW="$B_DIR/WORKFLOW.md"
STATE_FILE="$RUN_DIR/partition-state.json"
A_LOG="$A_DIR/x0x-symphonyd.log"
B_LOG="$B_DIR/x0x-symphonyd.log"

DAEMON_A_PID=""
DAEMON_B_PID=""
SYMPHONY_A_URL=""
SYMPHONY_B_URL=""
SYMPHONY_A_TOKEN=""
SYMPHONY_B_TOKEN=""

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_tools() {
  command -v curl >/dev/null 2>&1 || fail "curl is required"
  command -v "$PYTHON_BIN" >/dev/null 2>&1 || fail "$PYTHON_BIN is required"
  command -v "$CARGO_BIN" >/dev/null 2>&1 || fail "$CARGO_BIN is required"
}

require_env() {
  [[ -n "$X0XD_A_URL" ]] || fail "set SYMPHONY_PARTITION_X0XD_A_URL (or X0XD_A_URL)"
  [[ -n "$X0XD_B_URL" ]] || fail "set SYMPHONY_PARTITION_X0XD_B_URL (or X0XD_B_URL)"
}

json_body() {
  local name="$1"
  local topic="$2"
  RESOURCE_NAME="$name" RESOURCE_TOPIC="$topic" "$PYTHON_BIN" - <<'PY'
import json
import os
print(json.dumps({"name": os.environ["RESOURCE_NAME"], "topic": os.environ["RESOURCE_TOPIC"]}))
PY
}

curl_json() {
  local method="$1"
  local base_url="$2"
  local token="$3"
  local path="$4"
  local body="${5:-}"
  local args=(-fsS -X "$method" -H 'Content-Type: application/json')
  if [[ -n "$token" ]]; then
    args+=(-H "Authorization: Bearer $token")
  fi
  if [[ -n "$body" ]]; then
    args+=(-d "$body")
  fi
  curl "${args[@]}" "${base_url%/}$path"
}

json_contains_id() {
  local id="$1"
  local collection_key="$2"
  "$PYTHON_BIN" -c '
import json
import sys
wanted = sys.argv[1]
key = sys.argv[2]
try:
    data = json.load(sys.stdin)
except json.JSONDecodeError:
    sys.exit(1)
if isinstance(data, dict):
    entries = data.get(key, [])
else:
    entries = data
for entry in entries:
    if isinstance(entry, dict) and entry.get("id") == wanted:
        sys.exit(0)
sys.exit(1)
' "$id" "$collection_key"
}

ensure_task_list() {
  local base_url="$1"
  local token="$2"
  local list_id="$3"
  if curl_json GET "$base_url" "$token" /task-lists | json_contains_id "$list_id" task_lists; then
    return 0
  fi
  printf 'Creating TaskList %s on %s\n' "$list_id" "$base_url"
  curl_json POST "$base_url" "$token" /task-lists "$(json_body "$list_id" "$list_id")" >/dev/null
}

ensure_kv_store() {
  local base_url="$1"
  local token="$2"
  local list_id="$3"
  local store_id="symphony-$list_id"
  if curl_json GET "$base_url" "$token" /stores | json_contains_id "$store_id" stores; then
    return 0
  fi
  printf 'Creating KvStore %s on %s\n' "$store_id" "$base_url"
  curl_json POST "$base_url" "$token" /stores "$(json_body "$store_id" "$store_id")" >/dev/null
}

ensure_x0xd_resources() {
  ensure_task_list "$X0XD_A_URL" "$X0XD_A_TOKEN" "$LIST_ID"
  ensure_task_list "$X0XD_B_URL" "$X0XD_B_TOKEN" "$LIST_ID"
  ensure_kv_store "$X0XD_A_URL" "$X0XD_A_TOKEN" "$LIST_ID"
  ensure_kv_store "$X0XD_B_URL" "$X0XD_B_TOKEN" "$LIST_ID"
}

write_workflow() {
  local path="$1"
  local x0xd_url="$2"
  local workspace_root="$3"
  cat >"$path" <<EOF
---
tracker:
  kind: x0x_crdt
  list_id: $LIST_ID
  active_states:
    - partition_stress_never_dispatch
  terminal_states:
    - done
    - cancelled
    - duplicate
signing:
  policy: required
  x0xd_url: $x0xd_url
sharding:
  replication_factor: 2
workers:
  publish_enabled: true
  ttl_seconds: 10
  capabilities:
    - partition-stress
  sandbox_levels:
    - repo-write
  runner_presets:
    - shell
polling:
  interval_ms: 1000
workspace:
  root: $workspace_root
hooks:
  timeout_ms: 10000
agent:
  max_concurrent_agents: 1
  max_concurrent_agents_by_state:
    partition_stress_never_dispatch: 1
  max_turns: 1
  max_retry_backoff_ms: 1000
security:
  network_dispatch: "off"
  approval_ttl: "24h"
  required_trust: trusted
runner:
  kind: shell
  command: /usr/bin/env
  args:
    - true
  turn_timeout_ms: 10000
---
# Partition stress no-op runner

The ignored XSY-0029 harness claims manually through the daemon API. The daemon
poll loop is intentionally pointed at a non-task active state so it will not
start runner sessions while the partition phases execute.
EOF
}

start_daemon() {
  local side="$1"
  local x0xd_url="$2"
  local x0xd_token="$3"
  local workflow="$4"
  local data_dir="$5"
  local log_file="$6"
  local pid_var="DAEMON_${side}_PID"
  local url_var="SYMPHONY_${side}_URL"
  local token_var="SYMPHONY_${side}_TOKEN"

  mkdir -p "$data_dir" "$(dirname "$log_file")"
  printf 'Starting x0x-symphonyd %s (x0xd=%s)\n' "$side" "$x0xd_url"
  (
    cd "$ROOT_DIR"
    if [[ -n "$x0xd_token" ]]; then
      export X0X_API_TOKEN="$x0xd_token"
    else
      unset X0X_API_TOKEN || true
    fi
    exec "$CARGO_BIN" run --quiet --bin x0x-symphonyd -- \
      --config "$workflow" \
      --data-dir "$data_dir" \
      --bind 127.0.0.1:0
  ) >"$log_file" 2>&1 &
  local pid="$!"
  printf -v "$pid_var" '%s' "$pid"

  local port_file="$data_dir/daemon.port"
  local token_file="$data_dir/api-token"
  local port=""
  for ((i = 0; i < START_TIMEOUT_SECONDS; i++)); do
    if [[ -s "$port_file" && -s "$token_file" ]]; then
      port="$(tr -d '\n' <"$port_file")"
      local url="http://127.0.0.1:$port"
      if curl -fsS "$url/health" >/dev/null 2>&1; then
        printf -v "$url_var" '%s' "$url"
        printf -v "$token_var" '%s' "$(tr -d '\n' <"$token_file")"
        printf 'Daemon %s ready at %s (log: %s)\n' "$side" "$url" "$log_file"
        return 0
      fi
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      tail -n 80 "$log_file" >&2 || true
      fail "x0x-symphonyd $side exited before becoming healthy"
    fi
    sleep 1
  done
  tail -n 80 "$log_file" >&2 || true
  fail "timed out waiting for x0x-symphonyd $side"
}

stop_daemon_pid() {
  local pid="$1"
  if [[ -z "$pid" ]]; then
    return 0
  fi
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}

stop_daemons() {
  stop_daemon_pid "$DAEMON_A_PID"
  stop_daemon_pid "$DAEMON_B_PID"
  DAEMON_A_PID=""
  DAEMON_B_PID=""
}

restart_daemons_for_reconcile() {
  printf 'Restarting both daemons to trigger startup reconcile after heal\n'
  stop_daemons
  start_daemon A "$X0XD_A_URL" "$X0XD_A_TOKEN" "$A_WORKFLOW" "$A_DATA_DIR" "$A_LOG"
  start_daemon B "$X0XD_B_URL" "$X0XD_B_TOKEN" "$B_WORKFLOW" "$B_DATA_DIR" "$B_LOG"
}

run_phase() {
  local phase="$1"
  printf '\n=== Running partition phase: %s ===\n' "$phase"
  (
    cd "$ROOT_DIR"
    SYMPHONY_PARTITION_A_URL="$SYMPHONY_A_URL" \
    SYMPHONY_PARTITION_B_URL="$SYMPHONY_B_URL" \
    SYMPHONY_PARTITION_A_TOKEN="$SYMPHONY_A_TOKEN" \
    SYMPHONY_PARTITION_B_TOKEN="$SYMPHONY_B_TOKEN" \
    SYMPHONY_PARTITION_LIST_ID="$LIST_ID" \
    SYMPHONY_PARTITION_PHASE="$phase" \
    SYMPHONY_PARTITION_STATE_FILE="$STATE_FILE" \
    SYMPHONY_PARTITION_A_PROOFS_DIR="$A_DIR/proofs" \
    SYMPHONY_PARTITION_B_PROOFS_DIR="$B_DIR/proofs" \
    SYMPHONY_PARTITION_WAIT_SECONDS="$WAIT_SECONDS" \
    "$CARGO_BIN" test --package x0x-symphony-bin --test partition_stress -- --ignored --nocapture
  )
}

run_or_pause() {
  local description="$1"
  local command_value="$2"
  if [[ -n "$command_value" ]]; then
    printf '%s: %s\n' "$description" "$command_value"
    bash -c "$command_value"
  else
    printf '\n%s\n' "$description"
    printf 'No command hook was supplied. Cut/heal the network now, then press Enter.\n'
    read -r _
  fi
}

main() {
  require_tools
  require_env
  mkdir -p "$A_DIR" "$B_DIR"
  trap stop_daemons EXIT

  printf 'XSY-0029 partition stress run directory: %s\n' "$RUN_DIR"
  printf 'Shared TaskList id: %s\n' "$LIST_ID"

  ensure_x0xd_resources
  write_workflow "$A_WORKFLOW" "$X0XD_A_URL" "$A_DIR/workspaces"
  write_workflow "$B_WORKFLOW" "$X0XD_B_URL" "$B_DIR/workspaces"

  start_daemon A "$X0XD_A_URL" "$X0XD_A_TOKEN" "$A_WORKFLOW" "$A_DATA_DIR" "$A_LOG"
  start_daemon B "$X0XD_B_URL" "$X0XD_B_TOKEN" "$B_WORKFLOW" "$B_DATA_DIR" "$B_LOG"

  run_phase create
  run_or_pause \
    'Induce the partition now; both x0xd peers should stop seeing each other while both symphony daemons remain alive.' \
    "${SYMPHONY_PARTITION_CUT_CMD:-}"
  run_phase partitioned_claim
  run_or_pause \
    'Heal the partition now; restore x0xd peer connectivity before verification.' \
    "${SYMPHONY_PARTITION_HEAL_CMD:-}"
  restart_daemons_for_reconcile
  sleep 2
  run_phase healed_verify

  printf '\nPASS: partition reunion harness completed.\n'
  printf 'State file: %s\n' "$STATE_FILE"
  printf 'Daemon A log/proofs: %s / %s\n' "$A_LOG" "$A_DIR/proofs"
  printf 'Daemon B log/proofs: %s / %s\n' "$B_LOG" "$B_DIR/proofs"
}

main "$@"
