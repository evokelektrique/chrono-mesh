#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/tmp/demo"
ESCRIPT="$ROOT/chrono_mesh"

nodelist=("node1" "node2" "node3")
ports=(4001 4002 4003)

mkdir -p "$BUILD"

echo "[1/5] Building escript…"
(cd "$ROOT" && mix escript.build >/dev/null)

echo "[2/5] Preparing configs…"
pubkeys=()

for idx in "${!nodelist[@]}"; do
  node="${nodelist[$idx]}"
  dir="$BUILD/$node"
  rm -rf "$dir"
  mkdir -p "$dir"
  CHRONO_MESH_HOME="$dir" CHRONO_MESH_LISTEN_PORT="${ports[$idx]}" HOME="$dir" USER="$node" "$ESCRIPT" init --name "$node" >/dev/null

  pubkey=$(grep "public_key_path" "$dir/.chrono_mesh/config.yaml" | awk '{print $2}')
  pubkeys+=("$pubkey")
done

add_peer() {
  local home="$1"
  local name="$2"
  local address="$3"
  local pubkey="$4"
  CHRONO_MESH_HOME="$home" HOME="$home" "$ESCRIPT" peers add --name "$name" --address "$address" --public-key "$pubkey" >/dev/null
}

for idx in "${!nodelist[@]}"; do
  node="${nodelist[$idx]}"
  dir="$BUILD/$node"
  for jdx in "${!nodelist[@]}"; do
    if [[ $idx -ne $jdx ]]; then
      add_peer "$dir" "${nodelist[$jdx]}" "127.0.0.1:${ports[$jdx]}" "${pubkeys[$jdx]}"
    fi
  done
done

start_node() {
  local node="$1"
  local port="$2"
  CHRONO_MESH_HOME="$BUILD/$node" \
    HOME="$BUILD/$node" \
    CHRONO_MESH_LISTEN_PORT="$port" \
    "$ESCRIPT" start --mode combined \
    >"$BUILD/${node}.log" 2>&1 &
  echo $!
}

echo "[3/5] Launching nodes…"
P1=$(start_node node1 4001)
P2=$(start_node node2 4002)
P3=$(start_node node3 4003)
sleep 2

cleanup() {
  echo "[*] Shutting down demo nodes…"
  kill "$P1" "$P2" "$P3" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[4/5] Sending demo message…"
CHRONO_MESH_HOME="$BUILD/node1" HOME="$BUILD/node1" "$ESCRIPT" send --to node3 --message "hello from demo run" --path-length 2

# give the network time to flush the next wave and deliver to node3
sleep 12

echo "[4/5b] Node3 inbox contents:"
cat "$BUILD/node3/.chrono_mesh/inbox.log" || echo "(no inbox entries yet)"

echo "[5/5] Logs (node1):"
tail -n 5 "$BUILD/node1.log" || true
echo "[5/5] Logs (node2):"
tail -n 5 "$BUILD/node2.log" || true
echo "[5/5] Logs (node3):"
tail -n 5 "$BUILD/node3.log" || true

echo "Demo finished. Logs stored in $BUILD/*.log"
