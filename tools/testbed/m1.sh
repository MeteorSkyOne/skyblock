#!/usr/bin/env bash
# M1 end-to-end checks in the netns testbed:
#   S1  added latency, tunnel vs direct (UDP and TCP)
#   S9  full-cone NAT: a third party reaches the client's mapping
#   S10 junk sent to the node gets no response
#   S12 inner packets to cloud metadata are dropped by the node
#
# Usage: sudo tools/testbed/m1.sh <dir containing skyblock, skyblock-server, sbtest>

set -uo pipefail

BIN=$(cd "${1:?usage: m1.sh <bin dir>}" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
NS="$HERE/netns.sh"
WORK=$(mktemp -d)
PIDS=()
FAILED=0

cleanup() {
    for p in "${PIDS[@]}"; do pkill -P "$p" 2>/dev/null; kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    bash "$NS" down
    rm -rf "$WORK"
}
trap cleanup EXIT

in_ns() {
    local ns=$1
    shift
    ip netns exec "sb-$ns" "$@"
}

check() {
    local name=$1
    shift
    if "$@"; then
        echo "PASS $name"
    else
        echo "FAIL $name"
        FAILED=1
    fi
}

field() { sed -n "s/.*\b$1=\([0-9.]*\).*/\1/p" <<<"$2"; }

key_of() { sed -n "s/^$1 = \"\(.*\)\"/\1/p"; }

bash "$NS" up || exit 1
# A second game address that the client reaches only through the tunnel.
in_ns game ip addr add 198.19.0.3/24 dev lan0

SERVER_KEYS=$("$BIN/skyblock" keygen)
CLIENT_KEYS=$("$BIN/skyblock" keygen)
cat >"$WORK/server.toml" <<EOF
private_key = "$(key_of private_key <<<"$SERVER_KEYS")"
ports = [40001]
egress = "lan0"
egress_ip = "198.19.0.1"

[[user]]
name = "tester"
public_key = "$(key_of '# public_key' <<<"$CLIENT_KEYS")"
vip = "10.77.0.2"
EOF
cat >"$WORK/client.toml" <<EOF
private_key = "$(key_of private_key <<<"$CLIENT_KEYS")"
mode = "tun"

[[node]]
name = "testbed"
addr = "198.18.0.1"
ports = [40001]
public_key = "$(key_of '# public_key' <<<"$SERVER_KEYS")"

[tun]
routes = ["198.19.0.3/32", "169.254.169.254/32"]
EOF

# One echo per address: a wildcard-bound UDP socket would answer from the
# primary address, which connected clients drop.
for addr in 198.19.0.2 198.19.0.3; do
    in_ns game "$BIN/sbtest" echo --bind "$addr:9000" 2>/dev/null &
    PIDS+=($!)
done
in_ns server "$BIN/skyblock-server" --log-level debug run -c "$WORK/server.toml" \
    >"$WORK/server.log" 2>&1 &
PIDS+=($!)
sleep 0.3
in_ns client "$BIN/skyblock" up -c "$WORK/client.toml" >"$WORK/client.out" 2>"$WORK/client.log" &
PIDS+=($!)

for _ in $(seq 50); do
    grep -q "TUN capture ready" "$WORK/client.log" && break
    sleep 0.1
done
if ! grep -q "TUN capture ready" "$WORK/client.log"; then
    echo "FAIL tunnel did not come up"
    echo "--- client log"; cat "$WORK/client.log"
    echo "--- server log"; cat "$WORK/server.log"
    exit 1
fi
echo "PASS tunnel up"

# S1: latency, tunnel vs direct.
for proto in udp tcp; do
    direct=$(in_ns client "$BIN/sbtest" "$proto-ping" --target 198.19.0.2:9000 --count 300 --interval-ms 5)
    tunnel=$(in_ns client "$BIN/sbtest" "$proto-ping" --target 198.19.0.3:9000 --count 300 --interval-ms 5)
    echo "  $proto direct: $direct" | grep "$proto "
    echo "  $proto tunnel: $tunnel" | grep "$proto "
    d50=$(field p50_us "$direct")
    t50=$(field p50_us "$tunnel")
    loss=$(field loss_pct "$tunnel")
    added=$((t50 - d50))
    echo "  $proto added p50 latency: ${added}us"
    check "S1 $proto no loss" [ "${loss%.*}" = 0 ]
    check "S1 $proto added p50 < 1ms" [ "$added" -lt 1000 ]
done

# S9: full cone. The client primes a mapping via 198.19.0.3, then a
# stranger (198.19.0.2) sends to the node's public side of that mapping.
in_ns client "$BIN/sbtest" udp-listen --bind 0.0.0.0:45000 --prime 198.19.0.3:9000 \
    --wait-ms 2500 >"$WORK/listen.out" &
LISTEN=$!
sleep 0.5
in_ns game "$BIN/sbtest" udp-send --to 198.19.0.1:45000 --count 3
check "S9 full cone: stranger reaches client" wait "$LISTEN"

# S10: junk to the node gets no response.
check "S10 probe gets no response" in_ns game "$BIN/sbtest" probe \
    --target 198.19.0.1:40001 --count 200 --wait-ms 1500

# S12: cloud metadata address is filtered by the node.
check "S12 metadata unreachable" bash -c "! ip netns exec sb-client $BIN/sbtest udp-ping \
    --target 169.254.169.254:9000 --count 5 --interval-ms 10 >/dev/null"
check "S12 node logged the drop" grep -q "inner packet filtered" "$WORK/server.log"

echo "--- client status (last line)"
tail -1 "$WORK/client.out"
echo "--- server log (info)"
grep -v DEBUG "$WORK/server.log" | tail -5

exit $FAILED
