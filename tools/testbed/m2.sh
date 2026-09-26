#!/usr/bin/env bash
# M2 checks in the netns testbed: redundancy over two paths.
#   S2  random loss 1% / 5%: effective loss with 1 vs 2 copies (bench)
#   S3  burst loss (Gilbert-Elliott): copies and copy delay (bench, report)
#   S4  jitter and reordering: no duplicates reach the app (up + udp-ping)
#   S5  one path fails mid-stream: no loss, the path is marked down
#   S8  bulk download next to a game flow: classification, game latency
#
# Usage: sudo tools/testbed/m2.sh <dir containing skyblock, skyblock-server, sbtest>
# SB_BENCH_SECS (default 20) sets the measured time per bench setting.

set -uo pipefail

BIN=$(cd "${1:?usage: m2.sh <bin dir>}" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
NS="$HERE/netns.sh"
WORK=$(mktemp -d)
SECS=${SB_BENCH_SECS:-20}
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

# lt A B: float A < B
lt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a < b) }'; }

# Loss percentage of a bench setting: bench_loss <output> <copies> <delay>
bench_loss() {
    sed -n "s/^copies $2 paths 2 delay $3ms: sent [0-9]* lost [0-9]* (\([0-9.]*\)%).*/\1/p" <<<"$1"
}

bash "$NS" up || exit 1
# A second game address that the client reaches only through the tunnel.
in_ns game ip addr add 198.19.0.3/24 dev lan0

SERVER_KEYS=$("$BIN/skyblock" keygen)
CLIENT_KEYS=$("$BIN/skyblock" keygen)
BENCH_KEYS=$("$BIN/skyblock" keygen)
cat >"$WORK/server.toml" <<EOF
private_key = "$(key_of private_key <<<"$SERVER_KEYS")"
ports = [40001, 40002]
egress = "lan0"
egress_ip = "198.19.0.1"
control_socket = "$WORK/ctl.sock"

[[user]]
name = "tester"
public_key = "$(key_of '# public_key' <<<"$CLIENT_KEYS")"
vip = "10.77.0.2"

[[user]]
name = "bencher"
public_key = "$(key_of '# public_key' <<<"$BENCH_KEYS")"
vip = "10.77.0.3"
EOF
node_block() {
    cat <<EOF
[[node]]
name = "testbed"
addr = "198.18.0.1"
ports = [40001, 40002]
public_key = "$(key_of '# public_key' <<<"$SERVER_KEYS")"

[tunnel]
paths = 2
copies = 2
copy_delay_ms = 2.0
EOF
}
{
    echo "private_key = \"$(key_of private_key <<<"$CLIENT_KEYS")\""
    echo 'mode = "tun"'
    node_block
    echo
    echo '[tun]'
    echo 'routes = ["198.19.0.3/32"]'
} >"$WORK/client.toml"
{
    echo "private_key = \"$(key_of private_key <<<"$BENCH_KEYS")\""
    node_block
} >"$WORK/bench.toml"

for addr in 198.19.0.2 198.19.0.3; do
    in_ns game "$BIN/sbtest" echo --bind "$addr:9000" 2>/dev/null &
    PIDS+=($!)
done
in_ns game "$BIN/sbtest" tcp-source --bind 198.19.0.3:9001 2>/dev/null &
PIDS+=($!)
in_ns server "$BIN/skyblock-server" --log-level debug run -c "$WORK/server.toml" \
    >"$WORK/server.log" 2>&1 &
PIDS+=($!)
sleep 0.3

bench() {
    in_ns client "$BIN/skyblock" bench -c "$WORK/bench.toml" --duration "${SECS}s" "$@" \
        2>>"$WORK/bench.log"
}

# S2: random loss.
for profile in loss1 loss5; do
    bash "$NS" netem "$profile"
    out=$(bench --copies 1,2 --paths 2)
    echo "--- S2 $profile"
    grep '^copies' <<<"$out" | cut -d'|' -f1
    one=$(bench_loss "$out" 1 2.0)
    two=$(bench_loss "$out" 2 2.0)
    if [ "$profile" = loss1 ]; then
        check "S2 loss1: 2 copies cut round-trip loss below 0.3% ($two%)" lt "$two" 0.3
    else
        check "S2 loss5: 1 copy loses over 5% ($one%)" lt 5 "$one"
        check "S2 loss5: 2 copies cut round-trip loss below 1.5% ($two%)" lt "$two" 1.5
    fi
done

# S3: bursty loss; copies back to back vs 2ms apart.
bash "$NS" netem burst
out=$(bench --copies 1,2 --paths 2 --delay-ms 0,2)
echo "--- S3 burst (Gilbert-Elliott)"
grep '^copies' <<<"$out" | cut -d'|' -f1
two=$(bench_loss "$out" 2 2.0)
one=$(bench_loss "$out" 1 2.0)
check "S3 burst: 2 copies lose less than 1 ($two% < $one%)" lt "$two" "$one"

# The remaining scenarios go through the full IP path with `up`.
bash "$NS" netem baseline
in_ns client "$BIN/skyblock" up -c "$WORK/client.toml" >"$WORK/client.out" 2>"$WORK/client.log" &
UP=$!
PIDS+=($UP)
for _ in $(seq 50); do
    grep -q "TUN capture ready" "$WORK/client.log" && break
    sleep 0.1
done
if ! grep -q "TUN capture ready" "$WORK/client.log"; then
    echo "FAIL tunnel did not come up"
    echo "--- client log"; cat "$WORK/client.log"
    echo "--- server log"; tail -20 "$WORK/server.log"
    exit 1
fi
echo "PASS tunnel up (2 paths)"
sleep 2

# S4: jitter and reordering must not duplicate or delay delivery.
for profile in jitter reorder; do
    bash "$NS" netem "$profile"
    out=$(in_ns client "$BIN/sbtest" udp-ping --target 198.19.0.3:9000 --count 1000 --interval-ms 5)
    echo "  S4 $profile: $(grep '^udp sent' <<<"$out")"
    check "S4 $profile: no duplicates delivered" [ "$(field dup "$out")" = 0 ]
    check "S4 $profile: no loss" [ "$(field recv "$out")" = 1000 ]
done

# S5: path 0 (node port 40001) fails 3s into a 15s stream.
bash "$NS" netem baseline
in_ns client "$BIN/sbtest" udp-ping --target 198.19.0.3:9000 --count 1500 --interval-ms 10 \
    >"$WORK/s5.out" &
PING=$!
sleep 3
in_ns server nft -f - <<'EOF'
table inet sbtest {
    chain in { type filter hook input priority -10; udp dport 40001 drop; }
    chain out { type filter hook output priority -10; udp sport 40001 drop; }
}
EOF
sleep 8
paths_during=$(tail -1 "$WORK/client.out" | sed -n 's/.*| paths \([0-9]*\/[0-9]*\).*/\1/p')
wait "$PING"
in_ns server nft delete table inet sbtest
out=$(cat "$WORK/s5.out")
echo "  S5: $(grep '^udp sent' <<<"$out")"
echo "  S5: client status during the outage: paths $paths_during"
check "S5 no loss across the path failure" [ "$(field recv "$out")" = 1500 ]
check "S5 failed path marked down" [ "$paths_during" = "1/2" ]
sleep 6

# S8: game pings alone, then next to a bulk download.
base=$(in_ns client "$BIN/sbtest" udp-ping --target 198.19.0.3:9000 --count 1000 --interval-ms 8)
in_ns client "$BIN/sbtest" tcp-sink --target 198.19.0.3:9001 --secs 14 >"$WORK/sink.out" &
SINK=$!
sleep 2
load=$(in_ns client "$BIN/sbtest" udp-ping --target 198.19.0.3:9000 --count 1000 --interval-ms 8)
bulk_status=$(tail -1 "$WORK/client.out")
wait "$SINK"
# The download goes node -> client: the node classifies it. (The client's
# `bulk` count covers its own direction, here only the ACKs, which sit
# around the 2Mbps threshold.)
sent=$(in_ns server "$BIN/skyblock-server" status -c "$WORK/server.toml" |
    sed -n 's/^inner packets: .* sent \([0-9]*\) (bulk \([0-9]*\)).*/\1 \2/p')
echo "  S8 alone:     $(grep '^udp sent' <<<"$base")"
echo "  S8 with bulk: $(grep '^udp sent' <<<"$load")"
echo "  S8 download:  $(cat "$WORK/sink.out")"
echo "  S8 status:    $bulk_status"
echo "  S8 node sent (all, bulk): $sent"
b99=$(field p99_us "$base")
l99=$(field p99_us "$load")
echo "  S8 game p99 added by the download: $((l99 - b99))us"
check "S8 download ran" [ -s "$WORK/sink.out" ]
mostly_bulk=no
[ -n "$sent" ] && [ "${sent#* }" -gt "$((${sent% *} / 2))" ] && mostly_bulk=yes
check "S8 node sent most of the download as bulk" [ "$mostly_bulk" = yes ]
check "S8 game flow lost nothing" [ "$(field recv "$load")" = 1000 ]

echo "--- client status (last line)"
tail -1 "$WORK/client.out"
echo "--- server log (info)"
grep -v DEBUG "$WORK/server.log" | tail -4

exit $FAILED
