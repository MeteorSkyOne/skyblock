#!/usr/bin/env bash
# Weak-network behaviour in the netns testbed: heavy loss, large per-packet
# delay variation, heavy reordering, loss bursts, one bad path, and short
# blackouts of the whole link. Each case runs `bench` (1-3 copies over two
# paths); the jittery cases also run game-like UDP and TCP through `up`,
# next to the same traffic sent directly (no tunnel) for comparison.
#
# Usage: sudo tools/testbed/weak.sh <dir containing skyblock, skyblock-server, sbtest>
# SB_BENCH_SECS (default 15) sets the measured time per bench setting.

set -uo pipefail

BIN=$(cd "${1:?usage: weak.sh <bin dir>}" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
NS="$HERE/netns.sh"
WORK=$(mktemp -d)
SECS=${SB_BENCH_SECS:-15}
PIDS=()
BLACKOUT=()
FAILED=0

cleanup() {
    for p in "${BLACKOUT[@]}" "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
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

lt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a < b) }'; }

# Round-trip loss % of one bench setting: bench_loss <output> <copies> <paths> <delay>
bench_loss() {
    sed -n "s/^copies $2 paths $3 delay $4ms: sent [0-9]* lost [0-9]* (\([0-9.]*\)%).*/\1/p" <<<"$1"
}

bench() {
    if ! in_ns client "$BIN/skyblock" bench -c "$WORK/bench.toml" --duration "${SECS}s" "$@" \
        2>"$WORK/bench.log"; then
        echo "bench failed:" >&2
        grep -v INFO "$WORK/bench.log" | tail -5 >&2
        FAILED=1
    fi
}

show() {
    if grep -q "^copies paths delay" <<<"$1"; then
        sed -n '/^copies paths delay/,$p' <<<"$1"
    else
        echo "  (no bench result)"
        FAILED=1
    fi
}

# SB_CASES="W5 W7" runs only those cases (default: all).
want() { [ -z "${SB_CASES:-}" ] || grep -qw "$1" <<<"$SB_CASES"; }

# Game-like UDP (125 pps) and TCP request/response, through the tunnel and
# directly, under the current impairment.
game_traffic() {
    local name=$1 t d
    for proto in udp tcp; do
        if [ "$proto" = udp ]; then
            t=$(in_ns client "$BIN/sbtest" udp-ping --target 198.19.0.3:9000 --count 1000 --interval-ms 8)
            d=$(in_ns client "$BIN/sbtest" udp-ping --target 198.19.0.2:9000 --count 1000 --interval-ms 8)
        else
            t=$(in_ns client "$BIN/sbtest" tcp-ping --target 198.19.0.3:9000 --count 300 --interval-ms 10)
            d=$(in_ns client "$BIN/sbtest" tcp-ping --target 198.19.0.2:9000 --count 300 --interval-ms 10)
        fi
        printf '  %-6s %s tunnel: %s\n' "$name" "$proto" "$(grep "^$proto sent" <<<"$t" | cut -d' ' -f2-)"
        printf '  %-6s %s direct: %s\n' "$name" "$proto" "$(grep "^$proto sent" <<<"$d" | cut -d' ' -f2-)"
        if [ "$proto" = udp ]; then
            check "$name: no duplicates reach the app" [ "$(field dup "$t")" = 0 ]
        fi
    done
}

# Drops everything on the link for ON ms every EVERY ms, both directions,
# by switching netem to 100% loss and back. One loop per side, started
# directly so that `$!` is the loop itself and `kill` stops it.
blackouts() {
    local on=$1 every=$2 ns
    local on_s off_s
    on_s=$(awk -v m="$1" 'BEGIN { print m / 1000 }')
    off_s=$(awk -v m="$((every - on))" 'BEGIN { print m / 1000 }')
    bash "$NS" netem baseline
    for ns in client server; do
        ip netns exec "sb-$ns" bash -c "while :; do
            tc qdisc change dev wan0 root netem delay 15ms loss 100%; sleep $on_s
            tc qdisc change dev wan0 root netem delay 15ms; sleep $off_s
        done" &
        BLACKOUT+=($!)
    done
}

stop_blackouts() {
    for p in "${BLACKOUT[@]}"; do kill "$p" 2>/dev/null; done
    BLACKOUT=()
    sleep 0.2
    bash "$NS" netem baseline
}

bash "$NS" up || exit 1
in_ns game ip addr add 198.19.0.3/24 dev lan0

SERVER_KEYS=$("$BIN/skyblock" keygen)
CLIENT_KEYS=$("$BIN/skyblock" keygen)
BENCH_KEYS=$("$BIN/skyblock" keygen)
cat >"$WORK/server.toml" <<EOF
private_key = "$(key_of private_key <<<"$SERVER_KEYS")"
ports = [40001, 40002]
egress = "lan0"
egress_ip = "198.19.0.1"

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
in_ns server "$BIN/skyblock-server" run -c "$WORK/server.toml" >"$WORK/server.log" 2>&1 &
PIDS+=($!)
sleep 0.3
in_ns client "$BIN/skyblock" up -c "$WORK/client.toml" >"$WORK/client.out" 2>"$WORK/client.log" &
PIDS+=($!)
for _ in $(seq 50); do
    grep -q "TUN capture ready" "$WORK/client.log" && break
    sleep 0.1
done
grep -q "TUN capture ready" "$WORK/client.log" || { echo "FAIL tunnel did not come up"; exit 1; }
sleep 2

if want W1; then
    echo "=== W1 heavy random loss (both directions)"
    for loss in 10 20 30; do
        bash "$NS" netem custom "delay 15ms loss $loss%"
        out=$(bench --copies 1,2,3 --paths 2)
        echo "--- loss $loss%"
        show "$out"
        one=$(bench_loss "$out" 1 2 2.0)
        two=$(bench_loss "$out" 2 2 2.0)
        check "W1 loss $loss%: 2 copies lose less than 1 ($two% < $one%)" lt "$two" "$one"
    done
fi

if want W2; then
    echo "=== W2 large delay variation: 30ms ± 20ms (normal) each way"
    bash "$NS" netem custom "delay 30ms 20ms distribution normal"
    show "$(bench --copies 1,2,3 --paths 2)"
    game_traffic W2
fi

if want W3; then
    echo "=== W3 heavy reordering: 30% of packets skip the 15ms queue"
    bash "$NS" netem custom "delay 15ms reorder 30% 50%"
    show "$(bench --copies 1,2 --paths 2)"
    game_traffic W3
fi

if want W4; then
    echo "=== W4 everything at once: 30ms ± 15ms, 10% loss"
    bash "$NS" netem custom "delay 30ms 15ms distribution normal loss 10%"
    show "$(bench --copies 1,2,3 --paths 2)"
    game_traffic W4
fi

if want W5; then
    echo "=== W5 loss bursts (Gilbert-Elliott, ~20% loss in runs of ~5 packets)"
    bash "$NS" netem custom "delay 15ms loss gemodel 5% 20% 100% 0%"
    show "$(bench --copies 1,2,3 --paths 2)"
fi

if want W6; then
    echo "=== W6 one bad path: port 40001 gets 20% loss and ±10ms, 40002 is clean"
    bash "$NS" pathem 40001 "delay 15ms 10ms distribution normal loss 20%"
    out=$(bench --copies 1,2 --paths 1,2)
    show "$out"
    one=$(bench_loss "$out" 1 1 2.0)
    check "W6 one copy on the best path avoids the bad one ($one%)" lt "$one" 1
    echo "  up status: $(tail -1 "$WORK/client.out")"
fi

if want W7; then
    echo "=== W7 blackouts: link drops everything for 30ms every 500ms"
    blackouts 30 500
    game_traffic W7
    show "$(bench --copies 1,2 --paths 2 --delay-ms 2,20,40)"
    stop_blackouts
fi

sleep 1
check "up session survived every case" bash -c "! grep -q reconnecting $WORK/client.log"
echo "--- up status (last line)"
tail -1 "$WORK/client.out"
exit $FAILED
