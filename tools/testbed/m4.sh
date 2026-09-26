#!/usr/bin/env bash
# M4 checks in the netns testbed:
#   A1  adaptive copies: 5% loss raises both directions to 3 copies, a
#       clean link brings them back to 2
#   N1  NACK fast retransmission with a single copy under 5% loss
#   P1  piggybacked items across 30ms blackouts
#   B1  bulk shaping on the node: a download through a 50 Mbit bottleneck
#       with a 120ms buffer, next to game traffic
#   BP  node with busy polling pinned to a CPU
#
# Usage: sudo tools/testbed/m4.sh <dir containing skyblock, skyblock-server, sbtest>

set -uo pipefail

BIN=$(cd "${1:?usage: m4.sh <bin dir>}" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
NS="$HERE/netns.sh"
WORK=$(mktemp -d)
PIDS=()
BLACKOUT=()
UP=
SERVER=
FAILED=0

stop_pid() { pkill -P "$1" 2>/dev/null; kill "$1" 2>/dev/null; wait "$1" 2>/dev/null; }

cleanup() {
    for p in "${BLACKOUT[@]}" "${PIDS[@]}" $UP $SERVER; do stop_pid "$p"; done
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
gt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a > b) }'; }
status() { tail -1 "$WORK/client.out"; }
copies() { status | sed -n 's/.*| copies \([0-9]*\/[0-9]*\) |.*/\1/p'; }

bash "$NS" up || exit 1
in_ns game ip addr add 198.19.0.3/24 dev lan0

SERVER_KEYS=$("$BIN/skyblock" keygen)
CLIENT_KEYS=$("$BIN/skyblock" keygen)

server_conf() {
    cat <<EOF
private_key = "$(key_of private_key <<<"$SERVER_KEYS")"
ports = [40001, 40002]
egress = "lan0"
egress_ip = "198.19.0.1"
control_socket = "$WORK/ctl.sock"
$1

[[user]]
name = "tester"
public_key = "$(key_of '# public_key' <<<"$CLIENT_KEYS")"
vip = "10.77.0.2"
EOF
}

start_server() {
    [ -n "$SERVER" ] && stop_pid "$SERVER"
    server_conf "$1" >"$WORK/server.toml"
    in_ns server "$BIN/skyblock-server" run -c "$WORK/server.toml" >>"$WORK/server.log" 2>&1 &
    SERVER=$!
    sleep 0.3
}

# start_up "<[tunnel] lines>": (re)starts `up` with those tunnel settings.
start_up() {
    [ -n "$UP" ] && stop_pid "$UP"
    {
        echo "private_key = \"$(key_of private_key <<<"$CLIENT_KEYS")\""
        echo 'mode = "tun"'
        echo '[[node]]'
        echo 'name = "testbed"'
        echo 'addr = "198.18.0.1"'
        echo 'ports = [40001, 40002]'
        echo "public_key = \"$(key_of '# public_key' <<<"$SERVER_KEYS")\""
        echo
        echo '[tunnel]'
        echo 'paths = 2'
        echo 'copy_delay_ms = 2.0'
        echo "$1"
        echo
        echo '[tun]'
        echo 'routes = ["198.19.0.3/32"]'
    } >"$WORK/client.toml"
    : >"$WORK/client.log"
    in_ns client "$BIN/skyblock" up -c "$WORK/client.toml" >"$WORK/client.out" 2>"$WORK/client.log" &
    UP=$!
    for _ in $(seq 50); do
        grep -q "TUN capture ready" "$WORK/client.log" && break
        sleep 0.1
    done
    grep -q "TUN capture ready" "$WORK/client.log" || {
        echo "FAIL tunnel did not come up"
        cat "$WORK/client.log"
        exit 1
    }
    sleep 1.5
}

ping_game() { in_ns client "$BIN/sbtest" udp-ping --target 198.19.0.3:9000 "$@"; }
loss_of() { field loss_pct "$1"; }

# Drops everything for ON ms every EVERY ms, both directions (as weak.sh W7).
blackouts() {
    local on_s off_s ns
    on_s=$(awk -v m="$1" 'BEGIN { print m / 1000 }')
    off_s=$(awk -v m="$(($2 - $1))" 'BEGIN { print m / 1000 }')
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
    for p in "${BLACKOUT[@]}"; do stop_pid "$p"; done
    BLACKOUT=()
    sleep 0.2
    bash "$NS" netem baseline
}

for addr in 198.19.0.2 198.19.0.3; do
    in_ns game "$BIN/sbtest" echo --bind "$addr:9000" 2>/dev/null &
    PIDS+=($!)
done
in_ns game "$BIN/sbtest" tcp-source --bind 198.19.0.3:9001 2>/dev/null &
PIDS+=($!)
start_server ""

echo "=== A1 adaptive copies"
start_up $'copies = 2\ncopies_max = 2\nnack = false'
bash "$NS" netem loss5
fixed=$(ping_game --count 2000 --interval-ms 10)
start_up $'copies = 2\ncopies_max = 3\nnack = false'
bash "$NS" netem loss5
ping_game --count 2000 --interval-ms 10 >"$WORK/a1.out" &
PING=$!
sleep 8
during=$(copies)
wait "$PING"
adaptive=$(cat "$WORK/a1.out")
bash "$NS" netem baseline
echo "  A1 fixed 2:    $(grep '^udp sent' <<<"$fixed")"
echo "  A1 adaptive:   $(grep '^udp sent' <<<"$adaptive")"
echo "  A1 copies (up/down) under 5% loss: $during"
check "A1 5% loss raises both directions to 3 copies" [ "$during" = 3/3 ]
check "A1 adaptive loses less than fixed 2 copies ($(loss_of "$adaptive")% < $(loss_of "$fixed")%)" \
    lt "$(loss_of "$adaptive")" "$(loss_of "$fixed")"
ping_game --count 2800 --interval-ms 10 >/dev/null
after=$(copies)
echo "  A1 copies 28s after the loss stopped: $after"
check "A1 back to 2 copies on a clean link" [ "$after" = 2/2 ]

echo "=== N1 NACK with one copy, 5% loss each way"
start_up $'copies = 1\ncopies_max = 1\nnack = false'
bash "$NS" netem loss5
off=$(ping_game --count 2000 --interval-ms 10)
start_up $'copies = 1\ncopies_max = 1\nnack = true'
bash "$NS" netem loss5
on=$(ping_game --count 2000 --interval-ms 10)
bash "$NS" netem baseline
echo "  N1 without NACK: $(grep '^udp sent' <<<"$off")"
echo "  N1 with NACK:    $(grep '^udp sent' <<<"$on")"
check "N1 NACK cuts round-trip loss to under a quarter ($(loss_of "$on")% vs $(loss_of "$off")%)" \
    lt "$(loss_of "$on")" "$(awk -v l="$(loss_of "$off")" 'BEGIN { print l / 4 }')"
# One retransmission each way: 30ms + 2 x (10ms to notice + 5ms wait +
# 15ms NACK + 15ms resend) = 120ms.
check "N1 at most one retransmission each way (max $(field max_us "$on")us < 150ms)" \
    lt "$(field max_us "$on")" 150000

echo "=== P1 piggybacking across 30ms blackouts every 500ms"
start_up $'copies = 2\ncopies_max = 2\nnack = false\npiggyback = 0'
blackouts 30 500
off=$(ping_game --count 2000 --interval-ms 8)
stop_blackouts
start_up $'copies = 2\ncopies_max = 2\nnack = false\npiggyback = 4'
blackouts 30 500
on=$(ping_game --count 2000 --interval-ms 8)
stop_blackouts
echo "  P1 piggyback 0: $(grep '^udp sent' <<<"$off")"
echo "  P1 piggyback 4: $(grep '^udp sent' <<<"$on")"
check "P1 piggybacking halves the loss ($(loss_of "$on")% vs $(loss_of "$off")%)" \
    lt "$(loss_of "$on")" "$(awk -v l="$(loss_of "$off")" 'BEGIN { print l / 2 }')"

echo "=== B1 bulk shaping behind a 50 Mbit bottleneck with a 120ms buffer"
bash "$NS" netem custom "delay 15ms rate 50mbit limit 500"
b1() {
    start_up "$1"
    local base load
    base=$(ping_game --count 500 --interval-ms 8)
    in_ns client "$BIN/sbtest" tcp-sink --target 198.19.0.3:9001 --secs 10 >"$WORK/sink.out" &
    local sink=$!
    sleep 2
    load=$(ping_game --count 800 --interval-ms 8)
    wait "$sink"
    echo "  B1 $2 alone:    $(grep '^udp sent' <<<"$base")"
    echo "  B1 $2 download: $(grep '^udp sent' <<<"$load")"
    echo "  B1 $2 sink:     $(cat "$WORK/sink.out")"
    B1_ADDED=$(($(field p99_us "$load") - $(field p99_us "$base")))
    B1_MBPS=$(field mbps "$(cat "$WORK/sink.out")")
    echo "  B1 $2 game p99 added: ${B1_ADDED}us, download ${B1_MBPS}Mbps"
}
b1 $'copies = 2\nbulk_rate_mbps = 0' "unshaped"
unshaped=$B1_ADDED
b1 $'copies = 2\nbulk_rate_mbps = 42' "shaped 42M"
bash "$NS" netem baseline
check "B1 unshaped download queues the game (p99 +${unshaped}us > 20ms)" gt "$unshaped" 20000
check "B1 shaping keeps the game p99 within 5ms (+${B1_ADDED}us)" lt "$B1_ADDED" 5000
check "B1 shaped download still gets most of the rate (${B1_MBPS}Mbps > 30)" gt "$B1_MBPS" 30
status=$(in_ns server "$BIN/skyblock-server" status -c "$WORK/server.toml")
grep '^  shaping' <<<"$status" | sed 's/^/  B1 /'
check "B1 node reports the shaper" grep -q "^  shaping 42000kbps" <<<"$status"

echo "=== BP busy polling on CPU 0"
start_server $'busy_poll = true\ncpu = 0'
start_up 'copies = 2'
out=$(ping_game --count 1000 --interval-ms 5)
echo "  BP: $(grep '^udp sent' <<<"$out")"
cpu=$(ps -o pcpu= -p "$(pgrep -f "skyblock-server run -c $WORK/server.toml")" | tr -d ' ')
echo "  BP: node CPU ${cpu}%"
check "BP no loss" [ "$(field recv "$out")" = 1000 ]
check "BP node spins (CPU ${cpu}% > 50%)" gt "${cpu:-0}" 50

echo "--- client log (warnings)"
grep -E "WARN|ERROR" "$WORK/client.log" | tail -5
exit $FAILED
