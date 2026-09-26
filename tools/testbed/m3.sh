#!/usr/bin/env bash
# M3 checks in the netns testbed (SPEC §10.3):
#   D1  DNS through the resolver VIP (node-side forwarding)
#   F1  oversized UDP both ways: inner IPv4 fragments reassembled by the
#       node, answers carried in IP_FRAG frames
#   S6  a path's 5-tuple blackholed: the client moves it to a new socket and
#       the node follows by trial decryption; then the client's address
#       changes under a running session
#   S7  rekeys every 3s while traffic flows (all of the above run with it)
#   P1  `skyblock ping` with ICMP and TCP probes, and a refused target
#   ST  `skyblock-server status`
#   S9  the node restarts mid-stream: the client handshakes again after 3s
#       of silence instead of waiting 15s for the session to die
#
# Usage: sudo tools/testbed/m3.sh <dir containing skyblock, skyblock-server, sbtest>

set -uo pipefail

BIN=$(cd "${1:?usage: m3.sh <bin dir>}" && pwd)
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

ge() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a >= b) }'; }

# Local port of the client's socket for path 0 (to node port 40001).
path0_port() {
    in_ns client ss -Hunp | awk '/skyblock/ {
        for (i = 2; i <= NF; i++) if ($i == "198.18.0.1:40001") { n = split($(i - 1), a, ":"); print a[n]; exit }
    }'
}

# (The log has colour codes between a field's name, `=` and value.)
established() {
    sed 's/\x1b\[[0-9;]*m//g' "$WORK/server.log" |
        grep -c 'session established.*user=tester\|user=tester.*session established'
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
dns_upstream = ["198.19.0.2"]
control_socket = "$WORK/ctl.sock"

[[user]]
name = "tester"
public_key = "$(key_of '# public_key' <<<"$CLIENT_KEYS")"
vip = "10.77.0.2"

[[user]]
name = "pinger"
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
EOF
}
{
    echo "private_key = \"$(key_of private_key <<<"$CLIENT_KEYS")\""
    echo 'mode = "tun"'
    node_block
    echo
    echo '[tunnel]'
    echo 'paths = 2'
    echo 'copies = 2'
    echo 'copy_delay_ms = 2.0'
    echo 'rekey_interval_s = 3'
    echo
    echo '[tun]'
    echo 'routes = ["198.19.0.3/32"]'
} >"$WORK/client.toml"
{
    echo "private_key = \"$(key_of private_key <<<"$BENCH_KEYS")\""
    node_block
} >"$WORK/ping.toml"

in_ns game "$BIN/sbtest" echo --bind 198.19.0.2:9000 2>/dev/null &
PIDS+=($!)
in_ns game "$BIN/sbtest" echo --bind 198.19.0.3:9000 2>/dev/null &
PIDS+=($!)
in_ns game "$BIN/sbtest" dns-server --bind 198.19.0.2:53 --answer 198.19.0.3 \
    >"$WORK/dns.log" 2>/dev/null &
PIDS+=($!)
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
    cat "$WORK/client.log"
    tail -20 "$WORK/server.log"
    exit 1
fi
echo "PASS tunnel up (2 paths, rekey every 3s)"
sleep 1

# D1: DNS through the resolver VIP; the node forwards to 198.19.0.2.
out=$(in_ns client "$BIN/sbtest" dns-query --server 10.77.0.1:53 --name game.example.com)
echo "  D1: $out"
check "D1 answer through the node" grep -q "answer=198.19.0.3" <<<"$out"
check "D1 upstream saw the node's address" grep -q "from=198.19.0.1:.*name=game.example.com" "$WORK/dns.log"

# F1: 3000-byte datagrams (fragmented at the TUN MTU of 1400 on the way
# out; 3028-byte packets in IP_FRAG frames on the way back).
for size in 1472 3000 8000; do
    out=$(in_ns client "$BIN/sbtest" udp-ping --target 198.19.0.3:9000 --count 200 --interval-ms 5 --size "$size")
    echo "  F1 $size B: $(grep '^udp sent' <<<"$out")"
    check "F1 $size-byte datagrams both ways" [ "$(field recv "$out")" = 200 ]
done

# S7: sustained traffic across several rekeys.
before=$(established)
out=$(in_ns client "$BIN/sbtest" udp-ping --target 198.19.0.3:9000 --count 2000 --interval-ms 10)
tcp=$(in_ns client "$BIN/sbtest" tcp-ping --target 198.19.0.3:9000 --count 300 --interval-ms 10)
status=$(in_ns server "$BIN/skyblock-server" status -c "$WORK/server.toml")
rekeys=$(sed -n 's/.*user tester .*rekeys \([0-9]*\),.*/\1/p' <<<"$status")
echo "  S7: $(grep '^udp sent' <<<"$out")"
echo "  S7: $(grep '^tcp sent' <<<"$tcp")"
echo "  S7: rekeys so far: $rekeys"
check "S7 no UDP loss or duplicates across rekeys" \
    [ "$(field recv "$out")" = 2000 -a "$(field dup "$out")" = 0 ]
check "S7 TCP unaffected" [ "$(field recv "$tcp")" = 300 ]
check "S7 rekeyed at least 7 times" ge "${rekeys:-0}" 7
check "S7 no re-handshake" [ "$(established)" = "$before" ]

# S6a: blackhole path 0's current 5-tuple (as if the ISP dropped it). The
# client moves the path to a new socket once it has been silent 15s.
port=$(path0_port)
echo "  S6a: blocking path 0 (local port $port)"
in_ns client "$BIN/sbtest" udp-ping --target 198.19.0.3:9000 --count 2500 --interval-ms 10 \
    >"$WORK/s6a.out" &
PING=$!
sleep 1
in_ns client nft -f - <<EOF
table inet s6 {
    chain out { type filter hook output priority 0; udp sport $port drop; }
    chain in { type filter hook input priority 0; udp dport $port drop; }
}
EOF
sleep 8
during=$(tail -1 "$WORK/client.out")
wait "$PING"
after=$(tail -1 "$WORK/client.out")
in_ns client nft delete table inet s6
newport=$(path0_port)
out=$(cat "$WORK/s6a.out")
echo "  S6a: $(grep '^udp sent' <<<"$out")"
echo "  S6a: status while blocked: $(sed 's/.*| paths/paths/' <<<"$during")"
echo "  S6a: status after:         $(sed 's/.*| paths/paths/' <<<"$after")"
echo "  S6a: path 0 local port $port -> $newport"
check "S6a no loss while one path is blackholed" [ "$(field recv "$out")" = 2500 ]
check "S6a path moved to a new local port" [ -n "$newport" -a "$newport" != "$port" ]
check "S6a path back up on the new port" grep -q "paths 2/2" <<<"$after"
check "S6a node followed the path without a handshake" [ "$(established)" = "$before" ]

# S6b: the client's address changes (198.18.0.2 -> 198.18.0.3) mid-stream.
in_ns client sysctl -qw net.ipv4.conf.wan0.promote_secondaries=1
in_ns client ip addr add 198.18.0.3/24 dev wan0
in_ns client "$BIN/sbtest" udp-ping --target 198.19.0.3:9000 --count 1000 --interval-ms 10 \
    >"$WORK/s6b.out" &
PING=$!
sleep 3
in_ns client ip addr del 198.18.0.2/24 dev wan0
wait "$PING"
out=$(cat "$WORK/s6b.out")
echo "  S6b: $(grep '^udp sent' <<<"$out")"
echo "  S6b: $(grep -c 'path moved to a new socket' "$WORK/client.log") socket moves in the client log"
check "S6b at most 5 of 1000 lost across the address change" ge "$(field recv "$out")" 995
check "S6b no re-handshake" [ "$(established)" = "$before" ]
check "S6b node sees the new address" grep -q "198.18.0.3" <<<"$(in_ns server "$BIN/skyblock-server" status -c "$WORK/server.toml")"

# P1: node selection with probes (as a second user, so `up` keeps going).
out=$(in_ns client "$BIN/skyblock" ping -c "$WORK/ping.toml" --target 198.19.0.2 2>/dev/null)
echo "$out" | sed 's/^/  P1 icmp: /'
check "P1 ICMP probe answered 10/10" grep -q "10/10)" <<<"$(tail -1 <<<"$out")"
out=$(in_ns client "$BIN/skyblock" ping -c "$WORK/ping.toml" --target 198.19.0.2 --probe tcp:9000 2>/dev/null)
echo "$out" | tail -1 | sed 's/^/  P1 tcp open: /'
check "P1 TCP probe (SYN-ACK) answered" grep -q "10/10)" <<<"$(tail -1 <<<"$out")"
out=$(in_ns client "$BIN/skyblock" ping -c "$WORK/ping.toml" --target 198.19.0.2 --probe tcp:9999 --count 5 2>/dev/null)
echo "$out" | tail -1 | sed 's/^/  P1 tcp closed: /'
check "P1 TCP probe (RST) answered" grep -q "5/5)" <<<"$(tail -1 <<<"$out")"
out=$(in_ns client "$BIN/skyblock" ping -c "$WORK/ping.toml" --target 169.254.169.254 --count 3 2>/dev/null)
echo "$out" | tail -1 | sed 's/^/  P1 refused: /'
check "P1 metadata address refused" grep -q "(-, 0/0)" <<<"$(tail -1 <<<"$out")"

# ST: status report (after ping's CLOSE has crossed the 15ms link).
sleep 0.5
status=$(in_ns server "$BIN/skyblock-server" status -c "$WORK/server.toml")
echo "--- status"
echo "$status"
check "ST session and both paths listed" \
    [ "$(grep -c '^  path ' <<<"$(sed -n '/^user tester/,/^user pinger/p' <<<"$status")")" = 2 ]
check "ST counters listed" grep -q "^dns via .*answers 1," <<<"$status"
check "ST ping sessions closed" grep -q "^user pinger (10.77.0.3): no session" <<<"$status"

# S9 (last: it resets the node's counters): the node restarts mid-stream,
# forgets the session and ignores its packets.
before=$(established)
in_ns client "$BIN/sbtest" udp-ping --target 198.19.0.3:9000 --count 1000 --interval-ms 10 \
    >"$WORK/s9.out" &
PING=$!
sleep 2
pkill -f "skyblock-server --log-level debug run -c $WORK/server.toml"
sleep 0.2
in_ns server "$BIN/skyblock-server" --log-level debug run -c "$WORK/server.toml" \
    >>"$WORK/server.log" 2>&1 &
PIDS+=($!)
wait "$PING"
out=$(cat "$WORK/s9.out")
lost=$((1000 - $(field recv "$out")))
echo "  S9: $(grep '^udp sent' <<<"$out")"
check "S9 back within 4s of the restart ($lost x 10ms lost)" [ "$lost" -le 400 ]
check "S9 handshake beside the silent session" \
    grep -q "handshaking again beside the session" "$WORK/client.log"
check "S9 new session on the restarted node" [ "$(established)" -gt "$before" ]

echo "--- client status (last line)"
tail -1 "$WORK/client.out"
echo "--- client log (warnings / socket moves)"
grep -E "WARN|moved|silent" "$WORK/client.log" | tail -8

exit $FAILED
