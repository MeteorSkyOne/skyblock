#!/usr/bin/env bash
# Network-namespace testbed for skyblock.
#
#   sb-client  wan0 198.18.0.2/24 ──┐  netem on both wan0 egresses
#   sb-server  wan0 198.18.0.1/24 ──┘
#              lan0 198.19.0.1/24 ──┐
#   sb-game    lan0 198.19.0.2/24 ──┘
#
# sb-server also routes between the two links, so the client can reach the
# game directly (no tunnel) for baseline comparisons.
#
# Requires root, iproute2 and the sch_netem module.
#
# Usage:
#   netns.sh up | down | status
#   netns.sh netem <profile>        apply a link profile (see below)
#   netns.sh netem custom "<args>"  apply arbitrary netem arguments
#   netns.sh pathem <port> "<args>" impair only the tunnel path to node port <port>
#   netns.sh exec <client|server|game> <cmd...>

set -euo pipefail

NS_CLIENT=sb-client
NS_SERVER=sb-server
NS_GAME=sb-game

# One-way delay on the client<->server link, so the base RTT is 2x this.
DELAY=${SB_DELAY:-15ms}

die() {
    echo "netns.sh: $*" >&2
    exit 1
}

in_ns() {
    local ns=$1
    shift
    ip netns exec "$ns" "$@"
}

up() {
    [[ $EUID -eq 0 ]] || die "must run as root"
    down 2>/dev/null || true

    ip netns add "$NS_CLIENT"
    ip netns add "$NS_SERVER"
    ip netns add "$NS_GAME"

    ip link add wan0 netns "$NS_CLIENT" type veth peer name wan0 netns "$NS_SERVER"
    ip link add lan0 netns "$NS_SERVER" type veth peer name lan0 netns "$NS_GAME"

    in_ns "$NS_CLIENT" ip addr add 198.18.0.2/24 dev wan0
    in_ns "$NS_SERVER" ip addr add 198.18.0.1/24 dev wan0
    in_ns "$NS_SERVER" ip addr add 198.19.0.1/24 dev lan0
    in_ns "$NS_GAME" ip addr add 198.19.0.2/24 dev lan0

    for ns in "$NS_CLIENT" "$NS_SERVER" "$NS_GAME"; do
        in_ns "$ns" ip link set lo up
    done
    in_ns "$NS_CLIENT" ip link set wan0 up
    in_ns "$NS_SERVER" ip link set wan0 up
    in_ns "$NS_SERVER" ip link set lan0 up
    in_ns "$NS_GAME" ip link set lan0 up

    # Direct path for baselines: client -> server (router) -> game.
    in_ns "$NS_SERVER" sysctl -qw net.ipv4.ip_forward=1
    in_ns "$NS_CLIENT" ip route add 198.19.0.0/24 via 198.18.0.1
    in_ns "$NS_GAME" ip route add 198.18.0.0/24 via 198.19.0.1

    netem baseline
    echo "testbed up (one-way delay $DELAY)"
}

down() {
    for ns in "$NS_CLIENT" "$NS_SERVER" "$NS_GAME"; do
        ip netns del "$ns" 2>/dev/null || true
    done
}

# netem profiles, applied to wan0 in both namespaces.
netem() {
    local profile=${1:-}
    local args
    case "$profile" in
        clear) args="" ;;
        baseline) args="delay $DELAY" ;;
        loss1) args="delay $DELAY loss 1%" ;;
        loss5) args="delay $DELAY loss 5%" ;;
        # Gilbert-Elliott: p(good->bad)=1%, p(bad->good)=30%,
        # loss 70% in the bad state, 0.1% in the good state.
        burst) args="delay $DELAY loss gemodel 1% 30% 70% 0.1%" ;;
        jitter) args="delay $DELAY 5ms distribution normal" ;;
        reorder) args="delay $DELAY reorder 10% 50%" ;;
        # Anything else: `netem custom "delay 30ms 20ms loss 10%"`.
        custom) args=${2:?netem custom needs netem arguments} ;;
        *) die "unknown profile '$profile' (clear|baseline|loss1|loss5|burst|jitter|reorder|custom ARGS)" ;;
    esac
    for ns in "$NS_CLIENT" "$NS_SERVER"; do
        in_ns "$ns" tc qdisc del dev wan0 root 2>/dev/null || true
        if [[ -n $args ]]; then
            # shellcheck disable=SC2086 # args is a word list on purpose
            in_ns "$ns" tc qdisc add dev wan0 root netem $args
        fi
    done
}

# Impairs one tunnel path only: UDP to/from node port PORT gets netem ARGS,
# everything else the baseline delay (both directions).
pathem() {
    local port=$1 args=$2 ns match
    for ns in "$NS_CLIENT" "$NS_SERVER"; do
        [[ $ns == "$NS_CLIENT" ]] && match=dport || match=sport
        in_ns "$ns" tc qdisc del dev wan0 root 2>/dev/null || true
        in_ns "$ns" tc qdisc add dev wan0 root handle 1: prio bands 3 \
            priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
        in_ns "$ns" tc qdisc add dev wan0 parent 1:1 handle 10: netem delay "$DELAY"
        in_ns "$ns" tc qdisc add dev wan0 parent 1:2 handle 20: netem delay "$DELAY"
        # shellcheck disable=SC2086 # args is a word list on purpose
        in_ns "$ns" tc qdisc add dev wan0 parent 1:3 handle 30: netem $args
        in_ns "$ns" tc filter add dev wan0 parent 1: protocol ip prio 1 u32 \
            match ip protocol 17 0xff match ip "$match" "$port" 0xffff flowid 1:3
    done
}

status() {
    for ns in "$NS_CLIENT" "$NS_SERVER" "$NS_GAME"; do
        echo "== $ns"
        in_ns "$ns" ip -brief addr
        in_ns "$ns" tc qdisc show | grep netem || true
    done
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    status) status ;;
    netem)
        [[ $# -ge 2 ]] || die "usage: netns.sh netem <profile>"
        netem "$2" "${3:-}"
        ;;
    pathem)
        [[ $# -ge 3 ]] || die "usage: netns.sh pathem <node port> <netem args>"
        pathem "$2" "$3"
        ;;
    exec)
        [[ $# -ge 3 ]] || die "usage: netns.sh exec <client|server|game> <cmd...>"
        ns="sb-$2"
        shift 2
        in_ns "$ns" "$@"
        ;;
    *) die "usage: netns.sh up|down|status|netem <profile> [args]|pathem <port> <args>|exec <ns> <cmd...>" ;;
esac
