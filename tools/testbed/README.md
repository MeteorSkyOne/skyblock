# Testbed

Linux network namespaces + `tc netem` for the scenarios in SPEC §10.3.
Runs on any Linux box with iproute2, including WSL2 (verified on Debian):

```sh
wsl -d Debian -u root -- bash tools/testbed/netns.sh up
```

```sh
sudo tools/testbed/netns.sh up                 # create sb-client / sb-server / sb-game
sudo tools/testbed/netns.sh netem loss1        # clear|baseline|loss1|loss5|burst|jitter|reorder
sudo tools/testbed/netns.sh exec client ping 198.19.0.2
sudo tools/testbed/netns.sh down
```

| Namespace | Address | Role |
|---|---|---|
| `sb-client` | `198.18.0.2` | skyblock client (Linux TUN backend) + traffic generator |
| `sb-server` | `198.18.0.1`, `198.19.0.1` | skyblock-server; also routes directly for baselines |
| `sb-game` | `198.19.0.2` | echo / P2P peer / DNS |

The client↔server link gets the netem profile on both directions; one-way
delay defaults to 15ms (`SB_DELAY=25ms` to change).

## Scenario scripts

They take the directory holding `skyblock`, `skyblock-server` and `sbtest`
(Linux builds, e.g. `target/x86_64-unknown-linux-musl/release`) and tear the
testbed down on exit:

| Script | Scenarios |
|---|---|
| `m1.sh` | S1 added latency, S9 full cone, S10 probe, S12 inner filter |
| `m2.sh` | S2 random loss, S3 burst loss, S4 jitter/reorder, S5 path failure, S8 bulk + game |
| `m3.sh` | D1 DNS, F1 IP fragments, S6 rebinding / address change, S7 rekeying, P1 `skyblock ping`, ST `status`, S9 node restart |
| `m4.sh` | A1 adaptive copies, N1 NACK, P1 piggyback, B1 bulk shaping, BP busy polling |
| `weak.sh` | W1 heavy loss, W2 large jitter, W3 heavy reordering, W4 all combined, W5 loss bursts, W6 one bad path, W7 short blackouts |

`m2.sh` runs `skyblock bench` as a second user next to `up`;
`SB_BENCH_SECS` sets the measured time per bench setting (default 20; 15 for `weak.sh`). `SB_CASES="W5 W7"` runs only those weak-network cases.

Beyond the named profiles, `netns.sh netem custom "delay 30ms 20ms loss 10%"`
applies arbitrary netem arguments, and `netns.sh pathem 40001 "<args>"`
impairs only the tunnel path to node port 40001.
