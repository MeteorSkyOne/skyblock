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
