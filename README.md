# netd

Unprivileged, cross-platform VM networking. This repository currently holds
the **Linux prototype of the socket-offload data path** and a benchmark
harness comparing it with native, passt, gvisor-tap-vsock, slirp and
tap+vhost-net.

## How the offload path works

```
guest app ──TCP──▶ iptables REDIRECT ──▶ netd-agent ──AF_VSOCK──▶ vhost-device-vsock ──unix──▶ netd ──TCP──▶ host / internet
                                       (SO_ORIGINAL_DST)          (vhost-user, no root)        (splice relay)
```

* No Ethernet frames, ARP, NAT or TCP state machine in the data path: the
  host kernel's TCP stack does the real work.
* Port forwards go the other way: `netd --forward 127.0.0.1:8080=80` connects
  to the agent's vsock port, which connects to the guest-local service.
* `netd-kvsock` uses the kernel `vhost-vsock` device instead of vhost-user
  (needs `/dev/vhost-vsock` access) and is kept as a reference.

## Crates

| crate | purpose |
|---|---|
| `netd-common` | offload wire protocol, splice relay, vsock helpers |
| `netd` | host daemon |
| `netd-agent` | guest agent |
| `nbench` | latency / connection-rate microbenchmark |

## Benchmark

Runs on GitHub Actions (`.github/workflows/bench.yml`, KVM-enabled
`ubuntu-24.04` runners) or any Linux host with KVM:

```sh
cargo build --release
bench/provision.sh            # Ubuntu 24.04 guest image with iperf3, agent, nbench
python3 bench/run.py          # all contenders, or e.g.: python3 bench/run.py native netd-vu passt-vu
```

Needs `qemu-system-x86`, `qemu-utils`, `cloud-image-utils`, `iperf3`, `passt`,
`gvproxy` (`GVPROXY=`), `vhost-device-vsock` (`VHOST_DEVICE_VSOCK=`) and sudo
for the privileged reference contenders.

## Prototype limitations

* TCP only (no UDP/ICMP/DNS yet); IPv4 destinations exercised by the benchmark.
* One thread pair per connection; no per-core sharding yet.
* `vhost-device-vsock` runs as a separate process; it will be embedded in netd.
