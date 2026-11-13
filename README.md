# netd

Unprivileged, cross-platform VM networking. This repository currently holds
the **Linux prototype of the socket-offload data path** and a benchmark
harness comparing it with native, passt, gvisor-tap-vsock, slirp and
tap+vhost-net.

## How the offload path works

```
guest app ──TCP──▶ iptables REDIRECT ──▶ netd-agent ──AF_VSOCK──▶ netd (vhost-user-vsock device) ──TCP──▶ host / internet
                                       (SO_ORIGINAL_DST)          (unix socket to QEMU, no root)
```

* No Ethernet frames, ARP, NAT or TCP state machine in the data path: the
  host kernel's TCP stack does the real work.
* Port forwards go the other way: `netd --forward 127.0.0.1:8080=80` connects
  to the agent's vsock port, which connects to the guest-local service.
* QEMU: `-chardev socket,id=c1,path=SOCK -device vhost-user-vsock-pci,chardev=c1`
  with shared guest memory; netd: `--vhost-user SOCK --guest-cid 3`.

### Shared-memory data path

As the vhost-user backend, netd already maps all guest RAM. The agent
allocates hugepages (pinned, physically contiguous), looks up their
guest-physical addresses in `/proc/self/pagemap` and registers them with netd
over vsock (`--shm-slots N`, default 16; 0 = off). Each offloaded connection
that gets a slot then moves its payload through two lock-free byte rings
(guest→host and host→guest, 2 MiB each, `netd_common::shm`); netd reads and
writes the host socket directly from/to guest memory. The connection's vsock
stream only carries the handshake and one-byte doorbells, sent only when the
other side has announced that it is about to sleep. netd validates every ring
position, so a misbehaving guest can only corrupt its own connections.
Connections without a free slot fall back to payload over vsock.

Doorbells cost a guest kernel round trip, a VM exit and an interrupt, so both
sides poll briefly before arming them: netd's worker keeps servicing active
rings for `--busy-poll-us` (default 50) after the last work, like vhost-net's
busyloop, and the agent spins for `--spin-us` (default 50) before sleeping.
For outbound connections the agent initially spins for 200 µs, until the
first response or 256 KiB of outbound data; an explicit `--spin-us` sets
both budgets. Set either option to zero to disable polling on that side.
Both only poll while waiting for data: a side blocked by a full ring or
socket is in a bulk transfer and sleeps until the peer has freed half the
ring, rather than taking CPU from the peer that has to make room. The host
also stops busy-polling after a full chunk of recent transfer activity; on
the next activity after 1 ms idle, it becomes eligible to poll again. Payload
is published in chunks of up to 256 KiB guest-to-host or 512 KiB
host-to-guest, so both sides copy at the same time. The host can combine
published guest-to-host chunks into a 512 KiB socket write.

Connection setup avoids round trips too. Each ring slot has one persistent
vsock stream, opened when the rings are registered, and the slot's
connections run over it one after another: the agent sends `Open{id, dst}`,
starts relaying at once without waiting for an answer, and finishes with
`Close` or `Reset`. netd only replies with `Fail{id, errno}` if the connect
fails, and the agent then resets the guest connection. A connection therefore
costs no vsock stream setup or teardown, only a few frames. When no slot is
free (or shm is off) the agent falls back to its `--pool N` (default 4) of
per-connection vsock streams.

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
python3 bench/run.py          # all contenders, or e.g.: python3 bench/run.py netd
```

Needs `qemu-system-x86`, `qemu-utils`, `cloud-image-utils`, `iperf3`, `passt`,
`gvproxy` (`GVPROXY=`) and sudo
for the privileged reference contenders.

Percentages are given against `native` (host loopback, unrestricted) and
`native-cpu` (host loopback pinned to as many CPUs as the guest has vCPUs),
the fairer bound when the runner has few cores.

## Prototype limitations

* TCP only (no UDP/ICMP/DNS yet); IPv4 destinations exercised by the benchmark.
* One thread pair per connection; no per-core sharding yet.
