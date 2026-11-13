#!/usr/bin/env python3
"""Benchmark guest networking options on a Linux KVM host.

Every contender boots the same provisioned guest (bench/work/base.qcow2) with
identical QEMU settings except networking, then runs:

  up1 / down1   iperf3 guest -> host / host -> guest, 1 stream
  up4 / down4   same with 4 parallel streams
  fwd1          iperf3 host -> guest service through the port forward
  rr            nbench 64-byte request/response latency (guest -> host)
  crr           nbench connections per second (guest -> host)

"native" runs the same clients on the host against host loopback. Guest
control uses qemu-guest-agent over virtio-serial, so it works without any
guest network.
"""

import argparse
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
W = ROOT / "bench" / "work"
BIN = ROOT / "target" / "release"
MAC = "52:54:00:12:34:56"
FWD_HOST_PORT = 15301
GUEST_IPERF_PORT = 5301
NBENCH_PORT = 7000
TAP = "nbtap0"

ARGS_VCPUS = 2
ALL = ["native", "tap-vhost", "slirp", "gvproxy", "passt", "passt-vu", "netd"]
NETD = ["netd"]
BASELINE = Path(__file__).resolve().parent / "baseline" / "linux-kvm.json"


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def sh(cmd, check=True, **kw):
    log("+", cmd if isinstance(cmd, str) else " ".join(map(str, cmd)))
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check, **kw)


def wait_path(p, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if Path(p).exists():
            return
        time.sleep(0.1)
    raise RuntimeError(f"timeout waiting for {p}")


def cpu_seconds(pid):
    """utime+stime of a process (all threads) in seconds."""
    try:
        f = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError):
        return 0.0


class QGA:
    def __init__(self, path):
        self.path = str(path)
        self.sock = None
        self.buf = b""
        self.seq = int(time.time())

    def _connect(self):
        if self.sock:
            self.sock.close()
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(self.path)
        self.buf = b""

    def _send(self, obj):
        self.sock.sendall(json.dumps(obj).encode() + b"\n")

    def _recv(self, timeout):
        self.sock.settimeout(timeout)
        while True:
            while b"\n" not in self.buf:
                d = self.sock.recv(1 << 20)
                if not d:
                    raise ConnectionError("qga closed")
                self.buf += d
            line, self.buf = self.buf.split(b"\n", 1)
            # guest-sync-delimited prefixes its reply with a 0xFF sentinel.
            line = line.lstrip(b"\xff").strip()
            if line:
                return json.loads(line)

    def wait(self, timeout=240, proc=None, console=None):
        end = time.time() + timeout
        while time.time() < end:
            if proc is not None and proc.poll() is not None:
                raise RuntimeError(f"qemu exited with {proc.returncode}")
            try:
                self._connect()
                self.seq += 1
                # 0xFF resets the guest agent's JSON parser after junk.
                self.sock.sendall(b"\xff")
                self._send({"execute": "guest-sync-delimited", "arguments": {"id": self.seq}})
                t = time.time() + 3
                while time.time() < t:
                    r = self._recv(3)
                    if r.get("return") == self.seq:
                        return
            except (OSError, ValueError, ConnectionError):
                time.sleep(1)
        tail = ""
        if console:
            try:
                tail = "\n".join(Path(console).read_text(errors="replace").splitlines()[-15:])
            except OSError:
                pass
        raise RuntimeError(f"guest agent did not come up; console tail:\n{tail}")

    def cmd(self, execute, args=None, timeout=30):
        msg = {"execute": execute}
        if args is not None:
            msg["arguments"] = args
        self._send(msg)
        r = self._recv(timeout)
        if "error" in r:
            raise RuntimeError(f"qga {execute}: {r['error']}")
        return r.get("return")

    def run(self, argv, timeout=180, check=True):
        if isinstance(argv, str):
            argv = ["/bin/sh", "-c", argv]
        pid = self.cmd("guest-exec", {"path": argv[0], "arg": argv[1:], "capture-output": True})["pid"]
        end = time.time() + timeout
        while time.time() < end:
            st = self.cmd("guest-exec-status", {"pid": pid})
            if st.get("exited"):
                out = base64.b64decode(st.get("out-data", "")).decode(errors="replace")
                err = base64.b64decode(st.get("err-data", "")).decode(errors="replace")
                rc = st.get("exitcode", -1)
                if check and rc != 0:
                    raise RuntimeError(f"guest command failed ({rc}): {argv}\n{out}\n{err}")
                return rc, out, err
            time.sleep(0.2)
        raise RuntimeError(f"guest command timed out: {argv}")


class Contender:
    """Base: a guest with one virtio-net NIC attached to some backend."""

    name = ""
    host_ip = ""          # address the guest uses to reach host loopback services
    mtu_note = ""

    def __init__(self, procs):
        self.procs = procs  # list of Popen to stop afterwards

    def spawn(self, argv, name, env=None):
        f = open(W / f"{self.name}-{name}.log" if not name.startswith(self.name) else W / f"{name}.log", "w")
        log("+", " ".join(map(str, argv)))
        p = subprocess.Popen([str(a) for a in argv], stdout=f, stderr=subprocess.STDOUT,
                             env=dict(os.environ, **(env or {})))
        self.procs.append(p)
        return p

    def helpers(self):
        """Host-side backend processes whose CPU time is attributed to networking."""
        return [p for p in self.procs if p.args and "qemu-system" not in p.args[0]]

    def start_backend(self):
        pass

    def qemu_net(self):
        return []

    def guest_setup(self, g):
        pass

    def setup_forward(self, g):
        """Return (host, port) on the host that reaches GUEST_IPERF_PORT in the guest."""
        raise NotImplementedError

    def nic(self, netdev="n0"):
        return ["-device", f"virtio-net-pci,netdev={netdev},mac={MAC}"]


def guest_wait_ipv4(g, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        _, out, _ = g.run("ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1", check=False)
        if out.strip():
            return out.strip()
        time.sleep(1)
    raise RuntimeError("guest got no IPv4 address")


def guest_iface(g):
    _, out, _ = g.run("ls /sys/class/net | grep -E '^en' | head -1")
    return out.strip()


class TapVhost(Contender):
    name = "tap-vhost"
    host_ip = "172.30.0.1"
    mtu_note = "1500 (privileged: tap + vhost-net)"

    def start_backend(self):
        user = os.environ.get("USER") or subprocess.check_output(["id", "-un"], text=True).strip()
        sh(f"sudo ip link del {TAP} 2>/dev/null || true")
        sh(f"sudo ip tuntap add dev {TAP} mode tap user {user} && sudo ip addr add 172.30.0.1/24 dev {TAP} && sudo ip link set {TAP} up")
        sh("sudo modprobe vhost_net && sudo chmod 666 /dev/vhost-net")

    def qemu_net(self):
        return ["-netdev", f"tap,id=n0,ifname={TAP},script=no,downscript=no,vhost=on"] + self.nic()

    def guest_setup(self, g):
        i = guest_iface(g)
        g.run(f"ip link set {i} up && ip addr add 172.30.0.2/24 dev {i}")

    def setup_forward(self, g):
        return "172.30.0.2", GUEST_IPERF_PORT  # routed, no forwarding needed

    def cleanup(self):
        sh(f"sudo ip link del {TAP}", check=False)


class Slirp(Contender):
    name = "slirp"
    host_ip = "10.0.2.2"
    mtu_note = "1500"

    def qemu_net(self):
        fwd = f"hostfwd=tcp:127.0.0.1:{FWD_HOST_PORT}-:{GUEST_IPERF_PORT}"
        return ["-netdev", f"user,id=n0,{fwd}"] + self.nic()

    def guest_setup(self, g):
        guest_wait_ipv4(g)

    def setup_forward(self, g):
        return "127.0.0.1", FWD_HOST_PORT


class Gvproxy(Contender):
    name = "gvproxy"
    host_ip = "192.168.127.254"
    mtu_note = "1500 (gvproxy default)"

    def start_backend(self):
        for s in ("gv.sock", "gv-api.sock"):
            (W / s).unlink(missing_ok=True)
        self.spawn([os.environ.get("GVPROXY", "gvproxy"), "-listen-qemu", f"unix://{W}/gv.sock",
                    "-listen", f"unix://{W}/gv-api.sock", "-ssh-port", "-1"], "gvproxy")
        wait_path(W / "gv.sock")

    def qemu_net(self):
        return ["-netdev", f"stream,id=n0,server=off,addr.type=unix,addr.path={W}/gv.sock"] + self.nic()

    def guest_setup(self, g):
        self.guest_ip = guest_wait_ipv4(g)

    def setup_forward(self, g):
        body = json.dumps({"local": f"127.0.0.1:{FWD_HOST_PORT}", "remote": f"{self.guest_ip}:{GUEST_IPERF_PORT}"})
        sh(["curl", "-fsS", "--unix-socket", f"{W}/gv-api.sock", "http://gv/services/forwarder/expose",
            "-X", "POST", "-d", body])
        return "127.0.0.1", FWD_HOST_PORT


def default_gw():
    out = subprocess.check_output(["ip", "-4", "route", "show", "default"], text=True).split()
    return out[out.index("via") + 1]


class Passt(Contender):
    name = "passt"
    mtu_note = "65520 (passt default)"
    vhost_user = False

    def __init__(self, procs):
        super().__init__(procs)
        self.host_ip = default_gw()  # passt maps the gateway address to host loopback

    def start_backend(self):
        s = W / (self.name + ".sock")
        s.unlink(missing_ok=True)
        argv = [os.environ.get("PASST", "passt"), "-f", "-q", "--socket", s, "-t", f"{FWD_HOST_PORT}:{GUEST_IPERF_PORT}"]
        if self.vhost_user:
            argv.insert(3, "--vhost-user")
        self.spawn(argv, self.name)
        wait_path(s)

    def qemu_net(self):
        s = W / (self.name + ".sock")
        if self.vhost_user:
            return ["-chardev", f"socket,id=c0,path={s}", "-netdev", "vhost-user,id=n0,chardev=c0"] + self.nic()
        return ["-netdev", f"stream,id=n0,server=off,addr.type=unix,addr.path={s}"] + self.nic()

    def guest_setup(self, g):
        guest_wait_ipv4(g)

    def setup_forward(self, g):
        return "127.0.0.1", FWD_HOST_PORT


class PasstVU(Passt):
    name = "passt-vu"
    mtu_note = "65520 (passt default, vhost-user)"
    vhost_user = True


NETD_GUEST_SETUP = """
set -e
modprobe vmw_vsock_virtio_transport 2>/dev/null || true
if ip link add nd0 type dummy 2>/dev/null; then
  ip link set nd0 up; ip addr add 192.168.5.15/24 dev nd0; ip route add default dev nd0
else
  ip addr add 192.168.5.15/32 dev lo; ip route add default dev lo src 192.168.5.15
fi
iptables -t nat -A OUTPUT -p tcp ! -d 127.0.0.0/8 -j REDIRECT --to-ports 15001
nohup /usr/local/bin/netd-agent >/var/log/netd-agent.log 2>&1 &
sleep 0.5
"""


class Netd(Contender):
    """netd is the vhost-user-vsock device; the guest runs netd-agent."""
    name = "netd"
    host_ip = "192.168.5.2"
    mtu_note = "n/a (socket offload, vhost-user-vsock, unprivileged)"

    def start_backend(self):
        (W / "netd-vu.sock").unlink(missing_ok=True)
        self.spawn([BIN / "netd", "--vhost-user", f"{W}/netd-vu.sock", "--guest-cid", "3",
                    "--forward", f"127.0.0.1:{FWD_HOST_PORT}={GUEST_IPERF_PORT}"], "netd",
                   env={"NETD_STATS": "1"})
        wait_path(W / "netd-vu.sock")

    def qemu_net(self):
        return ["-chardev", f"socket,id=c1,path={W}/netd-vu.sock", "-device", "vhost-user-vsock-pci,chardev=c1"]

    def guest_setup(self, g):
        g.run(NETD_GUEST_SETUP)

    def setup_forward(self, g):
        return "127.0.0.1", FWD_HOST_PORT


CLASSES = {c.name: c for c in [TapVhost, Slirp, Gvproxy, Passt, PasstVU, Netd]}


def iperf_gbps(js):
    d = json.loads(js)
    if "error" in d:
        raise RuntimeError("iperf3: " + d["error"])
    return round(d["end"]["sum_received"]["bits_per_second"] / 1e9, 2)


def iperf_args(target, port, extra, secs):
    return ["iperf3", "-c", target, "-p", str(port), "-t", str(secs), "-O", "1", "-J"] + extra


THROUGHPUT = {"up1": [], "down1": ["-R"], "up4": ["-P", "4"], "down4": ["-R", "-P", "4"]}


def measure(fn, pids):
    before = {p: cpu_seconds(p) for p in pids}
    t = time.time()
    v = fn()
    el = time.time() - t
    cpu = {p: round((cpu_seconds(p) - before[p]) / el, 2) for p in pids}
    return v, cpu


STAT_FIELDS = ["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"]


def guest_cpu_sample(g):
    """Aggregate guest CPU jiffies from /proc/stat."""
    _, out, _ = g.run("head -1 /proc/stat", timeout=10, check=False)
    return [int(x) for x in out.split()[1:1 + len(STAT_FIELDS)]]


def guest_cpu_delta(a, b):
    """Busy cores per category between two samples (e.g. {'system': 0.8, ...})."""
    d = [y - x for x, y in zip(a, b)]
    total = sum(d) or 1
    ncpu = ARGS_VCPUS
    res = {k: round(v / total * ncpu, 2) for k, v in zip(STAT_FIELDS, d) if k != "idle" and v}
    res["busy"] = round(sum(v for k, v in zip(STAT_FIELDS, d) if k not in ("idle", "iowait")) / total * ncpu, 2)
    return res


def run_native(args):
    res = {}
    for t, extra in THROUGHPUT.items():
        out = subprocess.run(iperf_args("127.0.0.1", 5201, extra, args.secs), capture_output=True, text=True).stdout
        res[t] = iperf_gbps(out)
        time.sleep(0.5)
    res["rr"] = json.loads(subprocess.check_output([BIN / "nbench", "rr", f"127.0.0.1:{NBENCH_PORT}", "20000"]))
    res["crr"] = json.loads(subprocess.check_output([BIN / "nbench", "crr", f"127.0.0.1:{NBENCH_PORT}", "5"]))
    return res


def run_contender(name, args):
    procs = []
    c = CLASSES[name](procs)
    overlay = W / f"{name}.qcow2"
    overlay.unlink(missing_ok=True)
    sh(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", "base.qcow2", overlay])
    qga_path = W / f"{name}-qga.sock"
    qga_path.unlink(missing_ok=True)
    res = {"mtu": c.mtu_note}
    try:
        c.start_backend()
        qemu = [
            "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", str(args.vcpus),
            "-m", "2048", "-nodefaults", "-display", "none",
            "-object", "memory-backend-memfd,id=mem,size=2048M,share=on", "-numa", "node,memdev=mem",
            "-drive", f"file={overlay},if=virtio,cache=unsafe",
            "-chardev", f"socket,id=qga0,path={qga_path},server=on,wait=off",
            "-device", "virtio-serial-pci", "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
            "-serial", f"file:{W}/{name}-console.log",
        ] + c.qemu_net()
        qp = c.spawn(qemu, f"{name}-qemu")
        wait_path(qga_path)
        g = QGA(qga_path)
        g.wait(proc=qp, console=W / f"{name}-console.log")
        log(f"[{name}] guest up")
        c.guest_setup(g)
        pids = {"qemu": qp.pid}
        for i, p in enumerate(c.helpers()):
            pids[f"{Path(p.args[0]).name}"] = p.pid

        for t, extra in THROUGHPUT.items():
            def go():
                _, out, err = g.run(["timeout", "-k", "5", str(args.secs + 20)] + iperf_args(c.host_ip, 5201, extra, args.secs),
                                   timeout=args.secs + 40, check=False)
                return iperf_gbps(out or err)
            try:
                s0 = guest_cpu_sample(g)
                v, cpu = measure(go, list(pids.values()))
                res[t] = v
                res[t + "_cpu"] = {k: cpu[p] for k, p in pids.items()}
                res[t + "_guest_cpu"] = guest_cpu_delta(s0, guest_cpu_sample(g))
            except Exception as e:  # keep going; record the failure
                res[t] = None
                res[t + "_error"] = str(e)[:300]
            log(f"[{name}] {t}: {res[t]}")
            time.sleep(0.5)

        for t, argv in {"rr": ["rr", f"{c.host_ip}:{NBENCH_PORT}", "20000"],
                        "crr": ["crr", f"{c.host_ip}:{NBENCH_PORT}", "5"]}.items():
            rc, out, err = g.run(["timeout", "-k", "5", "60", "/usr/local/bin/nbench"] + argv, timeout=80, check=False)
            try:
                res[t] = json.loads(out)
            except ValueError:
                res[t] = None
                res[t + "_error"] = (out + err)[:300]
            log(f"[{name}] {t}: {res[t]}")

        try:
            g.run(f"iperf3 -s -D -p {GUEST_IPERF_PORT}")
            time.sleep(0.5)
            host, port = c.setup_forward(g)
            time.sleep(0.5)
            out = subprocess.run(iperf_args(host, port, ["--connect-timeout", "5000"], args.secs),
                                 capture_output=True, text=True, timeout=args.secs + 30).stdout
            res["fwd1"] = iperf_gbps(out)
        except Exception as e:
            res["fwd1"] = None
            res["fwd1_error"] = str(e)[:300]
        log(f"[{name}] fwd1: {res['fwd1']}")
        try:
            _, out, _ = g.run("cat /var/log/netd-agent.log 2>/dev/null; echo ---; dmesg | tail -50", timeout=20, check=False)
            (W / f"{name}-guest.log").write_text(out)
        except Exception:
            pass
        try:
            g.cmd("guest-shutdown", timeout=5)
        except Exception:
            pass
    except Exception as e:
        res["error"] = str(e)[:500]
        log(f"[{name}] FAILED: {e}")
    finally:
        for p in reversed(procs):
            p.terminate()
        for p in procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        if hasattr(c, "cleanup"):
            c.cleanup()
        overlay.unlink(missing_ok=True)
    return res


def fmt(v, native, unit=""):
    if v is None:
        return "fail"
    if native:
        return f"{v}{unit} ({v / native * 100:.0f}%)"
    return f"{v}{unit}"


def report(results):
    nat = results.get("native", {})
    lines = [
        "| contender | up1 Gbps | down1 Gbps | up4 Gbps | down4 Gbps | fwd1 Gbps | rr p50 µs | crr conn/s | host helper CPU (up1) | guest busy cores up1 / down1 | link MTU |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, r in results.items():
        cells = [name]
        for t in ("up1", "down1", "up4", "down4"):
            cells.append(fmt(r.get(t), nat.get(t)))
        cells.append(fmt(r.get("fwd1"), nat.get("up1")))
        rr, crr = r.get("rr") or {}, r.get("crr") or {}
        cells.append(str(rr.get("p50_us", "fail" if name != "native" or not rr else "")))
        cells.append(str(crr.get("conn_per_sec", "fail")))
        cpu = r.get("up1_cpu") or {}
        helpers = {k: v for k, v in cpu.items() if k != "qemu"}
        cells.append(", ".join(f"{k} {v}" for k, v in helpers.items()) + (f"; qemu {cpu['qemu']}" if "qemu" in cpu else ""))
        cells.append(" / ".join(str((r.get(t + "_guest_cpu") or {}).get("busy", "")) for t in ("up1", "down1")).strip(" /"))
        cells.append(r.get("mtu", "host loopback"))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("contenders", nargs="*", default=NETD,
                    help="default: netd only; other contenders come from the frozen baseline ('all' = rerun everything)")
    ap.add_argument("--baseline", default=str(BASELINE), help="frozen results merged into the report ('' = none)")
    ap.add_argument("--secs", type=int, default=10)
    ap.add_argument("--vcpus", type=int, default=2)
    ap.add_argument("--out", default=str(W / "results.json"))
    args = ap.parse_args()
    global ARGS_VCPUS
    ARGS_VCPUS = args.vcpus
    if args.contenders == ["all"]:
        args.contenders = ALL

    if not (W / "base.qcow2").exists():
        sys.exit("run bench/provision.sh first")
    server = subprocess.Popen(["iperf3", "-s", "-p", "5201"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    nb = subprocess.Popen([BIN / "nbench", "server", f"0.0.0.0:{NBENCH_PORT}"])
    time.sleep(0.5)
    results = {}
    try:
        for name in args.contenders:
            log(f"=== {name}")
            results[name] = run_native(args) if name == "native" else run_contender(name, args)
            Path(args.out).write_text(json.dumps(results, indent=2))
    finally:
        server.terminate()
        nb.terminate()
    merged = {}
    if args.baseline and Path(args.baseline).exists():
        merged = {k: dict(v, mtu=v.get("mtu", "host loopback") + " [baseline]") if k != "native" else v
                  for k, v in json.loads(Path(args.baseline).read_text()).items() if k not in results}
    merged.update(results)
    md = report(merged)
    print(md)
    (W / "results.md").write_text(md + "\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write("## netd benchmark\n\n" + md + "\n")


if __name__ == "__main__":
    main()
