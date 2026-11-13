#!/bin/bash
# Local pre-CI check: boots the Ubuntu 6.8 guest kernel under QEMU (TCG works, no KVM needed)
# with netd-agent in an initramfs, and runs up/down/fwd iperf3 + rr/crr through netd
# (netd is the vhost-user-vsock device).
#   bench/vmtest/vmtest.sh [agent-args,comma,separated]
# Needs: qemu-system-x86_64, iperf3, cpio, zstd, curl, dpkg-deb, python3.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
EXTRA=${1:-}
KVER=${KVER:-6.8.0-147}
C=${VMTEST_CACHE:-$HOME/.cache/netd-vmtest}; W=$(mktemp -d)
mkdir -p "$C"
fetch() { # pkg-name -> extract into $C/x
  local f; f=$(curl -fsS "http://archive.ubuntu.com/ubuntu/pool/$1/" | grep -o "\"$2_[^\"]*_amd64.deb\"" | tr -d '"' | sort -V | tail -1)
  [ -f "$C/$f" ] || curl -fsSo "$C/$f" "http://archive.ubuntu.com/ubuntu/pool/$1/$f"
  dpkg-deb -x "$C/$f" "$C/x"
}
if [ ! -f "$C/x/boot/vmlinuz-$KVER-generic" ]; then
  fetch main/l/linux "linux-image-unsigned-$KVER-generic"
  fetch main/l/linux "linux-modules-$KVER-generic"
  fetch main/b/busybox busybox-static
fi
cargo build --release -q --manifest-path "$ROOT/Cargo.toml"
N=$ROOT/target/release
R=$W/rootfs; mkdir -p $R/{bin,proc,sys,dev,tmp,mod}
cp "$C/x/usr/bin/busybox" $R/bin/
for b in sh mount insmod ip poweroff sleep cat echo kill cut grep tr timeout nc; do ln -s busybox $R/bin/$b; done
cp $N/netd-agent $N/nbench "$(command -v iperf3)" $R/bin/
for f in $N/netd-agent $N/nbench "$(command -v iperf3)"; do ldd "$f" | grep -o '/[^ ]*'; done | sort -u |
  while read -r l; do mkdir -p "$R$(dirname "$l")"; cp -L "$l" "$R$l"; done
M=$C/x/lib/modules/$KVER-generic/kernel/net/vmw_vsock
for m in vsock vmw_vsock_virtio_transport_common vmw_vsock_virtio_transport; do zstd -qd "$M/$m.ko.zst" -o $R/mod/$m.ko; done
cat > $R/init <<'EOF'
#!/bin/sh
mount -t proc p /proc; mount -t sysfs s /sys; mount -t devtmpfs d /dev
for m in vsock vmw_vsock_virtio_transport_common vmw_vsock_virtio_transport; do insmod /mod/$m.ko; done
ip link set lo up
EXTRA=$(grep -o 'agent=[^ ]*' /proc/cmdline | cut -d= -f2- | tr , ' ')
netd-agent --listen 127.0.0.1:15001 --fixed-dst 192.168.5.2:5201 \
  --listen 127.0.0.1:15002 --fixed-dst 192.168.5.2:7000 \
  --listen 127.0.0.1:15003 --fixed-dst 192.168.5.2:1 \
  --listen 127.0.0.1:15004 --fixed-dst 192.168.5.2:7002 $EXTRA 2>/tmp/agent.log &
sleep 1
echo "VMTEST: server-first $(nc -w 5 127.0.0.1 15004 </dev/null)"
# Many more refused connections than ring slots: none may leak a slot, or
# the tests below would not use the shared rings.
echo "VMTEST: refused $(nbench crr 127.0.0.1:15003 1 2>&1)"
echo "VMTEST: up";   iperf3 -c 127.0.0.1 -p 15001 -t 5 -O 1 --connect-timeout 5000 2>&1 | grep -E "receiver|error"
echo "VMTEST: down"; iperf3 -c 127.0.0.1 -p 15001 -t 5 -O 1 -R --connect-timeout 5000 2>&1 | grep -E "receiver|error"
echo "VMTEST: rr $(nbench rr 127.0.0.1:15002 2000 2>&1)"
echo "VMTEST: crr $(nbench crr 127.0.0.1:15002 3 2>&1)"
iperf3 -s -1 -p 5301 >/dev/null 2>&1 & S=$!
sleep 1
echo "VMTEST: fwd-ready"
timeout 60 sh -c "while kill -0 $S 2>/dev/null; do sleep 1; done"
echo "VMTEST: agent log"; sort /tmp/agent.log | uniq -c
echo "VMTEST: DONE"; poweroff -f
EOF
chmod +x $R/init
(cd $R && find . | cpio -o -H newc 2>/dev/null | gzip -1 > $W/initrd.gz)

PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; }
trap cleanup EXIT
iperf3 -s -p 5201 >$W/iperf.log 2>&1 & PIDS+=($!)
$N/nbench server 127.0.0.1:7000 >$W/nb.log 2>&1 & PIDS+=($!)
python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",7002)); s.listen(); s.settimeout(120); c,_=s.accept(); c.sendall(b"hello"); c.close(); s.close()' >$W/server-first.log 2>&1 & PIDS+=($!)
NETD_STATS=1 $N/netd --vhost-user $W/vu.sock --guest-cid 3 --forward 127.0.0.1:15301=5301 >$W/netd.log 2>&1 & PIDS+=($!)
for _ in $(seq 50); do [ -S $W/vu.sock ] && break; sleep 0.1; done
ACCEL=tcg; [ -w /dev/kvm ] && ACCEL=kvm
timeout 300 qemu-system-x86_64 -machine q35 -accel $ACCEL -smp 2 -m 1024 -nodefaults -display none \
  -object memory-backend-memfd,id=mem,size=1024M,share=on -numa node,memdev=mem \
  -chardev socket,id=c1,path=$W/vu.sock -device vhost-user-vsock-pci,chardev=c1 \
  -kernel "$C/x/boot/vmlinuz-$KVER-generic" -initrd $W/initrd.gz \
  -append "console=ttyS0 rdinit=/init quiet agent=$EXTRA" -serial file:$W/console.log -no-reboot & Q=$!
for _ in $(seq 600); do grep -q 'VMTEST: fwd-ready' $W/console.log 2>/dev/null && break; kill -0 $Q 2>/dev/null || break; sleep 0.5; done
if grep -q 'VMTEST: fwd-ready' $W/console.log; then
  NETD_PID=$(pgrep -f "^$N/netd " | head -1)
  [ -n "$NETD_PID" ] && echo "netd open fds after crr: $(ls /proc/$NETD_PID/fd | wc -l)" > $W/fds.txt
  timeout 30 iperf3 -c 127.0.0.1 -p 15301 -t 5 -O 1 --connect-timeout 5000 2>&1 | grep -E "receiver|error" > $W/fwd.txt || true
fi
wait $Q || true
{ sed -n '/VMTEST: server-first/,/VMTEST: DONE/p' $W/console.log | grep -Ev '^\[ *[0-9]+\.[0-9]+\]' | grep -v fwd-ready
  echo "VMTEST: fwd (host -> guest)"; cat $W/fwd.txt 2>/dev/null; cat $W/fds.txt 2>/dev/null
  grep -v '^netd: stats' $W/netd.log; { grep -E 'shm_(tx|rx)_bytes: [1-9]' $W/netd.log || true; } | tail -2; } | tee $W/out.txt
echo "logs: $W"
# Fail if any direction moved no data, or the shared rings were not used
# (unless the agent was told not to use them).
SHM_OK=1
case "$EXTRA" in *shm-slots,0*) ;; *) grep -q 'shared rings registered' $W/out.txt && grep -qE 'shm_(tx|rx)_bytes: [1-9]' $W/out.txt || SHM_OK=0 ;; esac
grep -q 'VMTEST: refused {"conns":0,"errors":[1-9][0-9]' $W/out.txt || SHM_OK=0
grep -q 'VMTEST: server-first hello' $W/out.txt || SHM_OK=0
[ $SHM_OK = 1 ] && grep -q "\"errors\":0" $W/out.txt && [ "$(grep -A1 -E 'VMTEST: (up|down|fwd)' $W/out.txt | grep -c ' [1-9][0-9.]* [MG]bits/sec')" -eq 3 ] && echo "VMTEST: PASS" || { echo "VMTEST: FAIL"; exit 1; }
