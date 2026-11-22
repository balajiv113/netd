#!/bin/bash
# Two Linux guests on the experimental Ethernet switch. Run vmtest.sh first
# to populate its kernel and busybox cache.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
C=${VMTEST_CACHE:-$HOME/.cache/netd-vmtest}
KVER=${KVER:-6.8.0-147}
KERNEL=$C/x/boot/vmlinuz-$KVER-generic
BUSYBOX=$C/x/usr/bin/busybox
W=$(mktemp -d)
[ -r "$KERNEL" ] && [ -x "$BUSYBOX" ] || { echo "run bench/vmtest/vmtest.sh first to populate the cache" >&2; exit 1; }
cargo build --release -q --manifest-path "$ROOT/Cargo.toml"
R=$W/rootfs
mkdir -p "$R"/{bin,proc,sys,dev,tmp}
cp "$BUSYBOX" "$R/bin/busybox"
for b in sh mount ip poweroff sleep grep ping; do ln -s busybox "$R/bin/$b"; done
cp "$(command -v iperf3)" "$R/bin/iperf3"
ldd "$(command -v iperf3)" | grep -o '/[^ ]*' | sort -u |
  while read -r lib; do mkdir -p "$R$(dirname "$lib")"; cp -L "$lib" "$R$lib"; done
LIBGCC=$(readlink -f "$(gcc -print-file-name=libgcc_s.so.1)")
mkdir -p "$R$(dirname "$LIBGCC")"
cp -L "$LIBGCC" "$R$LIBGCC"
cat > "$R/init" <<'EOF'
#!/bin/sh
mount -t proc p /proc; mount -t sysfs s /sys; mount -t devtmpfs d /dev
ip link set lo up
ip link set eth0 up
if grep -q 'role=server' /proc/cmdline; then
  ip addr add 10.77.0.2/24 dev eth0
  iperf3 -s >/tmp/iperf.log 2>&1 &
  echo "SWITCH_VMTEST: server-ready"
  while :; do sleep 60; done
fi
ip addr add 10.77.0.1/24 dev eth0
i=0
while ! ping -c 1 -W 2 10.77.0.2 >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 20 ]; then echo "SWITCH_VMTEST: FAIL ping"; poweroff -f; fi
  sleep 1
done
echo "SWITCH_VMTEST: ping ok"
if ! iperf3 -c 10.77.0.2 -t 3; then echo "SWITCH_VMTEST: FAIL upload"; poweroff -f; fi
if ! iperf3 -c 10.77.0.2 -t 3 -R; then echo "SWITCH_VMTEST: FAIL download"; poweroff -f; fi
if ! iperf3 -c 10.77.0.2 -t 3 -P 4; then echo "SWITCH_VMTEST: FAIL upload4"; poweroff -f; fi
if ! iperf3 -c 10.77.0.2 -t 3 -R -P 4; then echo "SWITCH_VMTEST: FAIL download4"; poweroff -f; fi
echo "SWITCH_VMTEST: PASS"
poweroff -f
EOF
chmod +x "$R/init"
(cd "$R" && find . | cpio -o -H newc 2>/dev/null | gzip -1 > "$W/initrd.gz")
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
"$ROOT/target/release/netd" switch --listen 127.0.0.1:0 >"$W/switch.log" 2>&1 & PIDS+=($!)
for _ in $(seq 100); do
  grep -q 'switch listening on' "$W/switch.log" && break
  kill -0 "${PIDS[0]}" 2>/dev/null || { cat "$W/switch.log"; exit 1; }
  sleep 0.1
done
PORT=$(sed -n 's/.*switch listening on 127.0.0.1://p' "$W/switch.log")
[ -n "$PORT" ] || { echo "switch did not become ready" >&2; exit 1; }
ACCEL=tcg; [ -w /dev/kvm ] && ACCEL=kvm
QEMU=(qemu-system-x86_64 -machine q35 -accel "$ACCEL" -smp 2 -m 384 -nodefaults -display none
  -netdev "socket,id=net,connect=127.0.0.1:$PORT" -kernel "$KERNEL" -initrd "$W/initrd.gz" -no-reboot)
timeout 180 "${QEMU[@]}" -device virtio-net-pci,netdev=net,mac=52:54:00:77:00:02 \
  -append "console=ttyS0 rdinit=/init quiet role=server" -serial "file:$W/server.log" & PIDS+=($!)
for _ in $(seq 600); do
  grep -q 'SWITCH_VMTEST: server-ready' "$W/server.log" 2>/dev/null && break
  kill -0 "${PIDS[1]}" 2>/dev/null || break
  sleep 0.2
done
if ! grep -q 'SWITCH_VMTEST: server-ready' "$W/server.log" 2>/dev/null; then
  echo "SWITCH_VMTEST: FAIL server boot; logs: $W" >&2
  exit 1
fi
timeout 180 "${QEMU[@]}" -device virtio-net-pci,netdev=net,mac=52:54:00:77:00:01 \
  -append "console=ttyS0 rdinit=/init quiet role=client" -serial "file:$W/client.log" || true
grep -E 'SWITCH_VMTEST:|receiver' "$W/client.log" || true
echo "logs: $W"
grep -q 'SWITCH_VMTEST: PASS' "$W/client.log" && ! grep -q 'SWITCH_VMTEST: FAIL' "$W/client.log" &&
  awk '/receiver/ && $(NF-1) ~ /^[KMG]bits\/sec$/ && $(NF-2)+0 > 0 { n++ } END { exit n < 4 }' "$W/client.log" &&
  [ "$(grep -c '\[SUM\].*receiver' "$W/client.log")" -eq 2 ]
