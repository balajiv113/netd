#!/bin/bash
# Local pre-CI check: boots the Ubuntu 6.8 guest kernel under QEMU (TCG works, no KVM needed)
# with netd-agent in an initramfs, and runs up/down iperf3 + rr through
# vhost-device-vsock + netd.
#   bench/vmtest/vmtest.sh [VHOST_DEVICE_VSOCK_BIN] [agent-args,comma,separated]
# Needs: qemu-system-x86_64, iperf3, cpio, zstd, curl, dpkg-deb.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VDV=${1:-vhost-device-vsock}; EXTRA=${2:-}
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
for b in sh mount insmod ip poweroff sleep cat echo kill cut grep tr; do ln -s busybox $R/bin/$b; done
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
netd-agent --fixed-dst 192.168.5.2:5201 --listen 127.0.0.1:15001 --inbound-vsock 0 $EXTRA 2>/tmp/agent.log & A=$!
sleep 1
echo "VMTEST: up";   iperf3 -c 127.0.0.1 -p 15001 -t 5 -O 1 --connect-timeout 5000 2>&1 | grep -E "receiver|error"
echo "VMTEST: down"; iperf3 -c 127.0.0.1 -p 15001 -t 5 -O 1 -R --connect-timeout 5000 2>&1 | grep -E "receiver|error"
kill $A
netd-agent --fixed-dst 192.168.5.2:7000 --listen 127.0.0.1:15002 --inbound-vsock 0 $EXTRA 2>>/tmp/agent.log &
sleep 1
echo "VMTEST: rr $(nbench rr 127.0.0.1:15002 2000 2>&1)"
echo "VMTEST: agent log"; cat /tmp/agent.log
echo "VMTEST: DONE"; poweroff -f
EOF
chmod +x $R/init
(cd $R && find . | cpio -o -H newc 2>/dev/null | gzip -1 > $W/initrd.gz)

PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; }
trap cleanup EXIT
iperf3 -s -p 5201 >$W/iperf.log 2>&1 & PIDS+=($!)
$N/nbench server 127.0.0.1:7000 >$W/nb.log 2>&1 & PIDS+=($!)
RUST_LOG=${VDV_LOG:-warn} "$VDV" --vm guest-cid=3,socket=$W/vu.sock,uds-path=$W/vm.vsock,tx-buffer-size=1048576,queue-size=1024 >$W/vdv.log 2>&1 & PIDS+=($!)
$N/netd --listen-uds $W/vm.vsock_1024 --guest-uds $W/vm.vsock >$W/netd.log 2>&1 & PIDS+=($!)
for _ in $(seq 50); do [ -S $W/vu.sock ] && break; sleep 0.1; done
ACCEL=tcg; [ -w /dev/kvm ] && ACCEL=kvm
timeout 300 qemu-system-x86_64 -machine q35 -accel $ACCEL -smp 2 -m 1024 -nodefaults -display none \
  -object memory-backend-memfd,id=mem,size=1024M,share=on -numa node,memdev=mem \
  -chardev socket,id=c1,path=$W/vu.sock -device vhost-user-vsock-pci,chardev=c1 \
  -kernel "$C/x/boot/vmlinuz-$KVER-generic" -initrd $W/initrd.gz \
  -append "console=ttyS0 rdinit=/init quiet agent=$EXTRA" -serial stdio -no-reboot 2>&1 |
  sed -n '/VMTEST: up/,/VMTEST: DONE/p' | grep -Ev '^\[ *[0-9]+\.[0-9]+\]' | tee $W/out.txt
echo "logs: $W"
# Fail if either direction moved no data.
[ "$(grep -A1 -E 'VMTEST: (up|down)' $W/out.txt | grep -c ' [1-9][0-9.]* [MG]bits/sec')" -eq 2 ] && echo "VMTEST: PASS" || { echo "VMTEST: FAIL"; exit 1; }
