#!/usr/bin/env bash
# Build bench/work/base.qcow2: Ubuntu 24.04 cloud image with iperf3,
# qemu-guest-agent, iptables, netd-agent and nbench preinstalled. The guest is
# provisioned once over QEMU user networking and powers itself off.
set -euo pipefail

cd "$(dirname "$0")/.."
W=bench/work
mkdir -p "$W"
IMG_URL=${IMG_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}

[ -f "$W/cloud.img" ] || curl -fsSL -o "$W/cloud.img" "$IMG_URL"
cp target/release/netd-agent target/release/nbench "$W/"

rm -f "$W/base.qcow2"
qemu-img create -q -f qcow2 -F qcow2 -b cloud.img "$W/base.qcow2" 10G

cat >"$W/user-data" <<'EOF'
#cloud-config
package_update: true
packages: [iperf3, qemu-guest-agent, iptables]
write_files:
  - path: /etc/netplan/60-bench.yaml
    permissions: '0600'
    content: |
      network:
        version: 2
        ethernets:
          all:
            match: {name: "en*"}
            dhcp4: true
            dhcp6: false
bootcmd:
  - echo BOOTCMD_REACHED > /dev/ttyS0
runcmd:
  - echo RUNCMD_START > /dev/ttyS0
  - curl -fsS -o /usr/local/bin/netd-agent http://10.0.2.2:8765/netd-agent
  - curl -fsS -o /usr/local/bin/nbench http://10.0.2.2:8765/nbench
  - chmod +x /usr/local/bin/netd-agent /usr/local/bin/nbench
  - systemctl mask systemd-networkd-wait-online.service
  - systemctl disable unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer snapd.service snapd.socket || true
  - rm -f /etc/netplan/50-cloud-init.yaml
  - touch /etc/cloud/cloud-init.disabled
  - sh -c 'modprobe dummy && echo MOD_DUMMY_OK; modinfo vmw_vsock_virtio_transport >/dev/null && echo MOD_VSOCK_OK' > /dev/ttyS0 2>&1
  - echo PROVISION_DONE > /dev/ttyS0
power_state:
  mode: poweroff
  condition: true
EOF
printf 'instance-id: netd-bench\nlocal-hostname: bench\n' >"$W/meta-data"
cloud-localds "$W/seed.img" "$W/user-data" "$W/meta-data"

python3 -m http.server 8765 --bind 127.0.0.1 --directory "$W" >/dev/null 2>&1 &
HTTP_PID=$!

ACCEL=kvm
[ -w /dev/kvm ] || ACCEL=tcg
echo "provisioning with accel=$ACCEL"
: >"$W/provision.log"
tail -f "$W/provision.log" &
TAIL_PID=$!
trap 'kill $HTTP_PID $TAIL_PID 2>/dev/null || true' EXIT

rc=0
timeout "${PROVISION_TIMEOUT:-600}" qemu-system-x86_64 \
  -machine q35,accel=$ACCEL -cpu max -smp 2 -m 2048 -nodefaults -display none \
  -drive file="$W/base.qcow2",if=virtio \
  -drive file="$W/seed.img",if=virtio,format=raw \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -serial file:"$W/provision.log" || rc=$?
sleep 1

if [ $rc -ne 0 ] || ! grep -q PROVISION_DONE "$W/provision.log"; then
  echo "provisioning failed (qemu exit $rc)"
  exit 1
fi
echo "base image ready: $W/base.qcow2"
