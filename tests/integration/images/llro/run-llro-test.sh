#!/usr/bin/env bash
set -euo pipefail

WAN_A_DEV="$(ip -o -4 addr show | awk -v ip="${WAN_A_SOURCE_IP}" '$4 ~ ("^" ip "/") {print $2; exit}')"
WAN_B_DEV="$(ip -o -4 addr show | awk -v ip="${WAN_B_SOURCE_IP}" '$4 ~ ("^" ip "/") {print $2; exit}')"
if [[ -z "${WAN_A_DEV}" || -z "${WAN_B_DEV}" ]]; then
  echo "Failed to resolve interface names for source IPs" >&2
  ip -o -4 addr show >&2
  exit 1
fi

cat >/tmp/llro.yml <<EOF
monitor:
  - ${MONITOR_IP}
routes:
  - name: wan_a
    device: ${WAN_A_DEV}
    probe_source: ${WAN_A_SOURCE_IP}
    gateway: ${WAN_A_GATEWAY_IP}
  - name: wan_b
    device: ${WAN_B_DEV}
    probe_source: ${WAN_B_SOURCE_IP}
    gateway: ${WAN_B_GATEWAY_IP}
fallback_routes:
  ${MONITOR_IP}: wan_a
packet_loss_threshold: 0
rtt_threshold: 1
test_count: 1
test_interval: 0.2
scan_interval: 1
delete_preadded_routes: true
ip_bin: /usr/sbin/ip
EOF

# Ensure source-based probes can reach the target from both uplinks.
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null || true
sysctl -w "net.ipv4.conf.${WAN_A_DEV}.rp_filter=0" >/dev/null || true
sysctl -w "net.ipv4.conf.${WAN_B_DEV}.rp_filter=0" >/dev/null || true
ip route add default via "${WAN_A_GATEWAY_IP}" dev "${WAN_A_DEV}" || true
ip rule add pref 100 from "${WAN_A_SOURCE_IP}" lookup 101 || true
ip route add default via "${WAN_A_GATEWAY_IP}" dev "${WAN_A_DEV}" table 101 || true
ip rule add pref 101 from "${WAN_B_SOURCE_IP}" lookup 102 || true
ip route add default via "${WAN_B_GATEWAY_IP}" dev "${WAN_B_DEV}" table 102 || true

exec llro --config /tmp/llro.yml
