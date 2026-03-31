#!/usr/bin/env bash
set -euo pipefail

ip addr add "${MONITOR_IP}/32" dev lo || true

exec sleep infinity
