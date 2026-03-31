#!/usr/bin/env bash
set -euo pipefail

sysctl -w net.ipv4.ip_forward=1 >/dev/null
exec sleep infinity
