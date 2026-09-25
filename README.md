# LLRO (Lowest Latency Routes Optimizer)

Service to measure ICMP latency from multiple uplinks and keep per-host `/32` routes pinned to the best path.

LLRO continuously probes each monitored destination through each configured uplink source, compares packet loss and latency, and installs host routes using Linux `ip route` so traffic for that destination follows the healthiest path. It can freeze or override routing decisions per host through a local admin socket, and it can fall back to predefined routes when probes fail. In short, it automates per-destination path selection based on live network conditions instead of static one-time routing choices.

For a deeper technical walkthrough, see [HOW_IT_WORKS.md](HOW_IT_WORKS.md).

## Runtime requirements

- Linux with `iproute2` (`ip` command available, default path `/usr/sbin/ip`)
- Root privileges or equivalent capabilities (`CAP_NET_ADMIN` and raw ICMP capability)
- Python `>=3.11`

## Development setup

```bash
uv sync
```

## Run locally

```bash
uv run llro --config ./config.yml
```

## Configuration (recommended model)

Start from the example:

```bash
cp config.example.yml config.yml
```

Example:

```yaml
monitor:
  - 1.1.1.1
  - 8.8.8.8

routes:
  - name: wan_fiber
    device: eth0
    probe_source: 192.168.0.8
    gateway: 192.168.0.1
  - name: wan_lte
    device: wwan0
    probe_source: 10.0.0.2
    gateway: 10.0.0.1

also_route:
  1.1.1.1:
    - 1.0.0.1
  8.8.8.8:
    - 8.8.4.4

fallback_routes:
  1.1.1.1: wan_fiber
  8.8.8.8: wan_lte

rtt_threshold: 20
packet_loss_threshold: 2
pings_per_probe: 5
decision_cycles: 5
test_interval: 1
scan_interval: 30
delete_preadded_routes: true
# probe_timeout: 2
# bind_to_device: false
# ewma_alpha: 0.4
# switch_cooldown: 60
# ip_bin: /usr/sbin/ip
# admin_socket_path: /run/llro/admin.sock
```

### Key fields

- `monitor`: host IPs to probe and route.
- `routes`: route candidates.
- `routes[].name`: unique route identifier.
- `routes[].device`: network device used for route installation.
- `routes[].probe_source`: source IP used for probing and route `src`.
- `routes[].gateway`: next-hop gateway for the host route.
- `also_route`: optional extra IPs that should follow a monitored host route.
- `fallback_routes`: optional fallback route name per monitored host.
- `rtt_threshold`: minimum RTT improvement (ms) required before switching.
- `packet_loss_threshold`: packet-loss threshold (%) that can force switching.
- `pings_per_probe`: ICMP echo requests sent per host per route in each probe cycle.
- `decision_cycles`: number of probe cycles aggregated before a routing decision.
- `test_interval`: interval between ping packets in a probe run.
- `probe_timeout`: seconds to wait for each ICMP reply (default `2`).
- `payload_size`: ICMP Echo Request payload size in bytes.
- `scan_interval`: delay between scan cycles.
- `bind_to_device`: bind probe sockets to each route's `device` (`SO_BINDTODEVICE`) so probes egress that interface (default `false`; see "Probe path pinning").
- `ewma_alpha`: smoothing factor `(0, 1]` applied to per-route RTT/loss before decisions (default `0.4`; use `1.0` to disable smoothing).
- `switch_cooldown`: minimum seconds between RTT-improvement switches per host (default `60`; `0` disables; loss/dead failover is never delayed).
- `test_count`: deprecated; when set without the new keys it maps to both `pings_per_probe` and `decision_cycles`.
- `delete_preadded_routes`: remove existing static `/32` routes for monitored hosts on startup.
- `ip_bin`: optional `ip` binary path override.
- `admin_socket_path`: Unix socket path used by `llro-cli` for admin/monitoring.

## Probe path pinning

Probes are sent with each route's `probe_source` as their source address. Source binding alone does **not** fix the egress interface: once a `<host>/32` route is installed, all probes for that host follow it in the forward direction, so per-uplink metrics reflect hybrid paths (forward via the current route, return via the probe's uplink) — and packets leaving one uplink with another uplink's source IP may be dropped by upstream anti-spoofing (uRPF), showing up as phantom loss.

Two ways to make probes actually traverse the intended uplink:

- `bind_to_device: true` — LLRO sets `SO_BINDTODEVICE` on each probe socket, pinning egress to the route's `device`. The bound interface still needs a usable route to the destination (e.g. its own default route in the main table); otherwise probes fail with `ENETUNREACH`. Requires `CAP_NET_RAW` (already required by LLRO).
- Alternatively, keep `bind_to_device` off and configure per-source policy routing yourself, e.g. `ip rule from <probe_source> table <uplink-table>` plus a default route in that table. The probe's source binding then selects the right table.

## Legacy config compatibility

The old `interfaces` model is still accepted for now:

```yaml
interfaces:
  eth0:
    - 192.168.0.8
```

Compatibility mode maps each `interfaces.<device>.<source>` entry to a generated route candidate:

- `name: "<device>:<source>"`
- `probe_source: <source>`
- `gateway: <source>` (legacy behavior)

`fallback_routes` may reference either route names (new) or legacy source IPs (old).

## Tooling (Make + uv)

```bash
make validate          # format check + lint + typecheck + dead-code/complexity/security scans
make test              # unit tests (pytest -m "not integration")
make test-integration  # dockerized integration tests (needs a docker daemon)
make build             # build sdist/wheel + twine metadata check
```

Auto-fix formatting/lint issues:

```bash
make fix
```

Run integration tests directly:

```bash
uv run pytest tests/test_integration_compose.py -v -m integration
```

The compose integration scenario spins up multiple containers and verifies the daemon end-to-end: admin socket controls (`status`/`override`/`disable-switching`/`reset-auto` via `llro-cli`), route switchover when ICMP is blocked on the active path, and `fallback_routes` when all paths fail.

## Install as CLI

From local checkout:

```bash
uv pip install .
```

From wheel:

```bash
uv pip install dist/*.whl
```

Then run:

```bash
llro --config /etc/llro.yml
```

Admin commands (against running daemon):

```bash
llro-cli status
llro-cli override --host 1.1.1.1 --route wan_fiber
llro-cli disable-switching --all
llro-cli reset-auto --host 1.1.1.1
```

Example output:

```text
$ llro-cli status
Host 1.1.1.1 | mode=auto | switching=yes | current=wan_fiber | override=-
  wan_fiber: rtt=14.2 ms, loss=0%, alive=yes
  wan_lte: rtt=35.8 ms, loss=0%, alive=yes
Host 8.8.8.8 | mode=frozen | switching=no | current=wan_lte | override=-
  wan_fiber: rtt=48.1 ms, loss=0%, alive=yes
  wan_lte: rtt=31.6 ms, loss=0%, alive=yes
```

```text
$ llro-cli status --json
{
  "hosts": [
    {
      "current_route": "wan_fiber",
      "host": "1.1.1.1",
      "mode": "auto",
      "override_route": null,
      "routes": {
        "wan_fiber": {
          "avg_loss": 0,
          "avg_rtt": 14.2,
          "is_alive": true
        },
        "wan_lte": {
          "avg_loss": 0,
          "avg_rtt": 35.8,
          "is_alive": true
        }
      },
      "switching_enabled": true
    }
  ]
}
```

```text
$ llro-cli override --host 1.1.1.1 --route wan_lte
{"host": "1.1.1.1", "mode": "override", "route": "wan_lte", "route_applied": true}

$ llro-cli disable-switching --all
{"hosts": ["1.1.1.1", "8.8.8.8"], "mode": "frozen"}

$ llro-cli reset-auto --host 1.1.1.1
{"hosts": ["1.1.1.1"], "mode": "auto"}
```

## systemd service

The provided unit runs LLRO under a dedicated unprivileged user with only the network capabilities it needs (`CAP_NET_ADMIN` and `CAP_NET_RAW`).

### Prerequisites

Create the service user and verify the executable path:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin llro
which llro
# Update ExecStart in llro.service if the path differs from /usr/local/bin/llro
```

The unit uses `RuntimeDirectory=llro` so `/run/llro` is created automatically with correct ownership for the admin socket.

### Install

```bash
sudo cp llro.service /etc/systemd/system/llro.service
sudo systemctl daemon-reload
sudo systemctl enable --now llro
sudo systemctl status llro
```

### Verifying capabilities

On a hardened unit, LLRO must still be able to create raw ICMP sockets and modify routes. If the service fails to probe or install routes, check the journal for capability denials:

```bash
sudo journalctl -u llro -n 50
```

## PyPI release flow

- Local dry-run build: `make build`
- Publish manually with Twine:
- `make publish-testpypi`
- `make publish-pypi`
- GitHub Actions publish:
- Push tag `v*.*.*` to trigger `.github/workflows/release.yml`
- Workflow verifies the tag matches the package version, attests build provenance, creates a GitHub release, and publishes to PyPI via trusted publishing (`id-token`)

## Contributing

Inspired by <https://malaty.net/linux-lowest-latency-routes-optimizer/>
