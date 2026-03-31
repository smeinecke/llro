# LLRO (Lowest Latency Routes Optimizer)

Service to measure ICMP latency from multiple uplinks and keep per-host `/32` routes pinned to the best path.

LLRO continuously probes each monitored destination through each configured uplink source, compares packet loss and latency, and installs host routes using Linux `ip route` so traffic for that destination follows the healthiest path. It can freeze or override routing decisions per host through a local admin socket, and it can fall back to predefined routes when probes fail. In short, it automates per-destination path selection based on live network conditions instead of static one-time routing choices.

For a deeper technical walkthrough, see [HOW_IT_WORKS.md](/home/stefan/github/LowestLatencyRoutesOptimizer/HOW_IT_WORKS.md).

## Runtime requirements

- Linux with `iproute2` (`ip` command available, default path `/usr/sbin/ip`)
- Root privileges or equivalent capabilities (`CAP_NET_ADMIN` and raw ICMP capability)
- Python `>=3.7`

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
test_count: 5
test_interval: 1
scan_interval: 30
delete_preadded_routes: true
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
- `test_count`: number of probe rounds aggregated before routing decisions.
- `test_interval`: interval between ping packets in a probe run.
- `scan_interval`: delay between scan cycles.
- `delete_preadded_routes`: remove existing static `/32` routes for monitored hosts on startup.
- `ip_bin`: optional `ip` binary path override.
- `admin_socket_path`: Unix socket path used by `llro-cli` for admin/monitoring.

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
make validate   # format check + lint + typecheck + dead-code scan
make test       # pytest
make integration-test  # dockerized route mutation integration test
make build      # build sdist/wheel + twine metadata check
```

Auto-fix formatting/lint issues:

```bash
make fix
```

Run integration tests directly:

```bash
RUN_DOCKER_INTEGRATION=1 uv run pytest -m integration
```

The compose integration scenario spins up multiple containers, blocks ICMP on one path, and verifies LLRO switches the monitored host route to the remaining healthy path.

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
{"host": "1.1.1.1", "mode": "override", "route": "wan_lte"}

$ llro-cli disable-switching --all
{"hosts": ["1.1.1.1", "8.8.8.8"], "mode": "frozen"}

$ llro-cli reset-auto --host 1.1.1.1
{"hosts": ["1.1.1.1"], "mode": "auto"}
```

## systemd service

Use the provided unit as a base and verify the executable path in your environment:

```bash
which llro
```

Install:

```bash
sudo cp llro.service /etc/systemd/system/llro.service
sudo systemctl daemon-reload
sudo systemctl enable --now llro
sudo systemctl status llro
```

## PyPI release flow

- Local dry-run build: `make build`
- Publish manually with Twine:
- `make publish-testpypi`
- `make publish-pypi`
- GitHub Actions publish:
- Push tag `v*` to trigger `.github/workflows/publish-to-pypi.yml`
- Workflow uses trusted publishing (`id-token`) for PyPI

## Contributing

Inspired by <https://malaty.net/linux-lowest-latency-routes-optimizer/>
