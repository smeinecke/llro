# HOW LLRO Works

LLRO continuously chooses the best uplink for each monitored destination host and installs a `/32` route for that host.
It probes paths, compares health, and updates Linux routes automatically.

## High-Level Flow

```mermaid
flowchart LR
    A[Config: monitor hosts + route candidates] --> B[Probe Engine]
    B --> C[Per-route metrics per host<br/>RTT + loss + alive]
    C --> D[Decision Engine]
    D -->|best route| E[ip route add/replace host/32]
    D -->|manual controls| F[Override/Frozen/Auto mode]
    G[llro-cli via Unix socket] --> F
    F --> D
```

## Packet Flow

```mermaid
sequenceDiagram
    participant LLRO as LLRO Daemon
    participant WAN_A as Route A probe_source
    participant WAN_B as Route B probe_source
    participant TARGET as Monitored Host
    participant KERNEL as Linux Routing Table

    LLRO->>WAN_A: ICMP probe (source=probe_source_A)
    WAN_A->>TARGET: echo request
    TARGET-->>WAN_A: echo reply
    WAN_A-->>LLRO: RTT/loss sample

    LLRO->>WAN_B: ICMP probe (source=probe_source_B)
    WAN_B->>TARGET: echo request
    TARGET-->>WAN_B: echo reply
    WAN_B-->>LLRO: RTT/loss sample

    LLRO->>LLRO: Compare path quality (loss, RTT, mode)
    LLRO->>KERNEL: ip route add/replace TARGET/32 via best gateway
```

## Main Components

- Probe Engine: Sends ICMP probes for each monitored host from each configured route source.
- Decision Engine: Ranks candidate routes by packet loss first, then RTT, while respecting mode and thresholds.
- Route Applier: Writes host-specific Linux routes using `ip route add/replace`.
- Admin Control Plane: `llro-cli` talks to the daemon over a local Unix socket for status, override, freeze, and reset.

## What Is Sent and Applied

- Sent: ICMP probe packets from each `probe_source` to each monitored host.
- Collected: route quality metrics (`avg_rtt`, `avg_loss`, `is_alive`) per host/path.
- Applied: `/32` destination routes on the host:
`ip route add|replace <host>/32 via <gateway> dev <device> src <probe_source>`.

## Decision Outcome

- Healthy best path available: route is switched or kept on that best path.
- Path degraded: switch can occur based on loss/RTT threshold logic.
- Manual override/freeze active: automatic switching is constrained by selected mode.
- No valid path: optional fallback route is used, otherwise host route is removed.
