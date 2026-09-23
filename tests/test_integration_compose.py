import json
import os
import re
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NamedTuple

import pytest

COMPOSE_FILE = Path(__file__).resolve().parent / "integration" / "docker-compose.yml"
ADMIN_SOCKET_PATH = "/run/llro/admin.sock"
ROUTE_TIMEOUT_SECONDS = 45
SWITCH_TIMEOUT_SECONDS = 90

# NOTE: the tests in this module share one docker-compose testbed (module-scoped
# fixture) and intentionally run in file order — fault injection is cumulative.
pytestmark = pytest.mark.integration


class ComposeTestbed(NamedTuple):
    project: str
    env: dict[str, str]


def _run(cmd, env=None):  # type: ignore[no-untyped-def]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def _compose(testbed: ComposeTestbed, *args: str):
    return _run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "-p", testbed.project, *args],
        env=testbed.env,
    )


def _exec(testbed: ComposeTestbed, service: str, *cmd: str):
    return _compose(testbed, "exec", "-T", service, *cmd)


def _docker_compose_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return _run(["docker", "compose", "version"]).returncode == 0


def _build_network_env(project_name: str) -> dict[str, str]:
    seed = int(project_name[-2:], 16)
    wan_a_octet = 100 + (seed % 50)
    wan_b_octet = 150 + (seed % 50)
    monitor_octet = 10 + (seed % 200)

    return {
        "WAN_A_SUBNET": f"172.30.{wan_a_octet}.0/24",
        "WAN_B_SUBNET": f"172.31.{wan_b_octet}.0/24",
        "WAN_A_SOURCE_IP": f"172.30.{wan_a_octet}.10",
        "WAN_B_SOURCE_IP": f"172.31.{wan_b_octet}.10",
        "WAN_A_TARGET_IP": f"172.30.{wan_a_octet}.20",
        "WAN_B_TARGET_IP": f"172.31.{wan_b_octet}.20",
        "WAN_A_GATEWAY_IP": f"172.30.{wan_a_octet}.20",
        "WAN_B_GATEWAY_IP": f"172.31.{wan_b_octet}.20",
        "WAN_A_DOCKER_GW": f"172.30.{wan_a_octet}.254",
        "WAN_B_DOCKER_GW": f"172.31.{wan_b_octet}.254",
        "MONITOR_IP": f"198.18.{monitor_octet}.10",
    }


@pytest.fixture(scope="module")
def testbed() -> Iterator[ComposeTestbed]:
    """Bring up the compose testbed once for all tests in this module."""
    if not _docker_compose_available():
        pytest.skip("docker compose is not available.")

    testbed = None
    for _ in range(8):
        candidate = ComposeTestbed(
            project=f"llroint{uuid.uuid4().hex[:8]}",
            env={},
        )
        env = os.environ.copy()
        env.update(_build_network_env(candidate.project))
        testbed = ComposeTestbed(project=candidate.project, env=env)
        up = _compose(testbed, "up", "--build", "-d")
        if up.returncode == 0:
            break
        if "Pool overlaps with other one on this address space" in up.stderr:
            continue
        pytest.fail(f"compose up failed:\nSTDOUT:\n{up.stdout}\nSTDERR:\n{up.stderr}")
    else:
        pytest.fail("compose up failed repeatedly due network overlap; please clean stale Docker networks")

    try:
        yield testbed
    finally:
        _compose(testbed, "down", "-v", "--remove-orphans")


@pytest.fixture(autouse=True)
def _reset_modes(testbed: ComposeTestbed) -> Iterator[None]:
    """Best-effort return to auto mode after each test so a failure does not cascade."""
    yield
    try:
        _cli(testbed, "reset-auto", "--all")
    except Exception:
        pass


def _route_gateway(testbed: ComposeTestbed, monitor_ip: str) -> str | None:
    """Return the gateway of the host route for monitor_ip, or None if absent."""
    out = _exec(testbed, "llro", "ip", "route", "show", f"{monitor_ip}/32")
    if out.returncode != 0:
        return None
    match = re.search(r"\bvia\s+(\S+)", out.stdout)
    return match.group(1) if match else None


def _wait_for_gateway(testbed: ComposeTestbed, monitor_ip: str, expected_gateway: str, timeout_seconds: int) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if _route_gateway(testbed, monitor_ip) == expected_gateway:
            return True
        time.sleep(1)
    return False


def _wait_for_any_route(testbed: ComposeTestbed, monitor_ip: str, timeout_seconds: int) -> str | None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        gateway = _route_gateway(testbed, monitor_ip)
        if gateway is not None:
            return gateway
        time.sleep(1)
    return None


def _ping_from_source(testbed: ComposeTestbed, source_ip: str, target_ip: str) -> bool:
    ping = _exec(testbed, "llro", "ping", "-c", "1", "-W", "1", "-I", source_ip, target_ip)
    return ping.returncode == 0


def _drop_icmp(testbed: ComposeTestbed, source_ip: str, monitor_ip: str) -> None:
    """Drop ICMP echo requests and replies between source_ip and the monitor on the target."""
    for chain, src, dst in (
        ("INPUT", source_ip, monitor_ip),
        ("OUTPUT", monitor_ip, source_ip),
    ):
        result = _exec(
            testbed,
            "target",
            "iptables",
            "-I",
            chain,
            "-p",
            "icmp",
            "-s",
            src,
            "-d",
            dst,
            "-j",
            "DROP",
        )
        assert result.returncode == 0, f"failed to apply target ICMP drop rule ({chain}):\n{result.stderr}"


def _cli(testbed: ComposeTestbed, *args: str) -> dict[str, Any]:
    """Run llro-cli inside the daemon container and return the parsed JSON payload."""
    out = _exec(testbed, "llro", "llro-cli", "--socket", ADMIN_SOCKET_PATH, *args)
    assert out.returncode == 0, "llro-cli {} failed:\n{}".format(" ".join(args), out.stderr)
    return json.loads(out.stdout)


def _cli_status(testbed: ComposeTestbed, monitor_ip: str) -> dict[str, Any]:
    status = _cli(testbed, "status", "--json")
    hosts = status.get("hosts") or []
    for host in hosts:
        if host.get("host") == monitor_ip:
            return host
    pytest.fail(f"monitor host {monitor_ip} missing from status output: {status}")


def _wait_for_all_routes_dead(testbed: ComposeTestbed, monitor_ip: str, timeout_seconds: int) -> bool:
    """Wait until the daemon's status reports every route for monitor_ip as dead."""
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            host = _cli_status(testbed, monitor_ip)
        except (AssertionError, json.JSONDecodeError):
            time.sleep(1)
            continue
        routes = host.get("routes") or {}
        if routes and all(not route.get("is_alive") for route in routes.values()):
            return True
        time.sleep(1)
    return False


def test_admin_socket_status_and_controls(testbed: ComposeTestbed) -> None:
    monitor_ip = testbed.env["MONITOR_IP"]
    wan_gateways = {testbed.env["WAN_A_GATEWAY_IP"], testbed.env["WAN_B_GATEWAY_IP"]}

    initial_gateway = _wait_for_any_route(testbed, monitor_ip, ROUTE_TIMEOUT_SECONDS)
    assert initial_gateway in wan_gateways, f"LLRO did not establish an initial route, got: {initial_gateway}"

    assert _ping_from_source(testbed, testbed.env["WAN_A_SOURCE_IP"], monitor_ip), (
        "wan_a source cannot reach monitor before fault injection"
    )
    assert _ping_from_source(testbed, testbed.env["WAN_B_SOURCE_IP"], monitor_ip), (
        "wan_b source cannot reach monitor before fault injection"
    )

    host = _cli_status(testbed, monitor_ip)
    assert host["mode"] == "auto"
    assert host["switching_enabled"] is True
    assert host["routes"], "status reports no probe data"

    # Pin the route to wan_b; the daemon applies it immediately.
    response = _cli(testbed, "override", "--host", monitor_ip, "--route", "wan_b")
    assert response["mode"] == "override"
    assert response["route_applied"] is True
    assert _wait_for_gateway(testbed, monitor_ip, testbed.env["WAN_B_GATEWAY_IP"], ROUTE_TIMEOUT_SECONDS), (
        "override did not move the route to wan_b"
    )

    host = _cli_status(testbed, monitor_ip)
    assert host["mode"] == "override"
    assert host["override_route"] == "wan_b"

    # Back to auto before freezing: disable-switching keeps mode "override"
    # on pinned hosts (override takes precedence), so exercise "frozen" in
    # auto mode.
    response = _cli(testbed, "reset-auto", "--host", monitor_ip)
    assert response["mode"] == "auto"
    host = _cli_status(testbed, monitor_ip)
    assert host["mode"] == "auto"
    assert host["override_route"] is None

    # Freeze switching, then return to auto mode.
    response = _cli(testbed, "disable-switching", "--host", monitor_ip)
    assert response["mode"] == "frozen"
    host = _cli_status(testbed, monitor_ip)
    assert host["mode"] == "frozen"
    assert host["switching_enabled"] is False

    response = _cli(testbed, "reset-auto", "--host", monitor_ip)
    assert response["mode"] == "auto"
    host = _cli_status(testbed, monitor_ip)
    assert host["mode"] == "auto"
    assert host["switching_enabled"] is True


def test_route_switchover_when_icmp_blocked_on_one_path(testbed: ComposeTestbed) -> None:
    monitor_ip = testbed.env["MONITOR_IP"]
    sources = {
        testbed.env["WAN_A_GATEWAY_IP"]: testbed.env["WAN_A_SOURCE_IP"],
        testbed.env["WAN_B_GATEWAY_IP"]: testbed.env["WAN_B_SOURCE_IP"],
    }

    current_gateway = _wait_for_any_route(testbed, monitor_ip, ROUTE_TIMEOUT_SECONDS)
    assert current_gateway in sources, f"no current route to break, got: {current_gateway}"

    # Block whichever path currently carries the route so a switch is forced.
    blocked_source = sources[current_gateway]
    other_gateway = next(gateway for gateway in sources if gateway != current_gateway)
    other_source = sources[other_gateway]

    _drop_icmp(testbed, blocked_source, monitor_ip)
    assert not _ping_from_source(testbed, blocked_source, monitor_ip), (
        "source still reaches monitor after target ICMP drop"
    )
    assert _ping_from_source(testbed, other_source, monitor_ip), (
        "other source became unreachable after target ICMP drop"
    )

    assert _wait_for_gateway(testbed, monitor_ip, other_gateway, SWITCH_TIMEOUT_SECONDS), (
        "LLRO did not switch route after ICMP was blocked on the active path"
    )


def test_fallback_route_when_all_paths_fail(testbed: ComposeTestbed) -> None:
    monitor_ip = testbed.env["MONITOR_IP"]

    # Block both paths (one may already be dropped by the previous test; a
    # duplicate iptables rule is harmless). The compose config maps
    # fallback_routes: <monitor_ip> -> wan_a.
    _drop_icmp(testbed, testbed.env["WAN_A_SOURCE_IP"], monitor_ip)
    _drop_icmp(testbed, testbed.env["WAN_B_SOURCE_IP"], monitor_ip)
    assert not _ping_from_source(testbed, testbed.env["WAN_A_SOURCE_IP"], monitor_ip)
    assert not _ping_from_source(testbed, testbed.env["WAN_B_SOURCE_IP"], monitor_ip)

    # Wait until the daemon itself reports every route as dead — only then is
    # the fallback responsible for the route that remains installed.
    assert _wait_for_all_routes_dead(testbed, monitor_ip, SWITCH_TIMEOUT_SECONDS), (
        "daemon never reported all routes dead"
    )
    assert _wait_for_gateway(testbed, monitor_ip, testbed.env["WAN_A_GATEWAY_IP"], SWITCH_TIMEOUT_SECONDS), (
        "fallback route via wan_a was not installed after all probes failed"
    )
