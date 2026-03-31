import os
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict

import pytest


def _run(cmd, env=None):  # type: ignore[no-untyped-def]
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        check=False,
        env=env,
    )


def _wait_for_route(
    compose_file: Path,
    project_name: str,
    monitor_ip: str,
    expected_gateway: str,
    timeout_seconds: int,
    env: Dict[str, str],
) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        out = _run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "-p",
                project_name,
                "exec",
                "-T",
                "llro",
                "ip",
                "route",
                "show",
                "%s/32" % monitor_ip,
            ],
            env=env,
        )
        if out.returncode == 0 and ("via %s" % expected_gateway) in out.stdout:
            return True
        time.sleep(1)
    return False


def _ping_from_source(compose_file: Path, project_name: str, source_ip: str, target_ip: str, env: Dict[str, str]) -> bool:
    ping = _run(
        [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "-p",
            project_name,
            "exec",
            "-T",
            "llro",
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            "-I",
            source_ip,
            target_ip,
        ],
        env=env,
    )
    return ping.returncode == 0


def _build_network_env(project_name: str) -> Dict[str, str]:
    seed = int(project_name[-2:], 16)
    wan_a_octet = 100 + (seed % 50)
    wan_b_octet = 150 + (seed % 50)
    monitor_octet = 10 + (seed % 200)

    return {
        "WAN_A_SUBNET": "172.30.%s.0/24" % wan_a_octet,
        "WAN_B_SUBNET": "172.31.%s.0/24" % wan_b_octet,
        "WAN_A_SOURCE_IP": "172.30.%s.10" % wan_a_octet,
        "WAN_B_SOURCE_IP": "172.31.%s.10" % wan_b_octet,
        "WAN_A_TARGET_IP": "172.30.%s.20" % wan_a_octet,
        "WAN_B_TARGET_IP": "172.31.%s.20" % wan_b_octet,
        "WAN_A_GATEWAY_IP": "172.30.%s.20" % wan_a_octet,
        "WAN_B_GATEWAY_IP": "172.31.%s.20" % wan_b_octet,
        "WAN_A_DOCKER_GW": "172.30.%s.254" % wan_a_octet,
        "WAN_B_DOCKER_GW": "172.31.%s.254" % wan_b_octet,
        "MONITOR_IP": "198.18.%s.10" % monitor_octet,
    }


@pytest.mark.integration
def test_route_switchover_when_icmp_blocked_on_one_path() -> None:
    if os.environ.get("RUN_DOCKER_INTEGRATION") != "1":
        pytest.skip("Set RUN_DOCKER_INTEGRATION=1 to run Docker integration tests.")

    compose_file = Path(__file__).resolve().parent / "integration" / "docker-compose.yml"
    base_env = os.environ.copy()
    docker_check = _run(["docker", "compose", "version"], env=base_env)
    if docker_check.returncode != 0:
        pytest.skip("docker compose is not available.")

    project_name = ""
    compose_env = {}
    up = None
    for _ in range(8):
        project_name = "llroint%s" % uuid.uuid4().hex[:8]
        compose_env = base_env.copy()
        compose_env.update(_build_network_env(project_name))
        up = _run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "-p",
                project_name,
                "up",
                "--build",
                "-d",
            ],
            env=compose_env,
        )
        if up.returncode == 0:
            break
        if "Pool overlaps with other one on this address space" in up.stderr:
            continue
        pytest.fail("compose up failed:\nSTDOUT:\n%s\nSTDERR:\n%s" % (up.stdout, up.stderr))

    if up is None or up.returncode != 0:
        pytest.fail("compose up failed repeatedly due network overlap; please clean stale Docker networks")

    try:
        stable_on_a = _wait_for_route(
            compose_file,
            project_name,
            compose_env["MONITOR_IP"],
            compose_env["WAN_A_GATEWAY_IP"],
            45,
            compose_env,
        )
        assert stable_on_a, "LLRO did not establish the expected initial route via wan_a"
        assert _ping_from_source(
            compose_file,
            project_name,
            compose_env["WAN_A_SOURCE_IP"],
            compose_env["MONITOR_IP"],
            compose_env,
        ), "wan_a source cannot reach monitor before fault injection"
        assert _ping_from_source(
            compose_file,
            project_name,
            compose_env["WAN_B_SOURCE_IP"],
            compose_env["MONITOR_IP"],
            compose_env,
        ), "wan_b source cannot reach monitor before fault injection"

        drop_icmp = _run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "-p",
                project_name,
                "exec",
                "-T",
                "target",
                "iptables",
                "-I",
                "INPUT",
                "-p",
                "icmp",
                "-s",
                compose_env["WAN_A_SOURCE_IP"],
                "-d",
                compose_env["MONITOR_IP"],
                "-j",
                "DROP",
            ],
            env=compose_env,
        )
        assert drop_icmp.returncode == 0, "failed to apply target ICMP drop rule:\n%s" % drop_icmp.stderr
        drop_icmp_reply = _run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "-p",
                project_name,
                "exec",
                "-T",
                "target",
                "iptables",
                "-I",
                "OUTPUT",
                "-p",
                "icmp",
                "-s",
                compose_env["MONITOR_IP"],
                "-d",
                compose_env["WAN_A_SOURCE_IP"],
                "-j",
                "DROP",
            ],
            env=compose_env,
        )
        assert drop_icmp_reply.returncode == 0, "failed to apply target ICMP reply drop rule:\n%s" % drop_icmp_reply.stderr

        confirm_drop = _ping_from_source(
            compose_file,
            project_name,
            compose_env["WAN_A_SOURCE_IP"],
            compose_env["MONITOR_IP"],
            compose_env,
        )
        assert not confirm_drop, "wan_a source still reaches monitor after target ICMP drop"
        confirm_wan_b_alive = _ping_from_source(
            compose_file,
            project_name,
            compose_env["WAN_B_SOURCE_IP"],
            compose_env["MONITOR_IP"],
            compose_env,
        )
        assert confirm_wan_b_alive, "wan_b source became unreachable after target ICMP drop for wan_a"

        switched_to_b = _wait_for_route(
            compose_file,
            project_name,
            compose_env["MONITOR_IP"],
            compose_env["WAN_B_GATEWAY_IP"],
            60,
            compose_env,
        )
        assert switched_to_b, "LLRO did not switch route to wan_b after ICMP was blocked on wan_a path"
    finally:
        _run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "-p",
                project_name,
                "down",
                "-v",
                "--remove-orphans",
            ],
            env=compose_env,
        )
