import asyncio
from types import SimpleNamespace
from typing import List

import pytest

import llro


class StopLoop(Exception):
    pass


def make_host(address: str, alive: bool, rtt: float, loss: float) -> SimpleNamespace:
    return SimpleNamespace(address=address, is_alive=alive, avg_rtt=rtt, packet_loss=loss)


def make_routes_config() -> dict:
    return {
        "monitor": ["1.1.1.1"],
        "routes": [
            {
                "name": "wan_a",
                "device": "eth0",
                "probe_source": "10.0.0.1",
                "gateway": "10.0.0.254",
            }
        ],
        "test_count": 1,
        "test_interval": 0,
        "scan_interval": 0,
        "rtt_threshold": 20,
        "packet_loss_threshold": 5,
    }


def test_import_smoke() -> None:
    assert llro.LowestLatencyRoutesOptimizer is not None


def test_normalize_legacy_interfaces_and_fallback_source() -> None:
    cfg = {
        "monitor": ["1.1.1.1"],
        "interfaces": {"eth0": ["10.0.0.1"]},
        "fallback_routes": {"1.1.1.1": "10.0.0.1"},
    }
    normalized = llro.normalize_config(cfg)
    assert normalized["routes"][0]["name"] == "eth0:10.0.0.1"
    assert normalized["fallback_routes"]["1.1.1.1"] == "eth0:10.0.0.1"


def test_normalize_rejects_invalid_fallback_reference() -> None:
    cfg = make_routes_config()
    cfg["fallback_routes"] = {"1.1.1.1": "unknown"}
    with pytest.raises(llro.ConfigError):
        llro.normalize_config(cfg)


def test_run_calls_clear_routes_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(
        {
            "monitor": ["1.1.1.1"],
            "routes": [
                {
                    "name": "wan_a",
                    "device": "eth0",
                    "probe_source": "10.0.0.1",
                    "gateway": "10.0.0.254",
                }
            ],
            "delete_preadded_routes": True,
        }
    )
    calls = {"clear": 0, "async": 0}

    async def fake_run_service() -> None:
        calls["async"] += 1

    monkeypatch.setattr(optimizer, "clear_routes", lambda: calls.__setitem__("clear", calls["clear"] + 1))
    monkeypatch.setattr(optimizer, "run_service", fake_run_service)
    optimizer.run()
    assert calls["clear"] == 1
    assert calls["async"] == 1


def test_normalize_config_sets_default_admin_socket_path() -> None:
    cfg = make_routes_config()
    normalized = llro.normalize_config(cfg)
    assert normalized["admin_socket_path"] == "/run/llro/admin.sock"


def test_apply_route_config_add_success_tracks_current_route(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = make_routes_config()
    cfg["also_route"] = {"1.1.1.1": ["1.0.0.1"]}
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    commands = []

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        commands.append((cmd, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(llro.subprocess, "run", fake_run)
    optimizer.apply_route_config("1.1.1.1", "wan_a")

    assert optimizer.current_routes["1.1.1.1"] == "wan_a"
    assert optimizer.current_routes["1.0.0.1"] == "wan_a"
    assert commands[0][0][0] == "/usr/sbin/ip"
    assert commands[0][0][1:4] == ["route", "add", "1.1.1.1/32"]
    assert all("shell" not in kwargs for _cmd, kwargs in commands)


def test_apply_route_config_replace_when_add_fails_with_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
    seen = []

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        seen.append(cmd)
        if "add" in cmd:
            return SimpleNamespace(returncode=2, stdout="", stderr="RTNETLINK answers: File exists")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(llro.subprocess, "run", fake_run)
    optimizer.apply_route_config("1.1.1.1", "wan_a")
    assert any(item[2] == "replace" for item in seen)
    assert optimizer.current_routes["1.1.1.1"] == "wan_a"


def test_clear_route_ignores_missing_route_error(monkeypatch: pytest.MonkeyPatch) -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())

    monkeypatch.setattr(
        llro.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=2, stdout="", stderr="RTNETLINK answers: No such process"),
    )
    optimizer.clear_route("1.1.1.1")


def test_run_async_applies_best_route_and_fallbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = {
        "monitor": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
            {"name": "wan_b", "device": "eth1", "probe_source": "10.0.0.2", "gateway": "10.0.1.254"},
        ],
        "fallback_routes": {"2.2.2.2": "wan_a"},
        "test_count": 1,
        "scan_interval": 0,
        "test_interval": 0,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    applied = []
    cleared = []

    async def fake_multiping(_monitor: List[str], **kwargs: object) -> List[SimpleNamespace]:
        source = kwargs["source"]
        if source == "10.0.0.1":
            return [
                make_host("1.1.1.1", True, 30, 0),
                make_host("2.2.2.2", False, 0, 100),
                make_host("3.3.3.3", False, 0, 100),
            ]
        return [make_host("1.1.1.1", True, 10, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(optimizer, "apply_route_config", lambda host, route: applied.append((host, route)))
    monkeypatch.setattr(optimizer, "clear_route", lambda host: cleared.append(host))

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert ("1.1.1.1", "wan_b") in applied
    assert ("2.2.2.2", "wan_a") in applied
    assert "3.3.3.3" in cleared


def test_run_async_keeps_current_route_when_diff_below_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = {
        "monitor": ["1.1.1.1"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
            {"name": "wan_b", "device": "eth1", "probe_source": "10.0.0.2", "gateway": "10.0.1.254"},
        ],
        "test_count": 1,
        "rtt_threshold": 50,
        "scan_interval": 0,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a"}
    applied = []

    async def fake_multiping(_monitor: List[str], **kwargs: object) -> List[SimpleNamespace]:
        if kwargs["source"] == "10.0.0.1":
            return [make_host("1.1.1.1", True, 100, 0)]
        return [make_host("1.1.1.1", True, 90, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(optimizer, "apply_route_config", lambda host, route: applied.append((host, route)))

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert applied == []


def test_run_async_switches_on_packet_loss(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = {
        "monitor": ["1.1.1.1"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
            {"name": "wan_b", "device": "eth1", "probe_source": "10.0.0.2", "gateway": "10.0.1.254"},
        ],
        "test_count": 1,
        "packet_loss_threshold": 1,
        "scan_interval": 0,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a"}
    applied = []

    async def fake_multiping(_monitor: List[str], **kwargs: object) -> List[SimpleNamespace]:
        if kwargs["source"] == "10.0.0.1":
            return [make_host("1.1.1.1", True, 40, 50)]
        return [make_host("1.1.1.1", True, 50, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(optimizer, "apply_route_config", lambda host, route: applied.append((host, route)))

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert ("1.1.1.1", "wan_b") in applied


def test_admin_actions_override_disable_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = {
        "monitor": ["1.1.1.1"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
            {"name": "wan_b", "device": "eth1", "probe_source": "10.0.0.2", "gateway": "10.0.1.254"},
        ],
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    applied = []
    monkeypatch.setattr(optimizer, "apply_route_config", lambda host, route: applied.append((host, route)))

    response = asyncio.run(optimizer._handle_admin_action({"action": "override", "host": "1.1.1.1", "route": "wan_b"}))
    assert response["ok"] is True
    assert ("1.1.1.1", "wan_b") in applied
    assert optimizer.route_modes["1.1.1.1"] == "override"
    assert optimizer.override_routes["1.1.1.1"] == "wan_b"

    response = asyncio.run(optimizer._handle_admin_action({"action": "disable_switching", "host": "1.1.1.1"}))
    assert response["ok"] is True
    assert optimizer.switching_enabled["1.1.1.1"] is False

    response = asyncio.run(optimizer._handle_admin_action({"action": "reset_auto", "host": "1.1.1.1"}))
    assert response["ok"] is True
    assert optimizer.route_modes["1.1.1.1"] == "auto"
    assert optimizer.switching_enabled["1.1.1.1"] is True
    assert "1.1.1.1" not in optimizer.override_routes


def test_admin_status_and_validation_errors() -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
    optimizer.current_routes["1.1.1.1"] = "wan_a"
    optimizer.last_probe_snapshot = {"1.1.1.1": {"wan_a": {"avg_rtt": 10.5, "avg_loss": 0, "is_alive": True}}}

    status = asyncio.run(optimizer._handle_admin_action({"action": "status"}))
    assert status["ok"] is True
    host = status["data"]["hosts"][0]
    assert host["host"] == "1.1.1.1"
    assert host["current_route"] == "wan_a"
    assert host["routes"]["wan_a"]["avg_rtt"] == 10.5

    bad_route = asyncio.run(
        optimizer._handle_admin_action({"action": "override", "host": "1.1.1.1", "route": "missing"})
    )
    assert bad_route["ok"] is False

    bad_action = asyncio.run(optimizer._handle_admin_action({"action": "unknown"}))
    assert bad_action["ok"] is False


def test_run_async_respects_route_override(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = {
        "monitor": ["1.1.1.1"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
            {"name": "wan_b", "device": "eth1", "probe_source": "10.0.0.2", "gateway": "10.0.1.254"},
        ],
        "test_count": 1,
        "scan_interval": 0,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.route_modes["1.1.1.1"] = "override"
    optimizer.override_routes["1.1.1.1"] = "wan_b"
    applied = []

    async def fake_multiping(_monitor: List[str], **kwargs: object) -> List[SimpleNamespace]:
        if kwargs["source"] == "10.0.0.1":
            return [make_host("1.1.1.1", True, 10, 0)]
        return [make_host("1.1.1.1", True, 50, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(optimizer, "apply_route_config", lambda host, route: applied.append((host, route)))

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert ("1.1.1.1", "wan_b") in applied


def test_run_async_freeze_blocks_switching(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = {
        "monitor": ["1.1.1.1"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
            {"name": "wan_b", "device": "eth1", "probe_source": "10.0.0.2", "gateway": "10.0.1.254"},
        ],
        "test_count": 1,
        "scan_interval": 0,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a"}
    optimizer.route_modes["1.1.1.1"] = "frozen"
    optimizer.switching_enabled["1.1.1.1"] = False
    applied = []

    async def fake_multiping(_monitor: List[str], **kwargs: object) -> List[SimpleNamespace]:
        if kwargs["source"] == "10.0.0.1":
            return [make_host("1.1.1.1", True, 100, 0)]
        return [make_host("1.1.1.1", True, 10, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(optimizer, "apply_route_config", lambda host, route: applied.append((host, route)))

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert applied == []
