import asyncio
import json
import logging
import os
import subprocess
from types import SimpleNamespace

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
        "test_interval": 0.01,
        "scan_interval": 0.01,
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
    calls = []

    async def fake_start() -> None:
        calls.append("start")

    async def fake_stop() -> None:
        calls.append("stop")

    async def fake_clear() -> None:
        calls.append("clear")

    async def fake_run_async(_stop_event: asyncio.Event) -> None:
        calls.append("run")

    monkeypatch.setattr(optimizer, "_start_admin_server", fake_start)
    monkeypatch.setattr(optimizer, "_stop_admin_server", fake_stop)
    monkeypatch.setattr(optimizer, "clear_routes", fake_clear)
    monkeypatch.setattr(optimizer, "run_async", fake_run_async)
    optimizer.run()
    assert calls == ["start", "clear", "run", "stop"]


def test_normalize_config_sets_default_admin_socket_path() -> None:
    cfg = make_routes_config()
    normalized = llro.normalize_config(cfg)
    assert normalized["admin_socket_path"] == "/run/llro/admin.sock"


def test_normalize_config_default_payload_size() -> None:
    cfg = make_routes_config()
    normalized = llro.normalize_config(cfg)
    assert normalized["payload_size"] == 56


def test_normalize_config_default_systemd_logging() -> None:
    cfg = make_routes_config()
    normalized = llro.normalize_config(cfg)
    assert normalized["systemd_logging"] is False


def test_normalize_config_custom_systemd_logging() -> None:
    cfg = make_routes_config()
    cfg["systemd_logging"] = True
    normalized = llro.normalize_config(cfg)
    assert normalized["systemd_logging"] is True


def test_normalize_config_custom_payload_size() -> None:
    cfg = make_routes_config()
    cfg["payload_size"] = 128
    normalized = llro.normalize_config(cfg)
    assert normalized["payload_size"] == 128


def test_normalize_config_rejects_invalid_payload_size() -> None:
    cfg = make_routes_config()
    cfg["payload_size"] = "big"
    with pytest.raises(llro.ConfigError):
        llro.normalize_config(cfg)


def test_apply_route_config_add_success_tracks_current_route(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = make_routes_config()
    cfg["also_route"] = {"1.1.1.1": ["1.0.0.1"]}
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    commands = []

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        commands.append((cmd, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(llro.subprocess, "run", fake_run)
    asyncio.run(optimizer.apply_route_config("1.1.1.1", "wan_a"))

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
    asyncio.run(optimizer.apply_route_config("1.1.1.1", "wan_a"))
    assert any(item[2] == "replace" for item in seen)
    assert optimizer.current_routes["1.1.1.1"] == "wan_a"


def test_clear_route_ignores_missing_route_error(monkeypatch: pytest.MonkeyPatch) -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())

    monkeypatch.setattr(
        llro.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=2, stdout="", stderr="RTNETLINK answers: No such process"),
    )
    asyncio.run(optimizer.clear_route("1.1.1.1"))


def test_run_async_forwards_payload_size_to_multiping(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = make_routes_config()
    cfg["payload_size"] = 128
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    captured = {}

    async def fake_multiping(_monitor: list[str], **kwargs: object) -> list[SimpleNamespace]:
        captured["payload_size"] = kwargs.get("payload_size")
        return [make_host("1.1.1.1", True, 10, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)

    async def fake_apply(_host, _route):  # type: ignore[no-untyped-def]
        return True

    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert captured.get("payload_size") == 128


def test_run_async_applies_best_route_and_fallbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = {
        "monitor": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
            {"name": "wan_b", "device": "eth1", "probe_source": "10.0.0.2", "gateway": "10.0.1.254"},
        ],
        "fallback_routes": {"2.2.2.2": "wan_a"},
        "test_count": 1,
        "scan_interval": 0.01,
        "test_interval": 0.01,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    applied = []
    cleared = []

    async def fake_multiping(_monitor: list[str], **kwargs: object) -> list[SimpleNamespace]:
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

    async def fake_apply(host, route):  # type: ignore[no-untyped-def]
        applied.append((host, route))
        return True

    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

    async def fake_clear(host):  # type: ignore[no-untyped-def]
        cleared.append(host)

    monkeypatch.setattr(optimizer, "clear_route", fake_clear)

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
        "scan_interval": 0.01,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a"}
    applied = []

    async def fake_multiping(_monitor: list[str], **kwargs: object) -> list[SimpleNamespace]:
        if kwargs["source"] == "10.0.0.1":
            return [make_host("1.1.1.1", True, 100, 0)]
        return [make_host("1.1.1.1", True, 90, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)

    async def fake_apply(host, route):  # type: ignore[no-untyped-def]
        applied.append((host, route))
        return True

    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

    async def fake_missing(_destinations):  # type: ignore[no-untyped-def]
        return []

    monkeypatch.setattr(optimizer, "_missing_destinations", fake_missing)

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
        "scan_interval": 0.01,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a"}
    applied = []

    async def fake_multiping(_monitor: list[str], **kwargs: object) -> list[SimpleNamespace]:
        if kwargs["source"] == "10.0.0.1":
            return [make_host("1.1.1.1", True, 40, 50)]
        return [make_host("1.1.1.1", True, 50, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)

    async def fake_apply(host, route):  # type: ignore[no-untyped-def]
        applied.append((host, route))
        return True

    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert ("1.1.1.1", "wan_b") in applied


def test_run_async_switches_on_packet_loss_percent_units(monkeypatch: pytest.MonkeyPatch) -> None:
    # icmplib reports packet_loss as a 0..1 ratio; thresholds are configured in %.
    # 50% loss (ratio 0.5) must exceed a 5% threshold and force a switch.
    cfg = {
        "monitor": ["1.1.1.1"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
            {"name": "wan_b", "device": "eth1", "probe_source": "10.0.0.2", "gateway": "10.0.1.254"},
        ],
        "test_count": 1,
        "packet_loss_threshold": 5,
        "scan_interval": 0.01,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a"}
    applied = []

    async def fake_multiping(_monitor: list[str], **kwargs: object) -> list[SimpleNamespace]:
        if kwargs["source"] == "10.0.0.1":
            return [make_host("1.1.1.1", True, 40, 0.5)]
        return [make_host("1.1.1.1", True, 50, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)

    async def fake_apply(host, route):  # type: ignore[no-untyped-def]
        applied.append((host, route))
        return True

    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert ("1.1.1.1", "wan_b") in applied


def test_run_async_prefers_stable_route_over_flapping(monkeypatch: pytest.MonkeyPatch) -> None:
    # wan_b answers only 1 of 3 probe rounds. Averaging must not reward it for
    # the rounds where it was completely dead.
    cfg = {
        "monitor": ["1.1.1.1"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
            {"name": "wan_b", "device": "eth1", "probe_source": "10.0.0.2", "gateway": "10.0.1.254"},
        ],
        "test_count": 3,
        "scan_interval": 0.01,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a"}
    applied = []
    wan_b_calls = {"count": 0}
    sleep_calls = {"count": 0}

    async def fake_multiping(_monitor: list[str], **kwargs: object) -> list[SimpleNamespace]:
        if kwargs["source"] == "10.0.0.1":
            return [make_host("1.1.1.1", True, 40, 0)]
        wan_b_calls["count"] += 1
        if wan_b_calls["count"] == 1:
            return [make_host("1.1.1.1", True, 10, 0)]
        return [make_host("1.1.1.1", False, 0, 1.0)]

    async def fake_sleep(_seconds: float) -> None:
        sleep_calls["count"] += 1
        if sleep_calls["count"] >= 3:
            raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)

    async def fake_apply(host, route):  # type: ignore[no-untyped-def]
        applied.append((host, route))
        return True

    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

    async def fake_missing(_destinations):  # type: ignore[no-untyped-def]
        return []

    monkeypatch.setattr(optimizer, "_missing_destinations", fake_missing)

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert applied == []


def test_run_async_frozen_host_not_cleared_when_probes_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = {
        "monitor": ["1.1.1.1"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
        ],
        "test_count": 1,
        "scan_interval": 0.01,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a"}
    optimizer.route_modes["1.1.1.1"] = "frozen"
    optimizer.switching_enabled["1.1.1.1"] = False
    cleared = []

    async def fake_multiping(_monitor: list[str], **_kwargs: object) -> list[SimpleNamespace]:
        return [make_host("1.1.1.1", False, 0, 1.0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)

    async def fake_clear(host):  # type: ignore[no-untyped-def]
        cleared.append(host)

    monkeypatch.setattr(optimizer, "clear_route", fake_clear)

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert cleared == []


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

    async def fake_apply(host, route):  # type: ignore[no-untyped-def]
        applied.append((host, route))
        return True

    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

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
    optimizer._ewma["1.1.1.1"] = {"wan_a": {"rtt": 11.25, "loss": 1.5}}

    status = asyncio.run(optimizer._handle_admin_action({"action": "status"}))
    assert status["ok"] is True
    host = status["data"]["hosts"][0]
    assert host["host"] == "1.1.1.1"
    assert host["current_route"] == "wan_a"
    assert host["routes"]["wan_a"]["avg_rtt"] == 10.5
    assert host["routes"]["wan_a"]["ewma_rtt"] == 11.25
    assert host["routes"]["wan_a"]["ewma_loss"] == 1.5

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
        "scan_interval": 0.01,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.route_modes["1.1.1.1"] = "override"
    optimizer.override_routes["1.1.1.1"] = "wan_b"
    applied = []

    async def fake_multiping(_monitor: list[str], **kwargs: object) -> list[SimpleNamespace]:
        if kwargs["source"] == "10.0.0.1":
            return [make_host("1.1.1.1", True, 10, 0)]
        return [make_host("1.1.1.1", True, 50, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)

    async def fake_apply(host, route):  # type: ignore[no-untyped-def]
        applied.append((host, route))
        return True

    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

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
        "scan_interval": 0.01,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a"}
    optimizer.route_modes["1.1.1.1"] = "frozen"
    optimizer.switching_enabled["1.1.1.1"] = False
    applied = []

    async def fake_multiping(_monitor: list[str], **kwargs: object) -> list[SimpleNamespace]:
        if kwargs["source"] == "10.0.0.1":
            return [make_host("1.1.1.1", True, 100, 0)]
        return [make_host("1.1.1.1", True, 10, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)

    async def fake_apply(host, route):  # type: ignore[no-untyped-def]
        applied.append((host, route))
        return True

    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

    async def fake_missing(_destinations):  # type: ignore[no-untyped-def]
        return []

    monkeypatch.setattr(optimizer, "_missing_destinations", fake_missing)

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert applied == []


def test_normalize_config_validation_errors() -> None:
    with pytest.raises(llro.ConfigError):
        llro.normalize_config("not-a-mapping")  # type: ignore[arg-type]

    with pytest.raises(llro.ConfigError):
        llro.normalize_config({"monitor": "1.1.1.1", "routes": []})  # type: ignore[dict-item]

    with pytest.raises(llro.ConfigError):
        llro.normalize_config({"monitor": ["1.1.1.1"], "also_route": [], "routes": []})  # type: ignore[dict-item]

    with pytest.raises(llro.ConfigError):
        llro.normalize_config({"monitor": ["1.1.1.1"], "also_route": {"1.1.1.1": "x"}, "routes": []})  # type: ignore[dict-item]

    with pytest.raises(llro.ConfigError):
        llro.normalize_config({"monitor": ["1.1.1.1"], "routes": "bad"})  # type: ignore[dict-item]

    with pytest.raises(llro.ConfigError):
        llro.normalize_config({"monitor": ["1.1.1.1"], "routes": ["bad"]})  # type: ignore[list-item]

    with pytest.raises(llro.ConfigError):
        llro.normalize_config({"monitor": ["1.1.1.1"], "interfaces": {}, "routes": None})  # type: ignore[dict-item]

    with pytest.raises(llro.ConfigError):
        llro.normalize_config({"monitor": ["1.1.1.1"], "interfaces": {"eth0": []}, "routes": None})  # type: ignore[dict-item]


def test_normalize_config_duplicate_and_threshold_validation() -> None:
    cfg = {
        "monitor": ["1.1.1.1"],
        "routes": [
            {"name": "dup", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
            {"name": "dup", "device": "eth1", "probe_source": "10.0.0.2", "gateway": "10.0.1.254"},
        ],
    }
    with pytest.raises(llro.ConfigError):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["test_count"] = 0
    with pytest.raises(llro.ConfigError):
        llro.normalize_config(cfg)


def test_normalize_config_rejects_non_numeric_thresholds() -> None:
    cfg = make_routes_config()
    cfg["rtt_threshold"] = "fast"
    with pytest.raises(llro.ConfigError):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["packet_loss_threshold"] = "low"
    with pytest.raises(llro.ConfigError):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["test_interval"] = "soon"
    with pytest.raises(llro.ConfigError):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["scan_interval"] = "later"
    with pytest.raises(llro.ConfigError):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["test_count"] = "many"
    with pytest.raises(llro.ConfigError):
        llro.normalize_config(cfg)


def test_normalize_fallback_rejects_unknown_host_and_accepts_unique_gateway() -> None:
    cfg = {
        "monitor": ["1.1.1.1"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
        ],
        "fallback_routes": {"2.2.2.2": "wan_a"},
    }
    with pytest.raises(llro.ConfigError):
        llro.normalize_config(cfg)

    cfg["fallback_routes"] = {"1.1.1.1": "10.0.0.254"}
    normalized = llro.normalize_config(cfg)
    assert normalized["fallback_routes"]["1.1.1.1"] == "wan_a"


def test_resolve_targets_supports_all_and_rejects_invalid_host() -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
    assert optimizer._resolve_targets({"all": True}) == ["1.1.1.1"]
    assert optimizer._resolve_targets({"host": "8.8.8.8"}) is None


def test_run_ip_handles_exception_stdout_and_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())

    def raise_error(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise OSError("boom")

    monkeypatch.setattr(llro.subprocess, "run", raise_error)
    ok, err = asyncio.run(optimizer._run_ip(["route", "show"]))
    assert ok is False
    assert "boom" in err

    monkeypatch.setattr(
        llro.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="shown", stderr=""),
    )
    ok, err = asyncio.run(optimizer._run_ip(["route", "show"]))
    assert ok is True
    assert err == ""

    monkeypatch.setattr(
        llro.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=3, stdout="", stderr=""),
    )
    ok, err = asyncio.run(optimizer._run_ip(["route", "show"]))
    assert ok is False
    assert "exit code 3" in err


def test_clear_route_logs_error_for_unexpected_failure(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())

    async def fake_run_ip(_args):  # type: ignore[no-untyped-def]
        return False, "permission denied"

    monkeypatch.setattr(optimizer, "_run_ip", fake_run_ip)
    caplog.set_level(logging.ERROR)
    asyncio.run(optimizer.clear_route("1.1.1.1"))
    assert "Failed to remove route for 1.1.1.1" in caplog.text


def test_apply_route_config_logs_errors(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())

    caplog.set_level(logging.ERROR)
    asyncio.run(optimizer.apply_route_config("1.1.1.1", "missing"))
    assert "Unknown route 'missing'" in caplog.text

    calls = {"count": 0}

    async def fail_add_then_replace(_args):  # type: ignore[no-untyped-def]
        calls["count"] += 1
        if calls["count"] == 1:
            return False, "unexpected add failure"
        return False, "replace failed"

    monkeypatch.setattr(optimizer, "_run_ip", fail_add_then_replace)
    optimizer.current_routes["1.1.1.1"] = "wan_a"
    asyncio.run(optimizer.apply_route_config("1.1.1.1", "wan_a"))
    assert "Failed to replace route for 1.1.1.1" in caplog.text

    optimizer.current_routes.clear()
    asyncio.run(optimizer.apply_route_config("1.1.1.1", "wan_a"))
    assert "Failed to add route for 1.1.1.1" in caplog.text


def test_clear_routes_applies_fallback_and_clears_tracking(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = make_routes_config()
    cfg["also_route"] = {"1.1.1.1": ["1.0.0.1"]}
    cfg["fallback_routes"] = {"1.1.1.1": "wan_a"}
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a", "1.0.0.1": "wan_a"}
    cleared = []
    applied = []

    async def fake_clear(host):  # type: ignore[no-untyped-def]
        cleared.append(host)

    monkeypatch.setattr(optimizer, "clear_route", fake_clear)

    async def fake_apply(host, route):  # type: ignore[no-untyped-def]
        applied.append((host, route))
        return True

    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)
    asyncio.run(optimizer.clear_routes())
    assert set(cleared) == {"1.1.1.1", "1.0.0.1"}
    assert optimizer.current_routes == {}
    assert applied == [("1.1.1.1", "wan_a")]


def test_run_service_starts_and_stops_admin_server(monkeypatch: pytest.MonkeyPatch) -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
    calls = []

    async def fake_start() -> None:
        calls.append("start")

    async def fake_run(_stop_event: asyncio.Event = None) -> None:  # type: ignore[assignment]
        calls.append("run")
        assert _stop_event is not None

    async def fake_stop() -> None:
        calls.append("stop")

    monkeypatch.setattr(optimizer, "_start_admin_server", fake_start)
    monkeypatch.setattr(optimizer, "run_async", fake_run)
    monkeypatch.setattr(optimizer, "_stop_admin_server", fake_stop)
    asyncio.run(optimizer.run_service())
    assert calls == ["start", "run", "stop"]


def test_run_async_stops_when_stop_event_set(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = make_routes_config()
    cfg["scan_interval"] = 60
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    probe_calls = {"count": 0}

    async def fake_multiping(_monitor: list[str], **_kwargs: object) -> list[SimpleNamespace]:
        probe_calls["count"] += 1
        return [make_host("1.1.1.1", True, 10, 0)]

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)

    async def runner() -> None:
        stop_event = asyncio.Event()

        async def fake_wait_for(awaitable, **_kwargs):  # type: ignore[no-untyped-def]
            stop_event.set()
            return await awaitable

        monkeypatch.setattr(llro.asyncio, "wait_for", fake_wait_for)
        await optimizer.run_async(stop_event=stop_event)

    asyncio.run(runner())
    assert probe_calls["count"] == 1


def test_admin_server_start_and_stop_with_real_socket(tmp_path) -> None:  # type: ignore[no-untyped-def]
    socket_path = str(tmp_path / "admin.sock")
    cfg = make_routes_config()
    cfg["admin_socket_path"] = socket_path
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    asyncio.run(optimizer._start_admin_server())
    assert os.path.exists(socket_path)
    asyncio.run(optimizer._stop_admin_server())
    assert not os.path.exists(socket_path)


def test_admin_server_start_rejects_non_socket_path(tmp_path) -> None:  # type: ignore[no-untyped-def]
    socket_path = tmp_path / "admin.sock"
    socket_path.write_text("not a socket", encoding="utf-8")
    cfg = make_routes_config()
    cfg["admin_socket_path"] = str(socket_path)
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    with pytest.raises(RuntimeError):
        asyncio.run(optimizer._start_admin_server())


def test_handle_admin_client_invalid_json_and_handler_error(tmp_path) -> None:  # type: ignore[no-untyped-def]
    async def run_case(request_line: bytes, action_impl, sock_path: str):  # type: ignore[no-untyped-def]
        optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
        setattr(optimizer, "_handle_admin_action", action_impl)

        server = await asyncio.start_unix_server(optimizer._handle_admin_client, path=sock_path)
        client_reader, client_writer = await asyncio.open_unix_connection(path=sock_path)
        client_writer.write(request_line)
        await client_writer.drain()
        response = await client_reader.readline()
        client_writer.close()
        await client_writer.wait_closed()
        server.close()
        await server.wait_closed()
        return json.loads(response.decode("utf-8"))

    invalid = asyncio.run(run_case(b"not-json\n", lambda _req: {"ok": True}, str(tmp_path / "invalid.sock")))
    assert invalid["ok"] is False
    assert "invalid JSON" in invalid["error"]

    async def fail_action(_request):  # type: ignore[no-untyped-def]
        raise RuntimeError("explode")

    failed = asyncio.run(run_case(b'{"action":"status"}\n', fail_action, str(tmp_path / "error.sock")))
    assert failed["ok"] is False
    assert "explode" in failed["error"]


def test_admin_action_validation_errors() -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
    response = asyncio.run(optimizer._handle_admin_action("bad"))  # type: ignore[arg-type]
    assert response["ok"] is False
    assert "JSON object" in response["error"]

    response = asyncio.run(optimizer._handle_admin_action({"action": "override", "host": 1, "route": None}))
    assert response["ok"] is False

    response = asyncio.run(optimizer._handle_admin_action({"action": "override", "host": "9.9.9.9", "route": "wan_a"}))
    assert response["ok"] is False

    response = asyncio.run(optimizer._handle_admin_action({"action": "disable_switching"}))
    assert response["ok"] is False

    response = asyncio.run(optimizer._handle_admin_action({"action": "reset_auto"}))
    assert response["ok"] is False


def test_main_error_paths_and_debug_run(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    missing = tmp_path / "missing.yml"
    monkeypatch.setattr("sys.argv", ["llro", "--config", str(missing)])
    with pytest.raises(SystemExit) as exc:
        llro.main()
    assert exc.value.code == 1

    bad_yaml = tmp_path / "bad.yml"
    bad_yaml.write_text(":\n", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["llro", "--config", str(bad_yaml)])
    with pytest.raises(SystemExit) as exc:
        llro.main()
    assert exc.value.code == 1

    empty_yaml = tmp_path / "empty.yml"
    empty_yaml.write_text("", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["llro", "--config", str(empty_yaml)])
    with pytest.raises(SystemExit) as exc:
        llro.main()
    assert exc.value.code == 1

    invalid_cfg = tmp_path / "invalid.yml"
    invalid_cfg.write_text("monitor: [1.1.1.1]\nroutes: []\n", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["llro", "--config", str(invalid_cfg)])
    with pytest.raises(SystemExit) as exc:
        llro.main()
    assert exc.value.code == 1

    valid_cfg = tmp_path / "valid.yml"
    valid_cfg.write_text(
        (
            "monitor:\n"
            "  - 1.1.1.1\n"
            "routes:\n"
            "  - name: wan_a\n"
            "    device: eth0\n"
            "    probe_source: 10.0.0.1\n"
            "    gateway: 10.0.0.254\n"
            "debug: true\n"
        ),
        encoding="utf-8",
    )
    called = {"run": 0}

    def fake_run(self) -> None:  # type: ignore[no-untyped-def]
        called["run"] += 1

    monkeypatch.setattr(llro.LowestLatencyRoutesOptimizer, "run", fake_run)
    monkeypatch.setattr("sys.argv", ["llro", "--config", str(valid_cfg)])
    llro.main()
    assert called["run"] == 1


def test_main_systemd_logging_flag_overrides_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path, caplog: pytest.LogCaptureFixture
) -> None:  # type: ignore[no-untyped-def]
    valid_cfg = tmp_path / "valid.yml"
    valid_cfg.write_text(
        (
            "monitor:\n"
            "  - 1.1.1.1\n"
            "routes:\n"
            "  - name: wan_a\n"
            "    device: eth0\n"
            "    probe_source: 10.0.0.1\n"
            "    gateway: 10.0.0.254\n"
        ),
        encoding="utf-8",
    )
    called = {"run": 0}

    def fake_run(self) -> None:  # type: ignore[no-untyped-def]
        called["run"] += 1

    monkeypatch.setattr(llro.LowestLatencyRoutesOptimizer, "run", fake_run)
    monkeypatch.setattr("sys.argv", ["llro", "--config", str(valid_cfg), "--systemd-logging"])
    with caplog.at_level(logging.INFO):
        llro.main()
    assert called["run"] == 1
    # Timestamp should be absent from the handler format.
    for handler in logging.getLogger().handlers:
        assert "%(asctime)s" not in handler.formatter._fmt  # type: ignore[union-attr]


def test_normalize_config_rejects_invalid_monitor_ip() -> None:
    cfg = make_routes_config()
    cfg["monitor"] = ["not-an-ip"]
    with pytest.raises(llro.ConfigError, match="valid IP address"):
        llro.normalize_config(cfg)


def test_normalize_config_rejects_duplicate_monitor_entries() -> None:
    cfg = make_routes_config()
    cfg["monitor"] = ["1.1.1.1", "1.1.1.1"]
    with pytest.raises(llro.ConfigError, match="duplicate"):
        llro.normalize_config(cfg)


def test_normalize_config_rejects_also_route_conflicts() -> None:
    cfg = make_routes_config()
    cfg["monitor"] = ["1.1.1.1", "2.2.2.2"]
    cfg["also_route"] = {"1.1.1.1": ["2.2.2.2"]}
    with pytest.raises(llro.ConfigError, match="must not be a monitored host"):
        llro.normalize_config(cfg)

    cfg["also_route"] = {"1.1.1.1": ["9.9.9.9"], "2.2.2.2": ["9.9.9.9"]}
    with pytest.raises(llro.ConfigError, match="multiple hosts"):
        llro.normalize_config(cfg)


def test_normalize_config_rejects_out_of_range_thresholds() -> None:
    cfg = make_routes_config()
    cfg["rtt_threshold"] = -1
    with pytest.raises(llro.ConfigError, match="rtt_threshold"):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["packet_loss_threshold"] = 101
    with pytest.raises(llro.ConfigError, match="packet_loss_threshold"):
        llro.normalize_config(cfg)


def test_normalize_config_bool_coercion() -> None:
    cfg = make_routes_config()
    cfg["delete_preadded_routes"] = "false"
    cfg["debug"] = "yes"
    normalized = llro.normalize_config(cfg)
    assert normalized["delete_preadded_routes"] is False
    assert normalized["debug"] is True

    cfg = make_routes_config()
    cfg["systemd_logging"] = "maybe"
    with pytest.raises(llro.ConfigError, match="boolean"):
        llro.normalize_config(cfg)


def test_route_cmd_uses_128_prefix_for_ipv6() -> None:
    cfg = make_routes_config()
    cfg["monitor"] = ["2001:db8::1"]
    cfg["routes"][0]["probe_source"] = "fd00::1"
    cfg["routes"][0]["gateway"] = "fd00::fe"
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    route = optimizer.routes_by_name["wan_a"]
    cmd = optimizer._route_cmd("add", "2001:db8::1", route)
    assert "2001:db8::1/128" in cmd


def test_normalize_config_rejects_invalid_also_route_ip() -> None:
    cfg = make_routes_config()
    cfg["also_route"] = {"1.1.1.1": ["bad-ip"]}
    with pytest.raises(llro.ConfigError, match="valid IP address"):
        llro.normalize_config(cfg)


def test_normalize_config_rejects_invalid_route_ip() -> None:
    cfg = make_routes_config()
    cfg["routes"][0]["probe_source"] = "bad"
    with pytest.raises(llro.ConfigError, match="valid IP address"):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["routes"][0]["gateway"] = "bad"
    with pytest.raises(llro.ConfigError, match="valid IP address"):
        llro.normalize_config(cfg)


def test_normalize_config_rejects_invalid_device_name() -> None:
    cfg = make_routes_config()
    cfg["routes"][0]["device"] = "eth0!"
    with pytest.raises(llro.ConfigError, match="valid device name"):
        llro.normalize_config(cfg)


def test_normalize_config_rejects_non_positive_intervals_and_payload() -> None:
    cfg = make_routes_config()
    cfg["test_interval"] = 0
    with pytest.raises(llro.ConfigError, match="test_interval must be greater than 0"):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["scan_interval"] = -1
    with pytest.raises(llro.ConfigError, match="scan_interval must be greater than 0"):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["payload_size"] = 0
    with pytest.raises(llro.ConfigError, match="payload_size must be greater than 0"):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["ip_timeout"] = 0
    with pytest.raises(llro.ConfigError, match="ip_timeout must be greater than 0"):
        llro.normalize_config(cfg)


def test_normalize_config_rejects_relative_ip_bin() -> None:
    cfg = make_routes_config()
    cfg["ip_bin"] = "ip"
    with pytest.raises(llro.ConfigError, match="absolute path"):
        llro.normalize_config(cfg)


def test_run_ip_timeout_logs_distinct_error(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())

    def raise_timeout(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise subprocess.TimeoutExpired(cmd=["/usr/sbin/ip"], timeout=10)

    monkeypatch.setattr(llro.subprocess, "run", raise_timeout)
    caplog.set_level(logging.ERROR)
    ok, err = asyncio.run(optimizer._run_ip(["route", "show"]))
    assert ok is False
    assert err == "timeout"
    assert "timed out" in caplog.text


def test_run_async_clears_also_route_on_probe_failure_without_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = {
        "monitor": ["1.1.1.1"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
        ],
        "also_route": {"1.1.1.1": ["1.0.0.1"]},
        "test_count": 1,
        "scan_interval": 0.01,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a", "1.0.0.1": "wan_a"}
    cleared = []

    async def fake_multiping(_monitor: list[str], **_kwargs: object) -> list[SimpleNamespace]:
        return [make_host("1.1.1.1", False, 0, 100)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)

    async def fake_clear(host):  # type: ignore[no-untyped-def]
        cleared.append(host)

    monkeypatch.setattr(optimizer, "clear_route", fake_clear)

    async def fake_apply(_host, _route):  # type: ignore[no-untyped-def]
        return True

    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert "1.1.1.1" in cleared
    assert "1.0.0.1" in cleared


def test_clear_route_drops_current_route_tracking(monkeypatch: pytest.MonkeyPatch) -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
    optimizer.current_routes["1.1.1.1"] = "wan_a"

    async def fake_run_ip(_args):  # type: ignore[no-untyped-def]
        return True, ""

    monkeypatch.setattr(optimizer, "_run_ip", fake_run_ip)
    asyncio.run(optimizer.clear_route("1.1.1.1"))
    assert "1.1.1.1" not in optimizer.current_routes


def test_missing_destinations_reads_kernel_table(monkeypatch: pytest.MonkeyPatch) -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
    monkeypatch.setattr(
        llro.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps([{"dst": "1.1.1.1"}, {"dst": "default"}, {"dst": "10.0.0.0/24"}]),
            stderr="",
        ),
    )
    assert asyncio.run(optimizer._missing_destinations(["1.1.1.1", "8.8.8.8"])) == ["8.8.8.8"]

    monkeypatch.setattr(
        llro.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    assert asyncio.run(optimizer._missing_destinations(["1.1.1.1"])) == ["1.1.1.1"]

    monkeypatch.setattr(
        llro.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=2, stdout="", stderr="failed"),
    )
    assert asyncio.run(optimizer._missing_destinations(["1.1.1.1"])) == []

    monkeypatch.setattr(
        llro.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="not-json", stderr=""),
    )
    assert asyncio.run(optimizer._missing_destinations(["1.1.1.1"])) == []


def test_run_async_reapplies_route_missing_from_kernel(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = {
        "monitor": ["1.1.1.1"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
            {"name": "wan_b", "device": "eth1", "probe_source": "10.0.0.2", "gateway": "10.0.1.254"},
        ],
        "test_count": 1,
        "rtt_threshold": 50,
        "scan_interval": 0.01,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a"}
    applied = []

    async def fake_multiping(_monitor: list[str], **kwargs: object) -> list[SimpleNamespace]:
        if kwargs["source"] == "10.0.0.1":
            return [make_host("1.1.1.1", True, 100, 0)]
        return [make_host("1.1.1.1", True, 90, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)

    async def fake_apply(host, route):  # type: ignore[no-untyped-def]
        applied.append((host, route))
        return True

    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

    async def fake_missing(destinations):  # type: ignore[no-untyped-def]
        return list(destinations)

    monkeypatch.setattr(optimizer, "_missing_destinations", fake_missing)

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert applied == [("1.1.1.1", "wan_a")]


def test_run_async_recovers_route_cleared_during_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
    optimizer.current_routes = {"1.1.1.1": "wan_a"}
    applied = []
    cleared = []
    iterations = {"count": 0}

    async def fake_multiping(_monitor: list[str], **_kwargs: object) -> list[SimpleNamespace]:
        alive = iterations["count"] > 0
        return [make_host("1.1.1.1", alive, 10 if alive else 0, 0 if alive else 100)]

    async def fake_sleep(_seconds: float) -> None:
        iterations["count"] += 1
        if iterations["count"] > 1:
            raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)

    async def fake_run_ip(_args):  # type: ignore[no-untyped-def]
        return True, ""

    monkeypatch.setattr(optimizer, "_run_ip", fake_run_ip)

    async def fake_apply(host, route):  # type: ignore[no-untyped-def]
        applied.append((host, route))
        return True

    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

    real_clear_route = optimizer.clear_route

    async def tracked_clear(host: str) -> None:
        cleared.append(host)
        await real_clear_route(host)

    monkeypatch.setattr(optimizer, "clear_route", tracked_clear)

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert "1.1.1.1" in cleared
    assert applied == [("1.1.1.1", "wan_a")]


def test_probe_socket_class_binds_to_device(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    class FakeSock:
        def setsockopt(self, level, optname, value):  # type: ignore[no-untyped-def]
            captured["opt"] = (level, optname, value)

        def close(self) -> None:
            pass

    monkeypatch.setattr(llro.ICMPv4Socket, "_create_socket", lambda _self, _type: FakeSock())
    sock_cls = llro._probe_socket_class(False, "eth0")
    assert issubclass(sock_cls, llro.ICMPv4Socket)
    sock_cls()
    import socket as stdlib_socket

    assert captured["opt"] == (stdlib_socket.SOL_SOCKET, stdlib_socket.SO_BINDTODEVICE, b"eth0")

    assert llro._probe_socket_class(False, None) is llro.ICMPv4Socket
    assert issubclass(llro._probe_socket_class(True, "eth0"), llro.ICMPv6Socket)


def test_run_async_bind_to_device_forwards_device(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = make_routes_config()
    cfg["bind_to_device"] = True
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    captured = {}

    async def fake_multiping(_monitor: list[str], **kwargs: object) -> list[SimpleNamespace]:
        captured.update(kwargs)
        return [make_host("1.1.1.1", True, 10, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)

    async def fake_apply(_host, _route):  # type: ignore[no-untyped-def]
        return True

    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert captured.get("device") == "eth0"
    assert captured.get("count") == 1
    assert captured.get("timeout") == 2.0


def test_normalize_config_test_count_alias_and_probe_options() -> None:
    cfg = make_routes_config()
    normalized = llro.normalize_config(cfg)
    assert normalized["pings_per_probe"] == 1
    assert normalized["decision_cycles"] == 1
    assert normalized["probe_timeout"] == 2.0
    assert normalized["bind_to_device"] is False
    assert normalized["ewma_alpha"] == 0.4
    assert normalized["switch_cooldown"] == 60

    cfg = make_routes_config()
    cfg["test_count"] = 5
    normalized = llro.normalize_config(cfg)
    assert normalized["pings_per_probe"] == 5
    assert normalized["decision_cycles"] == 5

    cfg["pings_per_probe"] = 2
    cfg["decision_cycles"] = 4
    normalized = llro.normalize_config(cfg)
    assert normalized["pings_per_probe"] == 2
    assert normalized["decision_cycles"] == 4


def test_normalize_config_rejects_invalid_probe_and_stability_options() -> None:
    cfg = make_routes_config()
    cfg["pings_per_probe"] = 0
    with pytest.raises(llro.ConfigError, match="pings_per_probe"):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["decision_cycles"] = 0
    with pytest.raises(llro.ConfigError, match="decision_cycles"):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["ewma_alpha"] = 0
    with pytest.raises(llro.ConfigError, match="ewma_alpha"):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["ewma_alpha"] = 1.5
    with pytest.raises(llro.ConfigError, match="ewma_alpha"):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["switch_cooldown"] = -1
    with pytest.raises(llro.ConfigError, match="switch_cooldown"):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["probe_timeout"] = 0
    with pytest.raises(llro.ConfigError, match="probe_timeout"):
        llro.normalize_config(cfg)

    cfg = make_routes_config()
    cfg["bind_to_device"] = "maybe"
    with pytest.raises(llro.ConfigError, match="boolean"):
        llro.normalize_config(cfg)


def test_run_async_ewma_dampens_single_bad_loss_round(monkeypatch: pytest.MonkeyPatch) -> None:
    # One 60%-loss probe round on the current route: with alpha=0.4 the smoothed
    # loss stays below the 50% threshold and no switch happens.
    cfg = {
        "monitor": ["1.1.1.1"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
            {"name": "wan_b", "device": "eth1", "probe_source": "10.0.0.2", "gateway": "10.0.1.254"},
        ],
        "pings_per_probe": 1,
        "decision_cycles": 1,
        "packet_loss_threshold": 50,
        "rtt_threshold": 20,
        "ewma_alpha": 0.4,
        "switch_cooldown": 0,
        "scan_interval": 0.01,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a"}
    optimizer._ewma["1.1.1.1"] = {"wan_a": {"rtt": 40.0, "loss": 0.0}, "wan_b": {"rtt": 60.0, "loss": 0.0}}
    applied = []

    async def fake_multiping(_monitor: list[str], **kwargs: object) -> list[SimpleNamespace]:
        if kwargs["source"] == "10.0.0.1":
            return [make_host("1.1.1.1", True, 40, 0.6)]
        return [make_host("1.1.1.1", True, 60, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    async def fake_missing(_destinations):  # type: ignore[no-untyped-def]
        return []

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(optimizer, "_missing_destinations", fake_missing)

    async def fake_apply(host, route):  # type: ignore[no-untyped-def]
        applied.append((host, route))
        return True

    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert applied == []
    assert optimizer._ewma["1.1.1.1"]["wan_a"]["loss"] == pytest.approx(24.0)


def test_run_async_switch_cooldown_suppresses_improvement(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = {
        "monitor": ["1.1.1.1"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
            {"name": "wan_b", "device": "eth1", "probe_source": "10.0.0.2", "gateway": "10.0.1.254"},
        ],
        "pings_per_probe": 1,
        "decision_cycles": 1,
        "rtt_threshold": 20,
        "ewma_alpha": 1.0,
        "switch_cooldown": 60,
        "scan_interval": 0.01,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a"}
    optimizer._last_switch_at["1.1.1.1"] = llro.time.monotonic()
    applied = []

    async def fake_multiping(_monitor: list[str], **kwargs: object) -> list[SimpleNamespace]:
        if kwargs["source"] == "10.0.0.1":
            return [make_host("1.1.1.1", True, 100, 0)]
        return [make_host("1.1.1.1", True, 10, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    async def fake_missing(_destinations):  # type: ignore[no-untyped-def]
        return []

    async def fake_apply(host, route):  # type: ignore[no-untyped-def]
        applied.append((host, route))
        return True

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(optimizer, "_missing_destinations", fake_missing)
    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert applied == []


def test_run_async_switch_cooldown_does_not_block_loss_failover(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = {
        "monitor": ["1.1.1.1"],
        "routes": [
            {"name": "wan_a", "device": "eth0", "probe_source": "10.0.0.1", "gateway": "10.0.0.254"},
            {"name": "wan_b", "device": "eth1", "probe_source": "10.0.0.2", "gateway": "10.0.1.254"},
        ],
        "pings_per_probe": 1,
        "decision_cycles": 1,
        "packet_loss_threshold": 5,
        "ewma_alpha": 1.0,
        "switch_cooldown": 60,
        "scan_interval": 0.01,
    }
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a"}
    optimizer._last_switch_at["1.1.1.1"] = llro.time.monotonic()
    applied = []

    async def fake_multiping(_monitor: list[str], **kwargs: object) -> list[SimpleNamespace]:
        if kwargs["source"] == "10.0.0.1":
            return [make_host("1.1.1.1", True, 40, 50)]
        return [make_host("1.1.1.1", True, 50, 0)]

    async def fake_sleep(_seconds: float) -> None:
        raise StopLoop()

    async def fake_apply(host, route):  # type: ignore[no-untyped-def]
        applied.append((host, route))
        return True

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)
    monkeypatch.setattr(llro.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(optimizer, "apply_route_config", fake_apply)

    with pytest.raises(StopLoop):
        asyncio.run(optimizer.run_async())

    assert ("1.1.1.1", "wan_b") in applied
    assert optimizer._last_switch_at["1.1.1.1"] > 0


def test_async_multiping_collects_rtts(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeAsyncSocket:
        def __init__(self, icmp_sock):  # type: ignore[no-untyped-def]
            self._icmp_sock = icmp_sock

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_args):  # type: ignore[no-untyped-def]
            return False

        def send(self, _request):  # type: ignore[no-untyped-def]
            pass

        async def receive(self, request, timeout=2):  # type: ignore[no-untyped-def]
            return SimpleNamespace(time=request.time + 0.01, raise_for_status=lambda: None)

    class FakeICMPSock:
        def __init__(self, address=None, privileged=True):  # type: ignore[no-untyped-def]
            pass

        def close(self) -> None:
            pass

    monkeypatch.setattr(llro, "AsyncSocket", FakeAsyncSocket)
    monkeypatch.setattr(llro, "ICMPv4Socket", FakeICMPSock)

    hosts = asyncio.run(llro.async_multiping(["1.1.1.1"], count=2, interval=0, timeout=1, payload_size=56))
    assert hosts[0].is_alive
    assert hosts[0].packets_sent == 2
    assert hosts[0].avg_rtt == pytest.approx(10.0)


def test_async_probe_host_counts_failed_replies(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeAsyncSocket:
        def __init__(self, icmp_sock):  # type: ignore[no-untyped-def]
            self._icmp_sock = icmp_sock

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_args):  # type: ignore[no-untyped-def]
            return False

        def send(self, _request):  # type: ignore[no-untyped-def]
            pass

        async def receive(self, request=None, timeout=2):  # type: ignore[no-untyped-def]
            raise llro.ICMPLibError("timeout")

    class FakeICMPSock:
        def __init__(self, address=None, privileged=True):  # type: ignore[no-untyped-def]
            pass

        def close(self) -> None:
            pass

    monkeypatch.setattr(llro, "AsyncSocket", FakeAsyncSocket)
    monkeypatch.setattr(llro, "ICMPv4Socket", FakeICMPSock)

    host = asyncio.run(
        llro._async_probe_host(
            "1.1.1.1",
            count=1,
            interval=0,
            timeout=1,
            payload_size=56,
            source=None,
            device=None,
            privileged=True,
        )
    )
    assert not host.is_alive
    assert host.packets_sent == 1
