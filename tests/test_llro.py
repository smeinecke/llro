import asyncio
import json
import logging
import os
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
    ok, err = optimizer._run_ip(["route", "show"])
    assert ok is False
    assert "boom" in err

    monkeypatch.setattr(
        llro.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="shown", stderr=""),
    )
    ok, err = optimizer._run_ip(["route", "show"])
    assert ok is True
    assert err == ""

    monkeypatch.setattr(
        llro.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=3, stdout="", stderr=""),
    )
    ok, err = optimizer._run_ip(["route", "show"])
    assert ok is False
    assert "exit code 3" in err


def test_clear_route_logs_error_for_unexpected_failure(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
    monkeypatch.setattr(optimizer, "_run_ip", lambda _args: (False, "permission denied"))
    caplog.set_level(logging.ERROR)
    optimizer.clear_route("1.1.1.1")
    assert "Failed to remove route for 1.1.1.1" in caplog.text


def test_apply_route_config_logs_errors(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())

    caplog.set_level(logging.ERROR)
    optimizer.apply_route_config("1.1.1.1", "missing")
    assert "Unknown route 'missing'" in caplog.text

    calls = {"count": 0}

    def fail_add_then_replace(_args):  # type: ignore[no-untyped-def]
        calls["count"] += 1
        if calls["count"] == 1:
            return False, "unexpected add failure"
        return False, "replace failed"

    monkeypatch.setattr(optimizer, "_run_ip", fail_add_then_replace)
    optimizer.current_routes["1.1.1.1"] = "wan_a"
    optimizer.apply_route_config("1.1.1.1", "wan_a")
    assert "Failed to replace route for 1.1.1.1" in caplog.text

    optimizer.current_routes.clear()
    optimizer.apply_route_config("1.1.1.1", "wan_a")
    assert "Failed to add route for 1.1.1.1" in caplog.text


def test_clear_routes_applies_fallback_and_clears_tracking(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = make_routes_config()
    cfg["also_route"] = {"1.1.1.1": ["1.0.0.1"]}
    cfg["fallback_routes"] = {"1.1.1.1": "wan_a"}
    optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
    optimizer.current_routes = {"1.1.1.1": "wan_a", "1.0.0.1": "wan_a"}
    cleared = []
    applied = []
    monkeypatch.setattr(optimizer, "clear_route", lambda host: cleared.append(host))
    monkeypatch.setattr(optimizer, "apply_route_config", lambda host, route: applied.append((host, route)))
    optimizer.clear_routes()
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

    async def fake_multiping(_monitor: List[str], **_kwargs: object) -> List[SimpleNamespace]:
        probe_calls["count"] += 1
        return [make_host("1.1.1.1", True, 10, 0)]

    monkeypatch.setattr(llro, "async_multiping", fake_multiping)

    async def runner() -> None:
        stop_event = asyncio.Event()

        async def fake_wait_for(awaitable, timeout):  # type: ignore[no-untyped-def]
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
