"""Fault injection: dependencies misbehaving at system boundaries.

Covers the failure modes the existing suite leaves untested: daemon socket
faults, subprocess failures in route listing/apply, admin protocol edge
cases, and negative paths — asserting observable effects, not just that a
call didn't raise.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import llro  # noqa: E402
import llro_cli  # noqa: E402


def make_routes_config() -> dict:
    return {
        "monitor": ["1.1.1.1"],
        "routes": [
            {
                "name": "wan_a",
                "device": "eth0",
                "probe_source": "10.0.0.1",
                "gateway": "10.0.0.254",
            },
            {
                "name": "wan_b",
                "device": "eth1",
                "probe_source": "10.0.0.2",
                "gateway": "10.0.1.254",
            },
        ],
        "test_count": 1,
        "test_interval": 0.01,
        "scan_interval": 0.01,
        "rtt_threshold": 20,
        "packet_loss_threshold": 5,
    }


class _FakeSocket:
    """Configurable fake UNIX socket for _send_request tests."""

    connect_exc: Exception | None = None
    send_exc: Exception | None = None
    recv_chunks: list[bytes] | None = None
    recv_exc: Exception | None = None

    def __init__(self) -> None:
        self._recv_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def settimeout(self, _v):
        return None

    def connect(self, _path):
        if self.connect_exc:
            raise self.connect_exc

    def sendall(self, _msg):
        if self.send_exc:
            raise self.send_exc

    def recv(self, _n):
        self._recv_calls += 1
        if self.recv_exc:
            raise self.recv_exc
        if self.recv_chunks:
            return self.recv_chunks.pop(0)
        return b""


def _patched_socket(monkeypatch: pytest.MonkeyPatch, **kwargs) -> _FakeSocket:
    fake = _FakeSocket()
    for k, v in kwargs.items():
        setattr(fake, k, v)
    monkeypatch.setattr(llro_cli.socket, "socket", lambda *_a, **_kw: fake)
    return fake


class TestSendRequestFaults:
    def test_missing_socket_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patched_socket(monkeypatch, connect_exc=FileNotFoundError("no such file"))
        with pytest.raises(RuntimeError, match="failed to connect"):
            llro_cli._send_request("/tmp/missing.sock", {"action": "status"})

    def test_send_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patched_socket(monkeypatch, send_exc=BrokenPipeError("gone"))
        with pytest.raises(RuntimeError, match="failed to send"):
            llro_cli._send_request("/tmp/x.sock", {"action": "status"})

    def test_empty_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patched_socket(monkeypatch)
        with pytest.raises(RuntimeError, match="empty response"):
            llro_cli._send_request("/tmp/x.sock", {"action": "status"})

    def test_malformed_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patched_socket(monkeypatch, recv_chunks=[b"this is not json"])
        with pytest.raises(RuntimeError, match="invalid response"):
            llro_cli._send_request("/tmp/x.sock", {"action": "status"})

    def test_read_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patched_socket(monkeypatch, recv_exc=TimeoutError())
        with pytest.raises(RuntimeError, match="timed out"):
            llro_cli._send_request("/tmp/x.sock", {"action": "status"})

    def test_partial_response_still_parsed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A response arriving in fragments must be reassembled and parsed."""
        _patched_socket(monkeypatch, recv_chunks=[b'{"ok": tr', b'ue, "data"', b": {}}"])
        assert llro_cli._send_request("/tmp/x.sock", {"action": "status"}) == {"ok": True, "data": {}}


class TestMissingDestinations:
    def _optimizer(self) -> llro.LowestLatencyRoutesOptimizer:
        return llro.LowestLatencyRoutesOptimizer(make_routes_config())

    def _run(self, optimizer, monkeypatch: pytest.MonkeyPatch, **kwargs) -> list[str]:
        monkeypatch.setattr(llro.subprocess, "run", kwargs.get("subprocess_run"))
        return asyncio.run(optimizer._missing_destinations(["1.1.1.1"]))

    def test_subprocess_exception_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        optimizer = self._optimizer()
        calls = []

        def boom(*_a, **_kw):
            calls.append(1)
            raise OSError("ip binary missing")

        result = self._run(optimizer, monkeypatch, subprocess_run=boom)
        assert result == []
        assert calls == [1], "ip binary must have been invoked"

    def test_nonzero_exit_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        optimizer = self._optimizer()

        def fail(*_a, **_kw):
            return SimpleNamespace(returncode=1, stdout="", stderr="RTNETLINK error")

        assert self._run(optimizer, monkeypatch, subprocess_run=fail) == []

    def test_malformed_json_output_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        optimizer = self._optimizer()

        def garbage(*_a, **_kw):
            return SimpleNamespace(returncode=0, stdout="<not json>", stderr="")

        assert self._run(optimizer, monkeypatch, subprocess_run=garbage) == []

    def test_entries_missing_dst_are_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        optimizer = self._optimizer()

        def partial(*_a, **_kw):
            return SimpleNamespace(
                returncode=0, stdout=json.dumps([{"gateway": "10.0.0.1"}, {"dst": "1.1.1.1/32"}]), stderr=""
            )

        # 1.1.1.1 exists in the table -> nothing missing
        assert self._run(optimizer, monkeypatch, subprocess_run=partial) == []

    def test_missing_destination_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        optimizer = self._optimizer()

        def ok(*_a, **_kw):
            return SimpleNamespace(returncode=0, stdout=json.dumps([{"dst": "9.9.9.9/32"}]), stderr="")

        assert self._run(optimizer, monkeypatch, subprocess_run=ok) == ["1.1.1.1"]


class TestApplyRouteConfig:
    def test_unknown_route_returns_false(self) -> None:
        optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
        assert asyncio.run(optimizer.apply_route_config("1.1.1.1", "nonexistent")) is False

    def test_ip_failure_reports_false_but_tracks_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())

        async def fail_run_ip(args):
            return False, "RTNETLINK answers: Network is unreachable"

        monkeypatch.setattr(optimizer, "_run_ip", fail_run_ip)
        assert asyncio.run(optimizer.apply_route_config("1.1.1.1", "wan_a")) is False
        assert optimizer.current_routes == {}, "failed apply must not mark routes as active"

    def test_file_exists_falls_through_to_replace(self, monkeypatch: pytest.MonkeyPatch) -> None:
        optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
        commands = []

        async def exists_then_ok(args):
            commands.append(args[1])
            if args[1] == "add":
                return False, "RTNETLINK answers: File exists"
            return True, ""

        monkeypatch.setattr(optimizer, "_run_ip", exists_then_ok)
        assert asyncio.run(optimizer.apply_route_config("1.1.1.1", "wan_b")) is True
        assert commands == ["add", "replace"]
        assert optimizer.current_routes["1.1.1.1"] == "wan_b"

    def test_partial_destination_failure_continues(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """One failing destination must not stop the remaining destinations."""
        cfg = make_routes_config()
        cfg["also_route"] = {"1.1.1.1": ["2.2.2.2"]}
        optimizer = llro.LowestLatencyRoutesOptimizer(cfg)
        attempted = []

        async def flaky(args):
            dest = args[2]
            attempted.append(dest)
            return (dest != "1.1.1.1/32"), "boom"

        monkeypatch.setattr(optimizer, "_run_ip", flaky)
        result = asyncio.run(optimizer.apply_route_config("1.1.1.1", "wan_a"))
        assert result is False
        assert set(attempted) == {"1.1.1.1/32", "2.2.2.2/32"}, "all destinations must be attempted"
        assert optimizer.current_routes.get("2.2.2.2") == "wan_a"


class TestClearRoute:
    def test_no_such_process_is_tolerated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
        optimizer.current_routes["1.1.1.1"] = "wan_a"

        async def no_proc(_args):
            return False, "RTNETLINK answers: No such process"

        monkeypatch.setattr(optimizer, "_run_ip", no_proc)
        asyncio.run(optimizer.clear_route("1.1.1.1"))
        assert "1.1.1.1" not in optimizer.current_routes

    def test_other_failure_keeps_route_tracking(self, monkeypatch: pytest.MonkeyPatch) -> None:
        optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
        optimizer.current_routes["1.1.1.1"] = "wan_a"

        async def perm_denied(_args):
            return False, "RTNETLINK answers: Operation not permitted"

        monkeypatch.setattr(optimizer, "_run_ip", perm_denied)
        asyncio.run(optimizer.clear_route("1.1.1.1"))
        assert optimizer.current_routes["1.1.1.1"] == "wan_a"


class TestAdminClientEdgeCases:
    def _serve(self, request_line: bytes, tmp_path: Path, name: str) -> dict:
        async def run() -> dict:
            optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
            sock_path = str(tmp_path / name)
            server = await asyncio.start_unix_server(optimizer._handle_admin_client, path=sock_path)
            reader, writer = await asyncio.open_unix_connection(path=sock_path)
            if request_line:
                writer.write(request_line)
                await writer.drain()
            writer.write_eof()  # half-close: EOF without data -> "empty request" path
            await writer.drain()
            response = await reader.readline()
            writer.close()
            await writer.wait_closed()
            server.close()
            await server.wait_closed()
            return json.loads(response.decode("utf-8"))

        return asyncio.run(run())

    def test_empty_request_rejected(self, tmp_path: Path) -> None:
        resp = self._serve(b"", tmp_path, "empty.sock")
        assert resp == {"ok": False, "error": "empty request"}

    def test_non_object_request_rejected(self, tmp_path: Path) -> None:
        resp = self._serve(b"[1, 2, 3]\n", tmp_path, "list.sock")
        assert resp["ok"] is False
        assert "JSON object" in resp["error"]

    def test_unknown_action_rejected(self, tmp_path: Path) -> None:
        resp = self._serve(b'{"action": "explode"}\n', tmp_path, "act.sock")
        assert resp["ok"] is False
        assert "unsupported action" in resp["error"]


class TestAdminActionNegativePaths:
    def test_override_unknown_route_rejected(self) -> None:
        optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
        resp = asyncio.run(optimizer._handle_admin_action({"action": "override", "host": "1.1.1.1", "route": "nope"}))
        assert resp["ok"] is False
        assert "unknown route" in resp["error"]

    def test_override_applies_route_and_reports_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())

        async def ok_apply(_host, _route):
            return True

        monkeypatch.setattr(optimizer, "apply_route_config", ok_apply)
        resp = asyncio.run(optimizer._handle_admin_action({"action": "override", "host": "1.1.1.1", "route": "wan_b"}))
        assert resp["ok"] is True
        assert resp["data"] == {"host": "1.1.1.1", "mode": "override", "route": "wan_b", "route_applied": True}
        assert optimizer.override_routes["1.1.1.1"] == "wan_b"

    def test_disable_switching_host_not_in_monitor_rejected(self) -> None:
        optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
        resp = asyncio.run(optimizer._handle_admin_action({"action": "disable_switching", "host": "9.9.9.9"}))
        assert resp["ok"] is False
        assert "host or all" in resp["error"]

    def test_disable_switching_all_and_reset(self) -> None:
        optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())
        resp = asyncio.run(optimizer._handle_admin_action({"action": "disable_switching", "all": True}))
        assert resp["ok"] is True
        assert optimizer.switching_enabled["1.1.1.1"] is False
        assert optimizer.route_modes["1.1.1.1"] == "frozen"

        resp = asyncio.run(optimizer._handle_admin_action({"action": "reset_auto", "all": True}))
        assert resp["ok"] is True
        assert optimizer.switching_enabled["1.1.1.1"] is True
        assert optimizer.route_modes["1.1.1.1"] == "auto"


class TestRunIpFailureModes:
    def test_nonzero_exit_returns_stderr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())

        def fail(*_a, **_kw):
            return SimpleNamespace(returncode=2, stdout="", stderr="RTNETLINK answers: Permission denied")

        monkeypatch.setattr(llro.subprocess, "run", fail)
        ok, err = asyncio.run(optimizer._run_ip(["route", "show"]))
        assert ok is False
        assert "Permission denied" in err

    def test_exception_returns_error_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        optimizer = llro.LowestLatencyRoutesOptimizer(make_routes_config())

        def boom(*_a, **_kw):
            raise FileNotFoundError("no ip binary")

        monkeypatch.setattr(llro.subprocess, "run", boom)
        ok, err = asyncio.run(optimizer._run_ip(["route", "show"]))
        assert ok is False
        assert "no ip binary" in err
