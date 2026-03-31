import json
import socket
import threading

import pytest

import llro_cli


def test_make_payload_override() -> None:
    parser = llro_cli._build_parser()
    args = parser.parse_args(["override", "--host", "1.1.1.1", "--route", "wan_a"])
    payload = llro_cli._make_payload(args)
    assert payload == {"action": "override", "host": "1.1.1.1", "route": "wan_a"}


def test_make_payload_disable_all() -> None:
    parser = llro_cli._build_parser()
    args = parser.parse_args(["disable-switching", "--all"])
    payload = llro_cli._make_payload(args)
    assert payload == {"action": "disable_switching", "all": True}


def test_send_request_roundtrip(tmp_path) -> None:  # type: ignore[no-untyped-def]
    sock_path = str(tmp_path / "admin.sock")
    received = {}
    server_ready = threading.Event()

    def server() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
            srv.bind(sock_path)
            srv.listen(1)
            server_ready.set()
            conn, _ = srv.accept()
            with conn:
                data = b""
                while not data.endswith(b"\n"):
                    part = conn.recv(4096)
                    if not part:
                        break
                    data += part
                received.update(json.loads(data.decode("utf-8").strip()))
                conn.sendall(b'{"ok": true, "data": {"hello": "world"}}\n')

    thread = threading.Thread(target=server)
    thread.start()
    try:
        assert server_ready.wait(timeout=5), "server did not start in time"
        response = llro_cli._send_request(sock_path, {"action": "status"})
    finally:
        thread.join(timeout=5)

    assert received["action"] == "status"
    assert response["ok"] is True
    assert response["data"]["hello"] == "world"


def test_send_request_connect_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    class TimeoutSocket:
        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, _exc_type, _exc, _tb):  # type: ignore[no-untyped-def]
            return False

        def settimeout(self, _value: float) -> None:
            return None

        def connect(self, _path: str) -> None:
            raise socket.timeout()

    monkeypatch.setattr(llro_cli.socket, "socket", lambda *_args, **_kwargs: TimeoutSocket())
    with pytest.raises(RuntimeError) as exc:
        llro_cli._send_request("/tmp/admin.sock", {"action": "status"}, timeout_seconds=0.1)
    assert "timed out" in str(exc.value)


def test_main_status_table_output(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(
        llro_cli,
        "_send_request",
        lambda _socket, _payload: {
            "ok": True,
            "data": {
                "hosts": [
                    {
                        "host": "1.1.1.1",
                        "mode": "auto",
                        "switching_enabled": True,
                        "current_route": "wan_a",
                        "override_route": None,
                        "routes": {"wan_a": {"avg_rtt": 12.3, "avg_loss": 0, "is_alive": True}},
                    }
                ]
            },
        },
    )
    monkeypatch.setattr("sys.argv", ["llro-cli", "status"])
    llro_cli.main()
    out = capsys.readouterr().out
    assert "Host 1.1.1.1" in out
    assert "wan_a: rtt=12.3 ms" in out


def test_main_status_json_output(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(llro_cli, "_send_request", lambda _socket, _payload: {"ok": True, "data": {"hosts": []}})
    monkeypatch.setattr("sys.argv", ["llro-cli", "status", "--json"])
    llro_cli.main()
    out = capsys.readouterr().out
    assert '"hosts": []' in out


def test_main_returns_nonzero_on_daemon_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(llro_cli, "_send_request", lambda _socket, _payload: {"ok": False, "error": "boom"})
    monkeypatch.setattr("sys.argv", ["llro-cli", "status"])
    with pytest.raises(SystemExit) as exc:
        llro_cli.main()
    assert exc.value.code == 1
