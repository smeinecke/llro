#!/usr/bin/env python3
import argparse
import json
import socket
import sys
from typing import Any, Dict, List

from llro import DEFAULT_ADMIN_SOCKET_PATH


def _send_request(socket_path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    message = (json.dumps(payload) + "\n").encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        try:
            client.connect(socket_path)
        except OSError as exc:
            raise RuntimeError("failed to connect to %s: %s" % (socket_path, exc))

        client.sendall(message)
        chunks = []
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)

    if not chunks:
        raise RuntimeError("empty response from daemon")

    try:
        return json.loads(b"".join(chunks).decode("utf-8").strip())
    except ValueError as exc:
        raise RuntimeError("invalid response from daemon: %s" % exc)


def _format_status_table(hosts: List[Dict[str, Any]]) -> str:
    lines = []
    for item in hosts:
        host = item.get("host")
        mode = item.get("mode")
        current_route = item.get("current_route") or "-"
        override_route = item.get("override_route") or "-"
        switching_enabled = "yes" if item.get("switching_enabled") else "no"
        lines.append(
            "Host %s | mode=%s | switching=%s | current=%s | override=%s"
            % (host, mode, switching_enabled, current_route, override_route)
        )

        routes = item.get("routes") or {}
        if not routes:
            lines.append("  (no probe data yet)")
            continue

        route_names = sorted(routes.keys())
        for route_name in route_names:
            route_data = routes[route_name]
            avg_rtt = route_data.get("avg_rtt")
            avg_loss = route_data.get("avg_loss")
            is_alive = "yes" if route_data.get("is_alive") else "no"
            lines.append(
                "  %s: rtt=%s ms, loss=%s%%, alive=%s" % (route_name, avg_rtt, avg_loss, is_alive)
            )
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llro-cli",
        description="Admin client for LLRO daemon over Unix socket",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    status = subparsers.add_parser("status", help="show daemon routing status")
    status.add_argument("--socket", default=DEFAULT_ADMIN_SOCKET_PATH, help="admin socket path")
    status.add_argument("--json", action="store_true", dest="as_json", help="print raw JSON")

    override = subparsers.add_parser("override", help="override route for a host")
    override.add_argument("--socket", default=DEFAULT_ADMIN_SOCKET_PATH, help="admin socket path")
    override.add_argument("--host", required=True, help="monitored host to control")
    override.add_argument("--route", required=True, help="route name to pin")

    disable_switching = subparsers.add_parser("disable-switching", help="disable route switching")
    disable_switching.add_argument("--socket", default=DEFAULT_ADMIN_SOCKET_PATH, help="admin socket path")
    target_disable = disable_switching.add_mutually_exclusive_group(required=True)
    target_disable.add_argument("--host", help="disable switching for one monitored host")
    target_disable.add_argument("--all", action="store_true", help="disable switching for all monitored hosts")

    reset_auto = subparsers.add_parser("reset-auto", help="reset control mode back to auto routing")
    reset_auto.add_argument("--socket", default=DEFAULT_ADMIN_SOCKET_PATH, help="admin socket path")
    target_reset = reset_auto.add_mutually_exclusive_group(required=True)
    target_reset.add_argument("--host", help="reset one monitored host")
    target_reset.add_argument("--all", action="store_true", help="reset all monitored hosts")

    return parser


def _make_payload(args: argparse.Namespace) -> Dict[str, Any]:
    if args.command == "status":
        return {"action": "status"}

    if args.command == "override":
        return {"action": "override", "host": args.host, "route": args.route}

    if args.command == "disable-switching":
        payload = {"action": "disable_switching"}  # type: Dict[str, Any]
        if args.all:
            payload["all"] = True
        else:
            payload["host"] = args.host
        return payload

    if args.command == "reset-auto":
        payload = {"action": "reset_auto"}  # type: Dict[str, Any]
        if args.all:
            payload["all"] = True
        else:
            payload["host"] = args.host
        return payload

    raise RuntimeError("unknown command")


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    payload = _make_payload(args)

    try:
        response = _send_request(args.socket, payload)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

    if not response.get("ok"):
        print(response.get("error") or "request failed", file=sys.stderr)
        sys.exit(1)

    if args.command == "status":
        data = response.get("data") or {}
        if args.as_json:
            print(json.dumps(data, indent=2, sort_keys=True))
            return
        print(_format_status_table(data.get("hosts") or []))
        return

    data = response.get("data") or {}
    print(json.dumps(data, sort_keys=True))


if __name__ == "__main__":
    main()
