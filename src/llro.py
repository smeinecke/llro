#!/usr/bin/env python3
import argparse
import asyncio
import ipaddress
import json
import logging
import math
import os
import re
import shlex
import signal
import socket
import stat
import subprocess
import sys
import time
from typing import Any

import yaml
from icmplib import Host, ICMPLibError, ICMPRequest, is_ipv6_address
from icmplib.sockets import AsyncSocket, ICMPv4Socket, ICMPv6Socket
from icmplib.utils import unique_identifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)

DEFAULT_ADMIN_SOCKET_PATH = "/run/llro/admin.sock"


class ConfigError(ValueError):
    pass


def _as_float(value: Any, field_name: str) -> float:
    if isinstance(value, bool):
        raise ConfigError(f"{field_name} must be a number")
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{field_name} must be a number")
    if not math.isfinite(result):
        raise ConfigError(f"{field_name} must be a finite number")
    return result


def _as_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ConfigError(f"{field_name} must be an integer")
    if isinstance(value, float) and not value.is_integer():
        raise ConfigError(f"{field_name} must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        raise ConfigError(f"{field_name} must be an integer")


def _as_non_empty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{field_name} must be a non-empty string")
    return value.strip()


def _as_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "yes", "on", "1"):
            return True
        if lowered in ("false", "no", "off", "0"):
            return False
    raise ConfigError(f"{field_name} must be a boolean")


def _host_route_target(address: str) -> str:
    version = ipaddress.ip_address(address).version
    return f"{address}/{32 if version == 4 else 128}"


_DEVICE_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")


def _validate_ip_address(value: str, field_name: str) -> str:
    try:
        # Canonicalize so configured values always match the address form
        # reported back by icmplib (e.g. compressed lowercase IPv6).
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ConfigError(f"{field_name} must be a valid IP address, got '{value}'")


def _canonical_ip_or_value(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def _validate_device_name(value: str, field_name: str) -> str:
    if not _DEVICE_NAME_RE.match(value):
        raise ConfigError(f"{field_name} must be a valid device name, got '{value}'")
    return value


def _validate_absolute_path(value: str, field_name: str) -> str:
    if not os.path.isabs(value):
        raise ConfigError(f"{field_name} must be an absolute path, got '{value}'")
    return value


def _validate_ip_bin(value: str, field_name: str) -> str:
    _validate_absolute_path(value, field_name)
    if os.path.exists(value) and not os.access(value, os.X_OK):
        raise ConfigError(f"{field_name} is not executable: '{value}'")
    return value


def _normalize_monitor(config: dict[str, Any]) -> list[str]:
    monitor = config.get("monitor")
    if not isinstance(monitor, list) or not monitor:
        raise ConfigError("Config does not contain a non-empty monitor list")
    normalized = [
        _validate_ip_address(_as_non_empty_string(item, "monitor entry"), "monitor entry") for item in monitor
    ]
    if len(set(normalized)) != len(normalized):
        raise ConfigError("monitor contains duplicate entries")
    return normalized


def _normalize_also_route(config: dict[str, Any], monitor: list[str]) -> dict[str, list[str]]:
    raw_also_route = config.get("also_route", {})
    if not isinstance(raw_also_route, dict):
        raise ConfigError("also_route must be a mapping")

    monitor_set = set(monitor)
    seen_values = set()
    normalized = {}
    for host, mapped_hosts in raw_also_route.items():
        key = _validate_ip_address(_as_non_empty_string(host, "also_route key"), "also_route key")
        if key not in monitor_set:
            raise ConfigError(f"also_route key '{key}' must exist in monitor")
        if not isinstance(mapped_hosts, list):
            raise ConfigError("also_route values must be lists")
        normalized[key] = [
            _validate_ip_address(_as_non_empty_string(item, "also_route value"), "also_route value")
            for item in mapped_hosts
        ]
        for value in normalized[key]:
            if value in monitor_set:
                raise ConfigError(f"also_route value '{value}' must not be a monitored host")
            if value in seen_values:
                raise ConfigError(f"also_route value '{value}' is assigned to multiple hosts")
            seen_values.add(value)
    return normalized


def _normalize_routes(config: dict[str, Any]) -> list[dict[str, str]]:
    raw_routes = config.get("routes")
    routes = []

    if raw_routes is not None:
        if not isinstance(raw_routes, list) or not raw_routes:
            raise ConfigError("routes must be a non-empty list")
        for index, route in enumerate(raw_routes):
            if not isinstance(route, dict):
                raise ConfigError(f"routes[{index}] must be a mapping")
            name = _as_non_empty_string(route.get("name"), f"routes[{index}].name")
            device = _validate_device_name(
                _as_non_empty_string(route.get("device"), f"routes[{index}].device"),
                f"routes[{index}].device",
            )
            probe_source = _validate_ip_address(
                _as_non_empty_string(route.get("probe_source"), f"routes[{index}].probe_source"),
                f"routes[{index}].probe_source",
            )
            gateway = _validate_ip_address(
                _as_non_empty_string(route.get("gateway"), f"routes[{index}].gateway"),
                f"routes[{index}].gateway",
            )
            routes.append(
                {
                    "name": name,
                    "device": device,
                    "probe_source": probe_source,
                    "gateway": gateway,
                }
            )
        return routes

    # Backward compatibility: old interfaces model.
    raw_interfaces = config.get("interfaces")
    if not isinstance(raw_interfaces, dict) or not raw_interfaces:
        raise ConfigError("Config must contain either routes or interfaces")

    for device, probe_sources in raw_interfaces.items():
        dev_name = _validate_device_name(
            _as_non_empty_string(device, "interfaces key"),
            "interfaces key",
        )
        if not isinstance(probe_sources, list) or not probe_sources:
            raise ConfigError(f"interfaces[{dev_name}] must be a non-empty list")
        for probe_source in probe_sources:
            src = _validate_ip_address(
                _as_non_empty_string(probe_source, f"interfaces[{dev_name}] source"),
                f"interfaces[{dev_name}] source",
            )
            # Legacy behavior treated source and gateway as the same value.
            routes.append(
                {
                    "name": f"{dev_name}:{src}",
                    "device": dev_name,
                    "probe_source": src,
                    "gateway": src,
                }
            )
    return routes


def _normalize_fallback_routes(
    raw_fallback_routes: Any, monitor: list[str], routes: list[dict[str, str]]
) -> dict[str, str]:
    if raw_fallback_routes is None:
        return {}
    if not isinstance(raw_fallback_routes, dict):
        raise ConfigError("fallback_routes must be a mapping")

    route_names = {route["name"] for route in routes}
    by_probe_source = {}
    by_gateway = {}
    for route in routes:
        by_probe_source.setdefault(route["probe_source"], []).append(route["name"])
        by_gateway.setdefault(route["gateway"], []).append(route["name"])

    monitor_set = set(monitor)
    normalized = {}
    for host, route_ref in raw_fallback_routes.items():
        host_key = _validate_ip_address(_as_non_empty_string(host, "fallback_routes key"), "fallback_routes key")
        if host_key not in monitor_set:
            raise ConfigError(f"fallback_routes key '{host_key}' must exist in monitor")
        ref = _as_non_empty_string(route_ref, f"fallback_routes[{host_key}]")

        if ref in route_names:
            normalized[host_key] = ref
            continue
        ref_ip = _canonical_ip_or_value(ref)
        if ref_ip in by_probe_source and len(by_probe_source[ref_ip]) == 1:
            normalized[host_key] = by_probe_source[ref_ip][0]
            continue
        if ref_ip in by_gateway and len(by_gateway[ref_ip]) == 1:
            normalized[host_key] = by_gateway[ref_ip][0]
            continue
        raise ConfigError(f"fallback route '{ref}' for host '{host_key}' does not match a configured route")
    return normalized


def normalize_config(raw_config: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw_config, dict):
        raise ConfigError("Config must be a mapping")

    monitor = _normalize_monitor(raw_config)
    also_route = _normalize_also_route(raw_config, monitor)
    routes = _normalize_routes(raw_config)

    route_names = set()
    for route in routes:
        if route["name"] in route_names:
            raise ConfigError(f"Duplicate route name '{route['name']}'")
        route_names.add(route["name"])

    test_count_raw = raw_config.get("test_count")
    test_count = None
    if test_count_raw is not None:
        test_count = _as_int(test_count_raw, "test_count")
        if test_count <= 0:
            raise ConfigError("test_count must be greater than 0")
        logging.warning("test_count is deprecated; use pings_per_probe and decision_cycles instead")

    pings_per_probe = _as_int(
        raw_config.get("pings_per_probe", test_count if test_count is not None else 3),
        "pings_per_probe",
    )
    if pings_per_probe <= 0:
        raise ConfigError("pings_per_probe must be greater than 0")

    decision_cycles = _as_int(
        raw_config.get("decision_cycles", test_count if test_count is not None else 3),
        "decision_cycles",
    )
    if decision_cycles <= 0:
        raise ConfigError("decision_cycles must be greater than 0")

    packet_loss_threshold = _as_float(
        raw_config.get(
            "packet_loss_threshold",
            raw_config.get("paketloss_threshold", 5),
        ),
        "packet_loss_threshold",
    )

    test_interval = _as_float(raw_config.get("test_interval", 0.5), "test_interval")
    if test_interval <= 0:
        raise ConfigError("test_interval must be greater than 0")

    payload_size = _as_int(raw_config.get("payload_size", 56), "payload_size")
    if payload_size <= 0:
        raise ConfigError("payload_size must be greater than 0")
    if payload_size > 65507:
        raise ConfigError("payload_size must not exceed 65507")

    scan_interval = _as_float(raw_config.get("scan_interval", 10), "scan_interval")
    if scan_interval <= 0:
        raise ConfigError("scan_interval must be greater than 0")

    normalized = {
        "monitor": monitor,
        "also_route": also_route,
        "routes": routes,
        "fallback_routes": _normalize_fallback_routes(raw_config.get("fallback_routes"), monitor, routes),
        "rtt_threshold": _as_float(raw_config.get("rtt_threshold", 20), "rtt_threshold"),
        "packet_loss_threshold": packet_loss_threshold,
        # Keep legacy key to avoid breaking existing consumers/tests.
        "paketloss_threshold": packet_loss_threshold,
        "test_count": test_count if test_count is not None else pings_per_probe,
        "pings_per_probe": pings_per_probe,
        "decision_cycles": decision_cycles,
        "test_interval": test_interval,
        "payload_size": payload_size,
        "scan_interval": scan_interval,
        "delete_preadded_routes": _as_bool(raw_config.get("delete_preadded_routes", False), "delete_preadded_routes"),
        "ip_bin": _validate_ip_bin(_as_non_empty_string(raw_config.get("ip_bin", "/usr/sbin/ip"), "ip_bin"), "ip_bin"),
        "ip_timeout": _as_float(raw_config.get("ip_timeout", 10), "ip_timeout"),
        "probe_timeout": _as_float(raw_config.get("probe_timeout", 2.0), "probe_timeout"),
        "bind_to_device": _as_bool(raw_config.get("bind_to_device", False), "bind_to_device"),
        "ewma_alpha": _as_float(raw_config.get("ewma_alpha", 0.4), "ewma_alpha"),
        "switch_cooldown": _as_float(raw_config.get("switch_cooldown", 60), "switch_cooldown"),
        "admin_socket_path": _validate_absolute_path(
            _as_non_empty_string(raw_config.get("admin_socket_path", DEFAULT_ADMIN_SOCKET_PATH), "admin_socket_path"),
            "admin_socket_path",
        ),
        "systemd_logging": _as_bool(raw_config.get("systemd_logging", False), "systemd_logging"),
        "debug": _as_bool(raw_config.get("debug", False), "debug"),
    }

    if normalized["rtt_threshold"] < 0:
        raise ConfigError("rtt_threshold must be greater than or equal to 0")
    if not 0 <= normalized["packet_loss_threshold"] <= 100:
        raise ConfigError("packet_loss_threshold must be between 0 and 100")
    if normalized["ip_timeout"] <= 0:
        raise ConfigError("ip_timeout must be greater than 0")
    if normalized["probe_timeout"] <= 0:
        raise ConfigError("probe_timeout must be greater than 0")
    if not 0 < normalized["ewma_alpha"] <= 1:
        raise ConfigError("ewma_alpha must be in (0, 1]")
    if normalized["switch_cooldown"] < 0:
        raise ConfigError("switch_cooldown must be greater than or equal to 0")

    return normalized


def _probe_socket_class(is_ipv6: bool, device: str | None) -> type:
    base = ICMPv6Socket if is_ipv6 else ICMPv4Socket
    if not device:
        return base

    class BoundSocket(base):  # type: ignore[misc]
        def _create_socket(self, sock_type: int) -> socket.socket:
            sock = super()._create_socket(sock_type)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, device.encode())
            return sock

    return BoundSocket


async def _async_probe_host(
    address: str,
    *,
    count: int,
    interval: float,
    timeout: float,
    payload_size: int,
    source: str | None,
    device: str | None,
    privileged: bool,
) -> Host:
    sock_cls = _probe_socket_class(is_ipv6_address(address), device)
    request_id = unique_identifier()
    packets_sent = 0
    rtts: list[float] = []
    with AsyncSocket(sock_cls(source, privileged)) as sock:
        for sequence in range(count):
            if sequence > 0:
                await asyncio.sleep(interval)
            request = ICMPRequest(
                destination=address,
                id=request_id,
                sequence=sequence,
                payload_size=payload_size,
            )
            try:
                sock.send(request)
                packets_sent += 1
                reply = await sock.receive(request, timeout)  # pyright: ignore[reportArgumentType]
                reply.raise_for_status()
                rtts.append((reply.time - request.time) * 1000)
            except ICMPLibError:
                pass
    return Host(address, packets_sent, rtts)


async def async_multiping(
    addresses: list[str],
    *,
    count: int,
    interval: float,
    timeout: float,
    payload_size: int,
    source: str | None = None,
    device: str | None = None,
    privileged: bool = True,
) -> list[Host]:
    return list(
        await asyncio.gather(
            *(
                _async_probe_host(
                    address,
                    count=count,
                    interval=interval,
                    timeout=timeout,
                    payload_size=payload_size,
                    source=source,
                    device=device,
                    privileged=privileged,
                )
                for address in addresses
            )
        )
    )


class LowestLatencyRoutesOptimizer:
    def __init__(self, config: dict[str, Any]):
        self.config = normalize_config(config)
        self.routes: list[dict[str, str]] = self.config["routes"]
        self.routes_by_name: dict[str, dict[str, str]] = {route["name"]: route for route in self.routes}
        self.current_routes: dict[str, str] = {}
        self.route_modes: dict[str, str] = dict.fromkeys(self.config["monitor"], "auto")
        self.override_routes: dict[str, str] = {}
        self.switching_enabled: dict[str, bool] = dict.fromkeys(self.config["monitor"], True)
        self.last_probe_snapshot: dict[str, dict[str, dict[str, Any]]] = {}
        self._ewma: dict[str, dict[str, dict[str, float]]] = {}
        self._last_switch_at: dict[str, float] = {}
        self._state_lock: asyncio.Lock | None = None
        self._admin_server: asyncio.base_events.Server | None = None

    def _get_state_lock(self) -> asyncio.Lock:
        if self._state_lock is None:
            self._state_lock = asyncio.Lock()
        return self._state_lock

    def _destinations_for_host(self, host: str) -> list[str]:
        return [host] + self.config.get("also_route", {}).get(host, [])

    def run(self):
        """
        Runs the main loop

        Parameters:
            None

        Returns:
            None
        """
        asyncio.run(self.run_service())

    async def run_service(self) -> None:
        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        can_handle_signals = hasattr(loop, "add_signal_handler")

        if can_handle_signals:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, stop_event.set)

        await self._start_admin_server()
        try:
            if self.config.get("delete_preadded_routes"):
                await self.clear_routes()
            await self.run_async(stop_event)
        finally:
            if can_handle_signals:
                for sig in (signal.SIGINT, signal.SIGTERM):
                    loop.remove_signal_handler(sig)
            await self._stop_admin_server()

    async def _start_admin_server(self) -> None:
        socket_path = self.config["admin_socket_path"]
        socket_dir = os.path.dirname(socket_path)
        if socket_dir:
            os.makedirs(socket_dir, exist_ok=True)

        if os.path.exists(socket_path):
            mode = os.stat(socket_path).st_mode
            if stat.S_ISSOCK(mode):
                os.unlink(socket_path)
            else:
                raise RuntimeError(f"admin_socket_path exists and is not a socket: {socket_path}")

        self._admin_server = await asyncio.start_unix_server(self._handle_admin_client, path=socket_path)
        os.chmod(socket_path, 0o600)
        logging.info("Admin socket listening at %s", socket_path)

    async def _stop_admin_server(self) -> None:
        if self._admin_server is not None:
            self._admin_server.close()
            await self._admin_server.wait_closed()
            self._admin_server = None

        socket_path = self.config["admin_socket_path"]
        if os.path.exists(socket_path):
            mode = os.stat(socket_path).st_mode
            if stat.S_ISSOCK(mode):
                os.unlink(socket_path)

    async def _handle_admin_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        response = {"ok": False, "error": "empty request"}
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=30)
            if line:
                try:
                    request = json.loads(line.decode("utf-8"))
                except ValueError:
                    response = {"ok": False, "error": "invalid JSON request"}
                else:
                    response = await self._handle_admin_action(request)
        except Exception as exc:
            logging.exception("Admin request failed")
            response = {"ok": False, "error": str(exc) or type(exc).__name__}

        try:
            writer.write((json.dumps(response) + "\n").encode("utf-8"))
            await writer.drain()
        except OSError:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    async def _build_status_data(self) -> dict[str, Any]:
        async with self._get_state_lock():
            hosts = []
            for host in self.config["monitor"]:
                routes_data = {name: dict(data) for name, data in self.last_probe_snapshot.get(host, {}).items()}
                for name, smoothed in self._ewma.get(host, {}).items():
                    entry = routes_data.setdefault(name, {})
                    entry["ewma_rtt"] = round(smoothed["rtt"], 3)
                    entry["ewma_loss"] = round(smoothed["loss"], 3)
                hosts.append(
                    {
                        "host": host,
                        "mode": self.route_modes.get(host, "auto"),
                        "switching_enabled": bool(self.switching_enabled.get(host, True)),
                        "current_route": self.current_routes.get(host),
                        "override_route": self.override_routes.get(host),
                        "routes": routes_data,
                    }
                )
        return {"hosts": hosts}

    async def _handle_admin_action(self, request: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(request, dict):
            return {"ok": False, "error": "request must be a JSON object"}

        action = request.get("action")
        if action == "status":
            return {"ok": True, "data": await self._build_status_data()}

        if action == "override":
            host = request.get("host")
            route = request.get("route")
            if not isinstance(host, str) or not isinstance(route, str):
                return {"ok": False, "error": "host and route must be strings"}
            host = _canonical_ip_or_value(host)
            if host not in self.config["monitor"]:
                return {"ok": False, "error": f"unknown host '{host}'"}
            if route not in self.routes_by_name:
                return {"ok": False, "error": f"unknown route '{route}'"}
            async with self._get_state_lock():
                self.route_modes[host] = "override"
                self.switching_enabled[host] = True
                self.override_routes[host] = route
            applied = await self.apply_route_config(host, route)
            return {
                "ok": True,
                "data": {"host": host, "mode": "override", "route": route, "route_applied": applied},
            }

        if action == "disable_switching":
            targets = self._resolve_targets(request)
            if targets is None:
                return {"ok": False, "error": "set either host or all=true"}
            async with self._get_state_lock():
                for host in targets:
                    self.switching_enabled[host] = False
                    if self.route_modes.get(host) != "override":
                        self.route_modes[host] = "frozen"
            return {"ok": True, "data": {"hosts": targets, "mode": "frozen"}}

        if action == "reset_auto":
            targets = self._resolve_targets(request)
            if targets is None:
                return {"ok": False, "error": "set either host or all=true"}
            async with self._get_state_lock():
                for host in targets:
                    self.switching_enabled[host] = True
                    self.route_modes[host] = "auto"
                    self.override_routes.pop(host, None)
            return {"ok": True, "data": {"hosts": targets, "mode": "auto"}}

        return {"ok": False, "error": f"unsupported action '{action}'"}

    def _resolve_targets(self, request: dict[str, Any]) -> list[str] | None:
        if request.get("all") is True:
            return list(self.config["monitor"])

        host = request.get("host")
        if isinstance(host, str):
            host = _canonical_ip_or_value(host)
            if host in self.config["monitor"]:
                return [host]
        return None

    def _log_cmd(self, cmd: list[str]) -> None:
        logging.debug("cmd: %s", " ".join(shlex.quote(part) for part in cmd))

    async def _run_ip(self, args: list[str]) -> tuple[bool, str]:
        cmd = [self.config["ip_bin"]] + args
        self._log_cmd(cmd)
        try:
            completed = await asyncio.to_thread(
                subprocess.run,
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.config.get("ip_timeout", 10),
            )
        except subprocess.TimeoutExpired as exc:
            logging.error("ip command timed out after %ss: %s", self.config.get("ip_timeout", 10), exc)
            return False, "timeout"
        except Exception as exc:
            logging.exception(exc)
            return False, str(exc)

        if completed.returncode == 0:
            output = (completed.stdout or "").strip()
            if output:
                logging.debug(output)
            return True, ""

        stderr = (completed.stderr or "").strip()
        stdout = (completed.stdout or "").strip()
        error_text = stderr or stdout or (f"exit code {completed.returncode}")
        return False, error_text

    async def clear_routes(self):
        """
        Clears the routes that are not needed.

        Removes the host routes for all monitored hosts (and their also_route
        destinations), resets route tracking, then installs the configured
        fallback routes.

        Parameters:
            None

        Returns:
            None
        """
        hosts = set()
        for host in self.config["monitor"]:
            hosts.update(self._destinations_for_host(host))

        for host in hosts:
            await self.clear_route(host)

        self.current_routes = {}

        # set fallback routes as no route set
        for host, gateway in self.config.get("fallback_routes", {}).items():
            await self.apply_route_config(host, gateway)

    async def clear_route(self, host: str) -> None:
        """
        Removes the route for the given host.

        Parameters:
            host (str): The host to remove the route for.

        Returns:
            None
        """

        logging.info("Remove %s", host)
        ok, error_text = await self._run_ip(["route", "del", _host_route_target(host)])
        if ok or "RTNETLINK answers: No such process" in error_text:
            self.current_routes.pop(host, None)
            return
        logging.error("Failed to remove route for %s: %s", host, error_text)

    def _route_cmd(self, action: str, destination: str, route: dict[str, str]) -> list[str]:
        cmd = [
            "route",
            action,
            _host_route_target(destination),
            "via",
            route["gateway"],
            "dev",
            route["device"],
        ]
        if route.get("probe_source"):
            cmd.extend(["src", route["probe_source"]])
        return cmd

    async def _missing_destinations(self, destinations: list[str]) -> list[str]:
        if not destinations:
            return []
        cmd = [self.config["ip_bin"], "-j", "route", "show"]
        self._log_cmd(cmd)
        try:
            completed = await asyncio.to_thread(
                subprocess.run,
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.config.get("ip_timeout", 10),
            )
        except Exception as exc:
            logging.warning("Failed to list routes: %s", exc)
            return []
        if completed.returncode != 0:
            error_text = (completed.stderr or completed.stdout or "").strip()
            logging.warning("Failed to list routes: %s", error_text)
            return []
        try:
            entries = json.loads(completed.stdout or "[]")
        except ValueError:
            logging.warning("Failed to parse 'ip -j route show' output")
            return []
        existing = set()
        for entry in entries:
            dst = str(entry.get("dst", "")).split("/", 1)[0]
            existing.add(_canonical_ip_or_value(dst))
        return [destination for destination in destinations if destination not in existing]

    async def apply_route_config(self, host: str, route_name: str) -> bool:
        """
        Applies the route configuration.

        Adds the route to the routing table for the given host and gateway.
        Additionally, if the also_route configuration is specified, it will also add the route for
        the given host to the routing table of the specified hosts.

        Parameters:
            host (str): The host to add the route for.
            route_name (str): The route candidate name to use.

        Returns:
            bool: True if all destination routes were applied, False otherwise.
        """
        route = self.routes_by_name.get(route_name)
        if route is None:
            logging.error("Unknown route '%s' for host '%s'", route_name, host)
            return False

        hosts_to_add = self._destinations_for_host(host)

        logging.info("Apply %s => %s", host, route_name)
        all_ok = True
        for destination in hosts_to_add:
            if destination not in self.current_routes:
                ok, error_text = await self._run_ip(self._route_cmd("add", destination, route))
                if ok:
                    self.current_routes[destination] = route_name
                    continue
                if "RTNETLINK answers: File exists" not in error_text:
                    logging.error("Failed to add route for %s: %s", destination, error_text)
                    all_ok = False
                    continue

            ok, error_text = await self._run_ip(self._route_cmd("replace", destination, route))
            if not ok:
                logging.error("Failed to replace route for %s: %s", destination, error_text)
                all_ok = False
                continue
            self.current_routes[destination] = route_name
        return all_ok

    async def _execute_probes(self) -> tuple[list[Any], list[str]]:
        tasks = []
        route_names = []
        for route in self.routes:
            tasks.append(
                asyncio.create_task(
                    async_multiping(
                        self.config["monitor"],
                        count=self.config["pings_per_probe"],
                        source=route["probe_source"],
                        interval=self.config["test_interval"],
                        timeout=self.config["probe_timeout"],
                        payload_size=self.config["payload_size"],
                        device=route["device"] if self.config["bind_to_device"] else None,
                    )
                )
            )
            route_names.append(route["name"])
        result = await asyncio.gather(*tasks, return_exceptions=True)
        return result, route_names

    @staticmethod
    def _aggregate_probe_results(
        result: list[Any], route_names: list[str]
    ) -> tuple[dict[str, dict[str, dict[str, Any]]], set[str], dict[str, dict[str, dict[str, float]]]]:
        probe_snapshot: dict[str, dict[str, dict[str, Any]]] = {}
        sources_up: set[str] = set()
        new_sums: dict[str, dict[str, dict[str, float]]] = {}
        for x, hosts in enumerate(result):
            source = route_names[x]
            if isinstance(hosts, BaseException):
                logging.warning("%s: probe failed: %s", source, hosts)
                continue
            if not isinstance(hosts, list):
                logging.warning("%s: probe returned unexpected payload type: %s", source, type(hosts).__name__)
                continue
            for host in hosts:
                if host.address not in probe_snapshot:
                    probe_snapshot[host.address] = {}
                # icmplib reports packet_loss as a 0..1 ratio; convert to percent
                # to match packet_loss_threshold and status output semantics.
                probe_snapshot[host.address][source] = {
                    "avg_rtt": host.avg_rtt,
                    "avg_loss": host.packet_loss * 100,
                    "is_alive": bool(host.is_alive),
                }
                if host.address not in new_sums:
                    new_sums[host.address] = {}
                if source not in new_sums[host.address]:
                    new_sums[host.address][source] = {"rtt": 0.0, "loss": 0.0, "checks": 0, "alive": 0}
                metrics = new_sums[host.address][source]
                metrics["checks"] += 1
                metrics["loss"] += host.packet_loss * 100
                if not host.is_alive:
                    continue
                sources_up.add(source)
                metrics["rtt"] += host.avg_rtt
                metrics["alive"] += 1
        return probe_snapshot, sources_up, new_sums

    @staticmethod
    def _merge_sums(
        existing: dict[str, dict[str, dict[str, float]]],
        new: dict[str, dict[str, dict[str, float]]],
    ) -> dict[str, dict[str, dict[str, float]]]:
        merged: dict[str, dict[str, dict[str, float]]] = {}
        for host, sources in existing.items():
            merged[host] = {
                src: {"rtt": data["rtt"], "loss": data["loss"], "checks": data["checks"], "alive": data["alive"]}
                for src, data in sources.items()
            }
        for host, sources in new.items():
            if host not in merged:
                merged[host] = {}
            for src, metrics in sources.items():
                if src not in merged[host]:
                    merged[host][src] = {"rtt": 0.0, "loss": 0.0, "checks": 0, "alive": 0}
                merged[host][src]["rtt"] += metrics["rtt"]
                merged[host][src]["loss"] += metrics["loss"]
                merged[host][src]["checks"] += metrics["checks"]
                merged[host][src]["alive"] += metrics["alive"]
        return merged

    def _should_force_reset(self, sources_up: set[str]) -> bool:
        for current in self.current_routes.values():
            if current not in sources_up:
                return True
        return False

    def _ewma_metrics(self, host: str, route: str, rtt: float, loss: float) -> dict[str, float]:
        alpha = self.config["ewma_alpha"]
        state = self._ewma.setdefault(host, {})
        prev = state.get(route)
        if prev is None or alpha >= 1.0:
            state[route] = {"rtt": rtt, "loss": loss}
        else:
            prev["rtt"] = alpha * rtt + (1 - alpha) * prev["rtt"]
            prev["loss"] = alpha * loss + (1 - alpha) * prev["loss"]
        return state[route]

    @staticmethod
    def _resolve_route_action(
        host: str,
        best_route: tuple[str, float, float],
        current_route: str | None,
        mode: str,
        switching_enabled: bool,
        override_route: str | None,
        host_metrics: dict[str, dict[str, float]],
        packet_loss_threshold: float,
        rtt_threshold: float,
        now: float,
        last_switch_at: float,
        cooldown: float,
    ) -> tuple[str, str | None]:
        if mode == "override" and override_route:
            if current_route != override_route:
                return "apply", override_route
            return "keep", None

        if mode == "frozen" or not switching_enabled:
            return "keep", None

        if current_route is None or current_route not in host_metrics:
            return "apply", best_route[0]

        if current_route == best_route[0]:
            logging.debug("%s: Current route is already the fastest route", host)
            return "keep", None

        current_metrics = host_metrics[current_route]
        if current_metrics["alive"] == 0 or current_metrics["loss"] > packet_loss_threshold:
            logging.warning("%s: Current route has packet loss, need to switch", host)
            return "apply", best_route[0]

        current_rtt = current_metrics["rtt"]
        rtt_diff = current_rtt - best_route[1]
        logging.debug(
            "%s: rtt_diff: %s, (%s) %s (%s) %s ",
            host,
            rtt_diff,
            current_route,
            current_rtt,
            best_route[0],
            best_route[1],
        )

        if rtt_diff < rtt_threshold:
            logging.info(
                "%s: Route not changed to %s, rtt difference %s < threshold %s",
                host,
                best_route[0],
                round(rtt_diff, 3),
                rtt_threshold,
            )
            return "keep", None

        if cooldown > 0 and now - last_switch_at < cooldown:
            logging.info(
                "%s: Route not changed to %s, switch cooldown active (%.1fs remaining)",
                host,
                best_route[0],
                cooldown - (now - last_switch_at),
            )
            return "keep", None

        return "apply", best_route[0]

    async def _apply_routes_for_cycle(self, sums: dict[str, dict[str, dict[str, float]]]) -> list[str]:
        now = time.monotonic()
        valid_source_found: list[str] = []
        keep_hosts: list[str] = []
        for host, results in sums.items():
            metrics: dict[str, dict[str, float]] = {}
            for source, raw in results.items():
                if raw["alive"] == 0:
                    continue
                avg_rtt = raw["rtt"] / raw["alive"]
                avg_loss = raw["loss"] / raw["checks"]
                smoothed = self._ewma_metrics(host, source, avg_rtt, avg_loss)
                metrics[source] = {
                    "rtt": smoothed["rtt"],
                    "loss": smoothed["loss"],
                    "alive": raw["alive"],
                }
                logging.debug("%s: %s: %s %s", host, source, avg_rtt, avg_loss)

            if not metrics:
                continue
            best = min(metrics.items(), key=lambda item: (item[1]["loss"], item[1]["rtt"]))
            best_route = (best[0], best[1]["rtt"], best[1]["loss"])
            current_route = self.current_routes.get(host)

            async with self._get_state_lock():
                mode = self.route_modes.get(host, "auto")
                switching_enabled = bool(self.switching_enabled.get(host, True))
                override_route = self.override_routes.get(host)

            action, target_route = self._resolve_route_action(
                host,
                best_route,
                current_route,
                mode,
                switching_enabled,
                override_route,
                metrics,
                self.config["packet_loss_threshold"],
                self.config["rtt_threshold"],
                now,
                self._last_switch_at.get(host, float("-inf")),
                self.config["switch_cooldown"],
            )

            if action == "apply" and target_route:
                if await self.apply_route_config(host, target_route):
                    self._last_switch_at[host] = now
            elif action == "keep" and current_route:
                keep_hosts.append(host)

            valid_source_found.append(host)

        dest_to_host: dict[str, str] = {}
        for host in keep_hosts:
            for destination in self._destinations_for_host(host):
                dest_to_host[destination] = host
        missing = await self._missing_destinations(list(dest_to_host))
        missing_by_host: dict[str, list[str]] = {}
        for destination in missing:
            missing_by_host.setdefault(dest_to_host[destination], []).append(destination)
        for host, destinations in missing_by_host.items():
            current_route = self.current_routes.get(host)
            logging.warning(
                "%s: kernel route missing for %s, re-applying %s",
                host,
                ", ".join(destinations),
                current_route,
            )
            if current_route:
                await self.apply_route_config(host, current_route)
        return valid_source_found

    async def _handle_fallbacks(self, valid_source_found: list[str]) -> None:
        for sip in self.config["monitor"]:
            if sip in valid_source_found:
                continue
            logging.warning("No valid source found for %s", sip)
            async with self._get_state_lock():
                mode = self.route_modes.get(sip, "auto")
                switching_enabled = bool(self.switching_enabled.get(sip, True))
                override_route = self.override_routes.get(sip)
            if mode == "override" and override_route:
                await self.apply_route_config(sip, override_route)
                continue
            if mode == "frozen" or not switching_enabled:
                continue
            fallback = self.config.get("fallback_routes", {}).get(sip)
            if fallback:
                await self.apply_route_config(sip, fallback)
            else:
                logging.warning("No fallback routes configured for %s", sip)
                for destination in self._destinations_for_host(sip):
                    await self.clear_route(destination)

    async def _wait_interval(self, stop_event: asyncio.Event | None) -> None:
        if stop_event is None:
            await asyncio.sleep(self.config["scan_interval"])
            return
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=self.config["scan_interval"])
        except TimeoutError:
            pass

    async def run_async(self, stop_event: asyncio.Event | None = None):
        """
        Runs the main loop of the optimizer.

        The loop is responsible for sending ICMP requests to the hosts and setting the routing based on the results.

        Parameters:
            None

        Returns:
            None
        """
        checks = 0
        sums: dict[str, dict[str, dict[str, float]]] = {}
        while not (stop_event is not None and stop_event.is_set()):
            result, route_names = await self._execute_probes()
            probe_snapshot, sources_up, new_sums = self._aggregate_probe_results(result, route_names)

            async with self._get_state_lock():
                self.last_probe_snapshot = probe_snapshot

            force_reset = self._should_force_reset(sources_up)
            sums = self._merge_sums(sums, new_sums)
            checks += 1

            if checks >= self.config["decision_cycles"] or force_reset or not self.current_routes:
                valid_source_found = await self._apply_routes_for_cycle(sums)
                await self._handle_fallbacks(valid_source_found)
                checks = 0
                sums = {}

            await self._wait_interval(stop_event)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="Lowest Latency Routes Optimizer",
        description="Sends ICMP requests to list of given hosts and set static routing for the fastest response",
    )

    parser.add_argument("--config", type=str, help="Path to config file", required=True)
    parser.add_argument(
        "--systemd-logging",
        action="store_true",
        dest="systemd_logging",
        help="omit timestamp from log output (useful when running under systemd)",
    )

    args = parser.parse_args()

    try:
        with open(args.config, encoding="utf-8") as stream:
            try:
                config = yaml.safe_load(stream)
            except yaml.YAMLError as ex:
                logging.exception(ex)
                sys.exit(1)
    except Exception as e:
        logging.exception(e)
        sys.exit(1)

    if not config:
        logging.error("Config could not be parsed")
        sys.exit(1)

    try:
        llro_instance = LowestLatencyRoutesOptimizer(config)
    except ConfigError as exc:
        logging.error("Invalid configuration: %s", exc)
        sys.exit(1)

    if llro_instance.config.get("systemd_logging") or args.systemd_logging:
        logging.basicConfig(
            level=logging.DEBUG if llro_instance.config.get("debug") else logging.INFO,
            format="%(levelname)-8s %(message)s",
            force=True,
        )
    if llro_instance.config.get("debug"):
        logging.getLogger("root").setLevel(logging.DEBUG)

    llro_instance.run()


if __name__ == "__main__":
    main()
