"""Offline-safe environment preflight for Web and CLI consumers."""

from __future__ import annotations

import os
import platform
import socket
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from framework.path_resolver import PathResolver
from framework.runtime_config import RuntimeSettings

DEFAULT_TOOL_NAMES = (
    "nmap", "tshark", "capinfos", "editcap", "easytshark_analyzer",
    "xray", "curl", "ncat", "sqlmap", "binwalk",
)


def analyze_dut_target(value: str, *, probe: bool) -> dict:
    """规范化前端 DUT 输入；可选地进行 DNS + TCP 探活。"""
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("DUT 地址不能为空")
    parsed = urlsplit(raw if "://" in raw else f"http://{raw}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("DUT 必须是 http(s) URL、IP 或主机名，且不得包含账号信息")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("DUT 端口无效") from exc
    if not (1 <= port <= 65535):
        raise ValueError("DUT 端口必须在 1–65535 之间")
    path = parsed.path or "/"
    target_url = urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))
    result = {"input": raw, "url": target_url, "host": parsed.hostname, "port": port,
              "scheme": parsed.scheme, "reachability": "not_checked", "reason": None}
    if not probe:
        return result
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)})
    except socket.gaierror as exc:
        result.update(reachability="unreachable", reason=f"DNS 解析失败: {exc}")
        return result
    try:
        with socket.create_connection((parsed.hostname, port), timeout=3):
            result.update(reachability="reachable", resolved_addresses=addresses)
    except OSError as exc:
        result.update(reachability="unreachable", resolved_addresses=addresses, reason=f"TCP {port} 不可达: {exc}")
    return result


def _tool_version(path: str) -> str | None:
    """Best-effort version probe with a short timeout."""
    for flag in ("--version", "-version", "-v"):
        try:
            result = subprocess.run(
                [path, flag],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        line = (result.stdout or result.stderr).strip().splitlines()
        if line:
            return line[0][:240]
    return None


def collect_environment_preflight(
    settings: RuntimeSettings,
    *,
    dut_ip: str | None = None,
    include_versions: bool = True,
    probe_dut: bool = False,
) -> dict:
    """Collect local readiness without contacting the DUT or external services."""
    resolver = (
        PathResolver(settings.path_mapping_path)
        if settings.path_mapping_path
        else PathResolver()
    )

    tools = {}
    for name in DEFAULT_TOOL_NAMES:
        resolved = (
            settings.traffic_easytshark_path
            if name == "easytshark_analyzer" and settings.traffic_easytshark_path
            else resolver.get_tool_path(name)
        )
        available = bool(resolved and Path(resolved).is_file())
        tools[name] = {
            "available": available,
            "resolved_path": resolved,
            "version": _tool_version(resolved) if available and include_versions else None,
        }

    traffic_ready = tools["tshark"]["available"] and tools["xray"]["available"]
    traffic_intelligence_ready = tools["tshark"]["available"]
    requested_backend = settings.traffic_analyzer_backend
    worker_available = tools["easytshark_analyzer"]["available"]
    selected_backend = (
        "easytshark_batch"
        if requested_backend == "easytshark_batch" and worker_available
        else "direct_tshark"
    )
    python_ready = sys.version_info >= (3, 11)
    dut = {"ip": dut_ip, "reachability": "not_checked", "note": "未提供 DUT 地址"}
    if dut_ip:
        try:
            dut = analyze_dut_target(dut_ip, probe=probe_dut)
        except ValueError as exc:
            dut = {"input": dut_ip, "reachability": "invalid", "reason": str(exc)}
    return {
        "checked_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "python": platform.python_version(),
            "executable": sys.executable,
        },
        "deployment": settings.public_summary(),
        "tools": tools,
        "mcp": {
            "burp": {
                "configured": bool(os.environ.get("BURP_MCP_TOKEN")),
                "connected": False,
                "status": "not_checked",
            },
            "playwright": {"connected": False, "status": "not_checked"},
        },
        "dut": dut,
        "traffic_intelligence": {
            "requested_backend": requested_backend,
            "selected_backend": selected_backend,
            "ready": traffic_intelligence_ready,
            "direct_fallback_ready": tools["tshark"]["available"],
            "easytshark_worker_available": worker_available,
            "capinfos_available": tools["capinfos"]["available"],
            "editcap_available": tools["editcap"]["available"],
        },
        "readiness": {
            "offline_ready": python_ready,
            "traffic_ready": traffic_ready,
            "traffic_intelligence_ready": traffic_intelligence_ready,
            "full_device_ready": traffic_ready and dut.get("reachability") == "reachable",
        },
    }
