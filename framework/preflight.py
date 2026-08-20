"""Offline-safe environment preflight for Web and CLI consumers."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from framework.path_resolver import PathResolver
from framework.runtime_config import RuntimeSettings

DEFAULT_TOOL_NAMES = (
    "nmap", "tshark", "xray", "curl", "ncat", "sqlmap", "binwalk",
)


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
) -> dict:
    """Collect local readiness without contacting the DUT or external services."""
    resolver = (
        PathResolver(settings.path_mapping_path)
        if settings.path_mapping_path
        else PathResolver()
    )

    tools = {}
    for name in DEFAULT_TOOL_NAMES:
        resolved = resolver.get_tool_path(name)
        available = bool(resolved and Path(resolved).is_file())
        tools[name] = {
            "available": available,
            "resolved_path": resolved,
            "version": _tool_version(resolved) if available and include_versions else None,
        }

    traffic_ready = tools["tshark"]["available"] and tools["xray"]["available"]
    python_ready = sys.version_info >= (3, 11)
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
        "dut": {
            "ip": dut_ip,
            "reachability": "not_checked",
            "note": "离线 preflight 不主动访问 DUT",
        },
        "readiness": {
            "offline_ready": python_ready,
            "traffic_ready": traffic_ready,
            "full_device_ready": False,
        },
    }
