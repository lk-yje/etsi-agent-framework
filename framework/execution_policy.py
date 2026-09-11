"""Agent 标准工具的最小执行策略。

这层不决定 ETSI 条款如何测试；它只确保工具调用不越出本次工作区和已声明 DUT。
策略拒绝由 ToolRegistry 作为普通 tool error 返回并写 receipt，便于 Agent 纠正参数。
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_URL_HOST = re.compile(r"(?i)\b(?:https?|wss?)://([^/:\s]+)")
_DESTRUCTIVE = re.compile(
    r"(?i)(?:\brm\s+-[a-z]*r|\bdel\s+|\brmdir\b|\bremove-item\b|\bformat\b|\bshutdown\b|\breboot\b|\b(?:i?wr|curl)\b[^\n|]*\|\s*(?:sh|bash|powershell))"
)
_DANGEROUS_PYTHON = re.compile(
    r"(?i)(?:subprocess\.|os\.system|shutil\.rmtree|socket\.socket|requests\.|urllib\.request)"
)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    code: str
    reason: str
    params: dict[str, Any]
    approved_targets: tuple[str, ...] = ()

    def as_receipt(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "code": self.code,
            "reason": self.reason,
            "approved_targets": list(self.approved_targets),
        }


class ToolExecutionPolicy:
    """按单次 tool 调用创建，避免并发 phase 共享可变状态。"""

    def __init__(self, context: dict[str, Any] | None):
        self.context = context or {}
        raw_workspace = self.context.get("workspace")
        self.workspace = Path(raw_workspace).resolve() if raw_workspace else None
        self.approved_targets = self._approved_targets()

    def validate(self, tool_name: str, params: dict[str, Any]) -> PolicyDecision:
        normalized = dict(params)
        if self.workspace and tool_name in {"read_file", "write_file"}:
            path = params.get("path")
            if not isinstance(path, str) or not path.strip():
                return self._deny("workspace_path_missing", "文件工具必须提供工作区内 path", normalized)
            resolved = self._resolve_workspace_path(path)
            if resolved is None:
                return self._deny("workspace_path_outside", "文件路径必须位于本次 workspace 内", normalized)
            normalized["path"] = str(resolved)

        if tool_name == "bash":
            command = str(params.get("command", ""))
            if not command.strip():
                return self._deny("command_missing", "bash 工具必须提供 command", normalized)
            if _DESTRUCTIVE.search(command):
                return self._deny("destructive_command", "策略拒绝明显破坏性 shell 命令", normalized)
            target_issue = self._validate_targets(command)
            if target_issue:
                return self._deny("target_not_authorized", target_issue, normalized)

        if tool_name == "python_script":
            script = str(params.get("script", ""))
            if _DANGEROUS_PYTHON.search(script):
                return self._deny("python_capability_blocked", "python_script 不允许启动进程、网络访问或递归删除", normalized)

        # MCP 常用 URL 参数同样应只指向本次授权 DUT 或 localhost。
        for value in self._iter_strings(normalized):
            target_issue = self._validate_targets(value)
            if target_issue:
                return self._deny("target_not_authorized", target_issue, normalized)

        return PolicyDecision(True, "allowed", "调用符合最小执行策略", normalized, tuple(self.approved_targets))

    def _approved_targets(self) -> list[str]:
        if self.workspace is None:
            return []
        config_path = self.workspace / "run_config.json"
        try:
            config = json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
        except (OSError, json.JSONDecodeError):
            config = {}
        extra = config.get("authorized_targets") or []
        if isinstance(extra, str):
            extra = [extra]
        if not isinstance(extra, list):
            extra = []
        values = [config.get("dut_ip"), *extra]
        return [str(value).strip() for value in values if str(value).strip()]

    def _resolve_workspace_path(self, raw_path: str) -> Path | None:
        if self.workspace is None:
            return None
        candidate = Path(raw_path)
        candidate = candidate if candidate.is_absolute() else self.workspace / candidate
        try:
            target = candidate.resolve()
            return target if target.is_relative_to(self.workspace) else None
        except OSError:
            return None

    def _validate_targets(self, text: str) -> str | None:
        # 没有网络字面量就不猜测；工具可能只是读取/处理本地 artifact。
        ips = set(_IPV4.findall(text))
        hosts = {host.lower() for host in _URL_HOST.findall(text)}
        remote_ips = {ip for ip in ips if not self._is_local(ip)}
        remote_hosts = {host for host in hosts if host not in {"localhost", "127.0.0.1", "::1"}}
        if not remote_ips and not remote_hosts:
            return None
        approved = set(self.approved_targets)
        if not approved:
            return "本次 run_config 未声明 dut_ip/authorized_targets，禁止向网络目标发送调用"
        unknown_ips = sorted(remote_ips - approved)
        # 非 IP 主机名只允许其字面值明确列在 authorized_targets；dut_ip 不可推断 DNS。
        unknown_hosts = sorted(host for host in remote_hosts if host not in approved)
        if unknown_ips or unknown_hosts:
            return f"目标未在本次授权集合内: {', '.join([*unknown_ips, *unknown_hosts])}"
        return None

    @staticmethod
    def _is_local(value: str) -> bool:
        try:
            return ipaddress.ip_address(value).is_loopback
        except ValueError:
            return False

    def _deny(self, code: str, reason: str, params: dict[str, Any]) -> PolicyDecision:
        return PolicyDecision(False, code, reason, params, tuple(self.approved_targets))

    @staticmethod
    def _iter_strings(value: Any):
        if isinstance(value, dict):
            for nested in value.values():
                yield from ToolExecutionPolicy._iter_strings(nested)
        elif isinstance(value, list):
            for nested in value:
                yield from ToolExecutionPolicy._iter_strings(nested)
        elif isinstance(value, str):
            yield value
