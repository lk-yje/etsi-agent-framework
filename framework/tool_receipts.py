"""Agent 工具调用的可审计收据。

收据是“调用发生过”的证明，不替代条款 evidence：原始 Nmap/PCAP/Burp 等产物
仍由 evidence.path 引用。为避免 API token、口令或 Authorization 意外出现在
报告与 Web 页面，收据只保存参数/返回值的哈希和脱敏预览。
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_SECRET_KEY = re.compile(r"(?:token|secret|password|authorization|api[_-]?key|cookie)", re.IGNORECASE)
_SECRET_TEXT = re.compile(
    r"(?i)(?:bearer\s+|token[=:]\s*|api[_-]?key[=:]\s*|password[=:]\s*)([^\s,;\"']+)"
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(value)


def _redact_text(value: str, limit: int = 1200) -> str:
    text = _SECRET_TEXT.sub(lambda match: f"{match.group(0).split(match.group(1))[0]}[REDACTED]", value)
    return text[:limit] + ("…" if len(text) > limit else "")


def redact_value(value: Any) -> Any:
    """递归生成可写入 receipt 的参数摘要，不改变用于哈希的原始输入。"""
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _SECRET_KEY.search(str(key)) else redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


class ToolReceiptStore:
    """以每次调用一个原子 JSON 文件的方式保存 receipt，适合并发 phase。"""

    def __init__(self, workspace: Path):
        self.workspace = Path(workspace)
        self.directory = self.workspace / "tool-receipts"

    def record(
        self,
        *,
        context: dict[str, Any],
        tool_name: str,
        params: dict[str, Any],
        content: str,
        is_error: bool,
        started_at: datetime,
        ended_at: datetime,
    ) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        receipt_id = f"{started_at.strftime('%Y%m%dT%H%M%S%f')}_{uuid.uuid4().hex[:10]}"
        raw_params = _safe_json(params)
        raw_content = str(content)
        duration_ms = max(0, int((ended_at - started_at).total_seconds() * 1000))
        executable_hint = self._executable_hint(tool_name, params)
        receipt = {
            "schema_version": 1,
            "receipt_id": receipt_id,
            "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "workspace": str(self.workspace),
            "agent_id": context.get("agent_id"),
            "agent_type": context.get("agent_type"),
            "module_id": context.get("module_id"),
            "phase_id": context.get("phase_id"),
            "clause_ids": list(context.get("clause_ids") or []),
            "attempt": context.get("attempt"),
            "policy": context.get("policy"),
            "tool": {
                "name": tool_name,
                "executable_hint": executable_hint,
                "environment_version": self._environment_version(executable_hint),
                "params_sha256": _sha256(raw_params),
                "params_preview": redact_value(params),
            },
            "result": {
                "is_error": is_error,
                "content_sha256": _sha256(raw_content),
                "content_preview": _redact_text(raw_content),
                "duration_ms": duration_ms,
            },
            "artifact_refs": list(context.get("artifact_refs") or []),
            "raw_artifact_policy": "原始工具产物应由 clause evidence.path 或 artifact_refs 引用；receipt 不复制未脱敏输出。",
        }
        path = self.directory / f"{receipt_id}.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)
        return path

    def _environment_version(self, executable_hint: str) -> str | None:
        snapshot_path = self.workspace / "environment_snapshot.json"
        try:
            snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
            version = snapshot.get("tools", {}).get(executable_hint, {}).get("version")
            return str(version) if version else "not_recorded"
        except (OSError, json.JSONDecodeError, AttributeError):
            return "not_recorded"

    @staticmethod
    def _executable_hint(tool_name: str, params: dict[str, Any]) -> str:
        if tool_name != "bash":
            return tool_name
        command = str(params.get("command", ""))
        try:
            tokens = shlex.split(command, posix=False)
        except ValueError:
            tokens = command.split()
        if not tokens:
            return "bash"
        return Path(tokens[0]).stem.lower() or "bash"


def record_tool_receipt(
    context: dict[str, Any] | None,
    tool_name: str,
    params: dict[str, Any],
    content: str,
    is_error: bool,
    started_at: datetime,
    ended_at: datetime,
) -> Path | None:
    """best-effort 记录；收据故障不得改变工具本身的成功/失败语义。"""
    if not context or not context.get("workspace"):
        return None
    try:
        return ToolReceiptStore(Path(context["workspace"])).record(
            context=context, tool_name=tool_name, params=params, content=content,
            is_error=is_error, started_at=started_at, ended_at=ended_at,
        )
    except (OSError, TypeError, ValueError):
        return None
