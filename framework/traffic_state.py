"""阶段 3.1 的持久化交互状态。

控制 token 只用于唤醒独立的 Pipeline 子进程；本文件才是前端、报告和审计
共同读取的事实来源。状态写入复用 FileBus 的原子 JSON 写入保证。
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

from framework.file_bus import FileBus


TRAFFIC_STATE_FILE = "traffic_state.json"
ACTIVE_STATUSES = {
    "PREPARING", "CHANNELS_READY", "WAITING_START", "COLLECTING",
    "WAITING_FINISH", "STOPPING", "ANALYZING", "RESTORING_PROXY",
}
TERMINAL_STATUSES = {"COMPLETE", "BLOCKED", "SKIPPED", "CANCELLED", "FAILED"}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class TrafficStateStore:
    """以工作区为边界的 traffic_state.json 读写与审计历史维护。"""

    def __init__(self, workspace: Path):
        self.workspace = Path(workspace)
        self.bus = FileBus(self.workspace)

    def read(self) -> dict | None:
        path = self.workspace / TRAFFIC_STATE_FILE
        if not path.exists() or not path.stat().st_size:
            return None
        try:
            return self.bus.read_json(TRAFFIC_STATE_FILE)
        except (OSError, ValueError):
            return None

    def initialize(
        self,
        *,
        checklist_version: str,
        checklist: list[dict],
        dut_ip: str | None,
        capture_pcap: Path,
        control_mode: str,
    ) -> dict:
        """创建新的采集 attempt；中断的旧 attempt 明确留痕，不伪装可续接进程。"""
        previous = self.read()
        prior_attempts: list[dict] = []
        if previous:
            prior_attempts = list(previous.get("prior_attempts", []))
            if previous.get("status") in ACTIVE_STATUSES:
                prior_attempts.append({
                    "attempt_id": previous.get("attempt_id"),
                    "status": previous.get("status"),
                    "interrupted_at": _now(),
                    "reason": "Pipeline re-entered Traffic; previous process handles cannot be safely reattached",
                })

        now = _now()
        items = []
        for item in checklist:
            items.append({
                "id": item["id"],
                "label": item["label"],
                "required": bool(item.get("required", True)),
                "evidence_fields": list(item.get("evidence_fields", [])),
                "status": "pending",
                "updated_at": None,
                "note": "",
                "evidence": [],
            })
        state = {
            "schema_version": 1,
            "attempt_id": f"traffic-{datetime.now().strftime('%Y%m%d%H%M%S%f')}",
            "checklist_version": checklist_version,
            "status": "PREPARING",
            "control_mode": control_mode,
            "dut_ip": dut_ip,
            "capture_pcap": str(capture_pcap),
            "channels": {
                "tshark": {"status": "pending"},
                "xray": {"status": "pending"},
                "burp_upstream": {"status": "pending"},
            },
            "checklist": items,
            "history": [{"at": now, "event": "attempt_initialized", "status": "PREPARING"}],
            "prior_attempts": prior_attempts,
            "requested_action": None,
            "review_reason": None,
            "error": None,
        }
        return self._write(state)

    def transition(self, status: str, event: str, **fields: Any) -> dict:
        state = self.read()
        if state is None:
            raise RuntimeError("traffic_state.json 尚未初始化")
        state["status"] = status
        for key, value in fields.items():
            if value is not None:
                state[key] = value
        state.setdefault("history", []).append({
            "at": _now(), "event": event, "status": status,
            **{k: v for k, v in fields.items() if v is not None},
        })
        return self._write(state)

    def record_action(self, action: str, *, reason: str | None = None) -> dict:
        state = self.read()
        if state is None:
            raise RuntimeError("Traffic 尚未进入可交互状态")
        state["requested_action"] = action
        state.setdefault("history", []).append({
            "at": _now(), "event": "user_action_requested", "action": action,
            **({"reason": reason} if reason else {}),
        })
        if reason:
            state["last_action_reason"] = reason
        return self._write(state)

    def update_check_item(
        self, item_id: str, status: str, *, note: str = "", evidence: list[str] | None = None,
    ) -> dict:
        if status not in {"pending", "done", "na"}:
            raise ValueError("checklist status 必须是 pending、done 或 na")
        state = self.read()
        if state is None:
            raise RuntimeError("Traffic 尚未进入可交互状态")
        item = next((x for x in state.get("checklist", []) if x.get("id") == item_id), None)
        if item is None:
            raise KeyError(f"未知 checklist item: {item_id}")
        item.update({
            "status": status,
            "updated_at": _now(),
            "note": note.strip(),
            "evidence": list(evidence or []),
        })
        state.setdefault("history", []).append({
            "at": _now(), "event": "check_item_updated", "item_id": item_id,
            "item_status": status,
        })
        return self._write(state)

    def _write(self, state: dict) -> dict:
        self.bus.write_json(TRAFFIC_STATE_FILE, deepcopy(state))
        return state
