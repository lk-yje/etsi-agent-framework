"""ETSI Agent Framework — Web 控制台后端。

职责:
1. 启动/管理管线子进程（run_pipeline.py run --control-mode web）
2. 聚合工作区状态（pipeline_state + tokens + evidence + audit + 双通道实时）
3. 阶段 3.1 交互: traffic_state.json 为事实源，控制文件只唤醒 Pipeline
4. 实时事件流 (logs/events.jsonl tail)
5. 报告数据聚合 + 工作区文件访问

启动:
    py -3.11 web/server.py [--port 8000]
或:
    py -3.11 -m uvicorn web.server:app --port 8000

前端: 静态页面挂载于根路径 web/static/。
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import subprocess
import sys
import time
import types
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── 项目根目录（server.py 所在目录的上级）──
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from framework.preflight import analyze_dut_target, collect_environment_preflight
from framework.input_manager import (
    generate_tampered_from_new,
    reference_firmware_sample,
    reference_ixit_source,
    write_run_config,
)
from framework.runtime_config import RuntimeSettings
from framework.traffic_state import TrafficStateStore
from pipelines.etsi.traffic_checklist import load_traffic_checklist
from web.run_manager import PROC_KEY, RunManager

RUNS_FILE = Path(__file__).resolve().parent / ".runs.json"
STATIC_DIR = Path(__file__).resolve().parent / "static"
RUNTIME_SETTINGS = RuntimeSettings.from_env(PROJECT_ROOT)

app = FastAPI(title="ETSI Agent Framework Web Console", version="0.1.0")

# ============================================================
# 运行注册表（内存 + JSON 持久化）
# ============================================================

RUN_MANAGER = RunManager(RUNS_FILE)
_runs = RUN_MANAGER.runs       # 兼容现有路由和测试的注册表别名
_PROC = PROC_KEY


def _load_runs() -> None:
    RUN_MANAGER.use_registry_path(RUNS_FILE)
    RUN_MANAGER.load()


def _save_runs() -> None:
    RUN_MANAGER.use_registry_path(RUNS_FILE)
    RUN_MANAGER.save()


def _pid_may_be_running(pid: object) -> bool:
    """仅用于重启后的可见性提示，绝不据此取得控制权或终止 PID。"""
    numeric_pid: int | None = None
    try:
        numeric_pid = int(pid)
        if numeric_pid <= 0:
            return False
        os.kill(numeric_pid, 0)
        return True
    # Windows may surface an access-denied result from os.kill(pid, 0) as a
    # SystemError rather than the underlying OSError.  A historical PID that
    # cannot be inspected must not make the whole run list unavailable.  Use
    # tasklist as a read-only fallback so a process created before a console
    # restart is shown as orphaned rather than incorrectly failed.
    except (TypeError, ValueError, ProcessLookupError, OSError, SystemError):
        if os.name != "nt" or numeric_pid is None:
            return False
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {numeric_pid}", "/NH"],
                capture_output=True,
                text=True,
                errors="replace",
                check=False,
                timeout=3,
            )
            return result.returncode == 0 and str(numeric_pid) in result.stdout
        except (OSError, subprocess.SubprocessError):
            return False


def _terminal_run_status(state: dict | None) -> str:
    return RunManager.terminal_status(state)


def _reconcile_run(meta: dict) -> tuple[bool, bool]:
    return RunManager.reconcile(meta, read_state=_safe_read, pid_may_be_running=_pid_may_be_running)


_load_runs()


# ============================================================
# 请求模型
# ============================================================

class RunCreate(BaseModel):
    workspace: str
    dut_ip: Optional[str] = None
    pipeline: str = "etsi-ts103701"
    burp_host: Optional[str] = None
    burp_port: Optional[int] = None
    no_playwright: bool = False
    mock: bool = False
    resume_failed: bool = False
    resume_cancelled_m0_audit: bool = False
    resume_failed_m0_audit: bool = False
    profile: str = "certification-full"
    modules: list[str] = []


class RunPlanRequest(BaseModel):
    profile: str = "certification-full"
    modules: list[str] = []


class TrafficConfirm(BaseModel):
    action: str  # "start" | "done" | "skip"
    reason: Optional[str] = None


class TrafficChecklistUpdate(BaseModel):
    status: str  # "pending" | "done" | "na"
    note: str = ""
    evidence: list[str] = []


class PreflightRequest(BaseModel):
    workspace: Optional[str] = None
    dut_ip: Optional[str] = None
    include_versions: bool = True
    probe_dut: bool = False


class WorkspaceCreate(BaseModel):
    name: str


class FirmwareReference(BaseModel):
    path: str


class LocalInputReference(BaseModel):
    path: str


class LocalFilePickerRequest(BaseModel):
    kind: str  # "ixit" | "firmware"


# ============================================================
# 工具函数
# ============================================================

def _safe_read(path: Path) -> Optional[dict]:
    try:
        if path.exists() and path.stat().st_size > 0:
            return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        pass
    return None


_ARTIFACT_TEXT_SUFFIXES = {".json", ".log", ".md", ".txt"}
_MAX_ARTIFACT_TEXT_BYTES = 2 * 1024 * 1024


def _artifact_catalog(ws: Path) -> dict[str, dict[str, str]]:
    """只发布已知报告/主 evidence，不接受调用方提交工作区路径。"""
    catalog: dict[str, dict[str, str]] = {}
    for module_id in ("M0", "M1", "M2", "M3", "M4", "M5"):
        rel = Path("evidence") / f"pre-{module_id}-evidence.json"
        if (ws / rel).is_file():
            catalog[f"module-evidence-{module_id}"] = {"path": rel.as_posix(), "name": f"{module_id} evidence"}
    report_paths = [*sorted(ws.glob("认证检测报告_*.md")), *sorted((ws / "reports").glob("认证检测报告_*.html"))]
    for target in report_paths:
        rel = target.relative_to(ws).as_posix()
        artifact_id = "report-" + hashlib.sha256(rel.encode("utf-8")).hexdigest()[:16]
        catalog[artifact_id] = {"path": rel, "name": target.name}
    return catalog


def _read_events(workspace: Path) -> list[dict]:
    """读取 events.jsonl，返回事件列表（按时间序）。"""
    events_path = workspace / "logs" / "events.jsonl"
    if not events_path.exists():
        return []
    events = []
    try:
        for line in events_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except OSError:
        return []
    return events


def _stage_events(events: list[dict]) -> list[dict]:
    return [e for e in events if e.get("type") == "stage_event"]


def _derive_traffic(ws: Path, events: list[dict], current_state: Optional[str]) -> dict:
    """读取阶段 3.1 状态；旧工作区才回退到事件流推导。"""
    persisted = TrafficStateStore(ws).read()
    pcap = ws / "capture.pcap"
    pcap_size_kb = round(pcap.stat().st_size / 1024, 1) if pcap.exists() else 0

    xray_log = ws / "xray_run.log"
    xray_log_tail = ""
    if xray_log.exists():
        try:
            lines = xray_log.read_text(encoding="utf-8", errors="replace").splitlines()
            xray_log_tail = "\n".join(lines[-10:])
        except OSError:
            pass

    if persisted:
        channels = persisted.get("channels", {})
        mcp_status = _safe_read(ws / "mcp_status.json") or {}
        status = persisted.get("status")
        return {
            **persisted,
            "capture_started": status not in {"PREPARING", "BLOCKED"},
            "tshark_running": channels.get("tshark", {}).get("status") == "running" and status in {
                "CHANNELS_READY", "WAITING_START", "COLLECTING", "WAITING_FINISH",
            },
            "xray_running": channels.get("xray", {}).get("status") == "running" and status in {
                "CHANNELS_READY", "WAITING_START", "COLLECTING", "WAITING_FINISH",
            },
            "waiting_for_user": status in {"WAITING_START", "WAITING_FINISH"},
            "pcap_size_kb": pcap_size_kb,
            "xray_log_tail": xray_log_tail,
            "mcp": mcp_status,
        }

    # 保留对既有工作区的只读兼容；新运行不再以事件反推交互状态。
    # 保留每个 TRAFFIC 事件名最后一次出现
    last = {}
    for e in _stage_events(events):
        if e.get("stage") == "TRAFFIC" and e.get("event"):
            last[e["event"]] = e["ts"]
    tshark_running = last.get("tshark_started") and (
        not last.get("tshark_stopped") or last["tshark_started"] > last["tshark_stopped"]
    )
    xray_running = last.get("xray_started") and (
        not last.get("xray_stopped") or last["xray_started"] > last["xray_stopped"]
    )
    capture_started = bool(last.get("tshark_started") or last.get("xray_started"))

    return {
        "capture_started": capture_started,
        "tshark_running": bool(tshark_running),
        "xray_running": bool(xray_running),
        "waiting_for_user": (
            current_state == "traffic"
            and capture_started
            and bool(last.get("complete")) is False
        ),
        "pcap_size_kb": pcap_size_kb,
        "xray_log_tail": xray_log_tail,
        "checklist": _TRAFFIC_CHECKLIST,
    }


def _derive_pause(ws: Path) -> dict:
    """读取 transport 暂停状态（AgentRunner 在 transport 错误重试耗尽后写入）。"""
    paused = _safe_read(ws / "pause_state.json") or {}
    if not isinstance(paused, dict):
        return {"paused": False}
    return paused


def _derive_cancellation(ws: Path, meta: dict, traffic: dict, state: dict | None) -> dict:
    """把协作取消的事实拆为可观察步骤，绝不把“请求”显示为“已停止”。"""
    history = traffic.get("history", []) if isinstance(traffic, dict) else []
    by_event = {entry.get("event"): entry for entry in history if isinstance(entry, dict)}
    requested = (ws / "tokens" / ".cancel_requested").exists() or meta.get("status") == "cancellation_requested"
    pipeline_state = (state or {}).get("current_state")
    # 若父进程被明确终止，持久快照可能还停在一个活动阶段；注册表的失败
    # 终态才是控制台的运行事实。failed/needs_review 同样结束取消时间线。
    terminal = pipeline_state in {"cancelled", "failed", "needs_review"}
    cleanup_done = "cleanup_started" in by_event
    restore_done = "burp_restore_started" in by_event
    active_key = None
    if requested and not terminal:
        active_key = "traffic_cleanup" if not cleanup_done else ("proxy_restore" if not restore_done else "pipeline_terminal")

    def step(key: str, label: str, event: str | None = None, *, complete: bool = False) -> dict:
        entry = by_event.get(event) if event else None
        done = bool(entry) or complete
        return {
            "key": key, "label": label,
            "state": "done" if done else ("current" if key == active_key else "pending"),
            "at": entry.get("at") if entry else ((state or {}).get("updated_at") if complete else None),
        }

    return {
        "requested": requested,
        "terminal": terminal,
        "reason": (state or {}).get("errors", [])[-1] if terminal and (state or {}).get("errors") else None,
        "steps": [
            step("requested", "已请求取消", complete=requested),
            step("traffic_cleanup", "Traffic 清理（停止 xray / tshark）", "cleanup_started"),
            step("proxy_restore", "恢复 Burp 上游代理", "burp_restore_started"),
            step("pipeline_terminal", "Pipeline 已进入取消终态", complete=terminal),
        ],
    }


_TRAFFIC_CHECKLIST_VERSION, _TRAFFIC_CHECKLIST = load_traffic_checklist()


def _derive_module_activity(events: list[dict]) -> dict[str, dict]:
    """从本次 pipeline attempt 的事件流提取模块进度，忽略旧中断 trace。"""
    last_start = max((index for index, event in enumerate(events) if event.get("type") == "pipeline_start"), default=-1)
    activity: dict[str, dict] = {}
    for event in events[last_start + 1:]:
        details = event.get("details") or {}
        module_id = details.get("module") or details.get("module_id")
        agent_id = event.get("agent_id") or details.get("agent_id", "")
        if not module_id and isinstance(agent_id, str):
            match = re.match(r"(?:work|audit)_(M[1-5])(?:_(phase_[A-Z]))?", agent_id)
            if match:
                module_id = match.group(1)
                details = {**details, "phase": match.group(2) or details.get("phase_id")}
        if module_id not in {"M1", "M2", "M3", "M4", "M5"}:
            continue
        entry = activity.setdefault(module_id, {"state": "not_started", "phases_completed": [], "current_phase": None})
        if event.get("type") == "agent_start":
            entry.update({"state": "running", "agent_id": agent_id, "started_at": event.get("ts"),
                          "current_phase": details.get("phase") or details.get("phase_id")})
        elif event.get("type") == "agent_end" and entry.get("agent_id") == agent_id:
            entry["state"] = "idle"
            entry["last_outcome"] = event.get("outcome")
        elif event.get("type") == "stage_event" and event.get("stage") == "PHASE_ENGINE":
            if event.get("event") == "phase_start":
                entry.update({"state": "running", "current_phase": details.get("phase"),
                              "clause_total": details.get("clauses"), "started_at": event.get("ts"),
                              "action": "正在执行该 phase 的功能性条款"})
            elif event.get("event") == "phase_complete":
                phase = details.get("phase")
                if phase and phase not in entry["phases_completed"]:
                    entry["phases_completed"].append(phase)
                entry["action"] = "phase 已完成，等待下一步"
        elif event.get("type") == "stage_event" and event.get("stage") == "AGENT_ACTIVITY":
            entry.update({"state": "running", "agent_id": agent_id, "current_phase": details.get("phase_id"),
                          "action": f"正在调用 {details.get('tool', '工具')}", "last_tool": details.get("tool"),
                          "last_action_at": event.get("ts")})
    return activity


def _derive_modules(ws: Path, events: list[dict]) -> dict:
    """推导 M0-M5 各模块状态。"""
    modules = {}
    activity = _derive_module_activity(events)
    for mid in ["M0", "M1", "M2", "M3", "M4", "M5"]:
        ev_file = ws / f"evidence/pre-{mid}-evidence.json"
        ev = _safe_read(ev_file) or {}
        meta = ev.get("meta", {})
        clause_verdicts: dict[str, int] = {}
        for c in ev.get("clauses", []):
            v = c.get("verdict", c.get("verdictId", "?"))
            clause_verdicts[v] = clause_verdicts.get(v, 0) + 1

        phases = sorted(
            p.stem.replace(f"pre-{mid}-", "").replace("-evidence", "")
            for p in ws.glob(f"evidence/pre-{mid}-phase_*-evidence.json")
        )

        au = _safe_read(ws / f"audit-results/audit-result_{mid}.json") or {}
        if "audit" in au and isinstance(au["audit"], dict):
            audit_verdict = au["audit"].get("verdict")
        else:
            audit_verdict = au.get("verdict")

        audit_status = next((
            status for status in ("ACCEPTED", "REVIEW_REQUIRED", "REJECTED", "ERROR")
            if (ws / f"tokens/.audit_{mid}_{status}").exists()
        ), None)

        audit_queue = _derive_audit_queue_state(mid, ws, events, audit_status, audit_verdict)
        modules[mid] = {
            "name": _MODULE_NAMES.get(mid, mid),
            "evidence": ev_file.exists(),
            "clause_count": len(ev.get("clauses", [])),
            "verdict_counts": clause_verdicts,
            "phase_evidences": phases,
            "audit_done": audit_status is not None,
            "audit_gate_passed": audit_status == "ACCEPTED",
            "audit_status": audit_status,
            "audit_verdict": audit_verdict,
            "audit_queue": audit_queue,
            "flagged": audit_status == "REVIEW_REQUIRED",
            "retry_count": meta.get("retryCount", meta.get("retry_count", 0)),
            "status": meta.get("status", "not_started"),
            "activity": activity.get(mid, {"state": "not_started", "phases_completed": [], "current_phase": None}),
        }
    return modules


def _derive_audit_queue_state(
    module_id: str, ws: Path, events: list[dict], audit_status: str | None,
    audit_verdict: str | None,
) -> dict[str, str | None]:
    """将 L1→Audit 的实际排队状态显式呈现，避免“未审计”语义含混。"""
    if audit_status:
        return {"state": "completed", "reason": f"审计 {audit_verdict or audit_status}", "index": f"audit-results/audit-result_{module_id}.json"}
    for event in reversed(events):
        if event.get("type") != "stage_event" or event.get("stage") != "M1_M5":
            continue
        details = event.get("details") or {}
        if details.get("module") != module_id:
            continue
        if event.get("event") == "audit_not_queued":
            return {"state": "blocked_l1", "reason": details.get("reason"), "index": details.get("error_index")}
        if event.get("event") == "audit_queued":
            return {"state": "queued", "reason": details.get("reason"), "index": None}
    error_index = ws / f"l1_errors_pre-{module_id}-evidence.json"
    if error_index.with_suffix(".json").exists():
        return {"state": "blocked_l1", "reason": "L1 结构校验未通过；Audit 未入队", "index": error_index.with_suffix(".json").relative_to(ws).as_posix()}
    return {"state": "not_ready", "reason": "等待 Work evidence", "index": None}


_TOOL_GROUPS = (
    ("Burp MCP", ("burp",)),
    ("tshark / pcap", ("tshark", "pcap", "wireshark")),
    ("Playwright", ("playwright", "browser_")),
    ("sqlmap", ("sqlmap", "sqli")),
    ("xray", ("xray",)),
    ("网络与命令工具", ("nmap", "curl", "bash", "python", "netstat", "gobuster")),
)


def _tool_group(name: object) -> str:
    text = str(name or "").lower()
    for label, markers in _TOOL_GROUPS:
        if any(marker in text for marker in markers):
            return label
    return "其他工具"


def _read_tool_coverage(ws: Path) -> dict[str, list[dict[str, Any]]]:
    """按条款 recipe 的“应调用工具”分组；实际调用只作状态对照。

    不从实际 receipt 反推分组，故某工具完全未调用时，其应覆盖的条款仍会
    以“未调用/降级”完整出现，便于操作者审查执行缺口。
    """
    mapping = _safe_read(PROJECT_ROOT / "framework" / "clause_tool_map.json") or {}
    phase_definitions = _safe_read(PROJECT_ROOT / "framework" / "phase_definitions.json") or {}
    functional_clause_ids = {
        str(clause_id)
        for module_id in ("M1", "M2", "M3", "M4", "M5")
        for phase in ((phase_definitions.get("modules", {}).get(module_id, {}) or {}).get("phases", []) or [])
        for clause_id in phase.get("clauses", [])
    }
    expected: dict[str, dict[str, Any]] = {}
    for clause_id, recipe in mapping.items():
        if str(clause_id) not in functional_clause_ids:
            continue
        groups: set[str] = set()
        for category, tool_names in (recipe.get("tools") or {}).items():
            if tool_names:
                # recipe 的类别是条款“应调用工具”的权威归属。例如
                # burp_mcp 下的 auth_diff / proxy_latest_auth 都是 Burp MCP
                # 子工具，不能因短名称不带 "burp" 而被二次归入“其他工具”。
                category_group = _tool_group(category)
                groups.add(category_group)
                if category_group == "其他工具":
                    groups.update(_tool_group(name) for name in tool_names)
        for field in ("script", "pre_script", "workflow", "method"):
            if recipe.get(field):
                inferred_group = _tool_group(recipe[field])
                # workflow 文件名或自然语言方法说明本身不是工具；仅在文本
                # 能明确识别工具族时作为 recipe.tools 的补充分类。
                if inferred_group != "其他工具":
                    groups.add(inferred_group)
        expected[str(clause_id)] = {
            "expected_groups": groups,
            "behavior": recipe.get("method") or recipe.get("workflow") or "未配置测试行为",
        }

    actual: dict[str, dict[str, list[dict[str, str]]]] = {}
    receipt_dir = ws / "tool-receipts"
    for path in sorted(receipt_dir.glob("*.json")) if receipt_dir.is_dir() else []:
        receipt = _safe_read(path) or {}
        tool = (receipt.get("tool") or {}).get("executable_hint") or (receipt.get("tool") or {}).get("name")
        group, ref = _tool_group(tool), path.relative_to(ws).as_posix()
        for clause_id in receipt.get("clause_ids") or []:
            actual.setdefault(str(clause_id), {}).setdefault(group, []).append({
                "tool": str(tool), "source": "receipt", "index": ref,
                "outcome": "error" if (receipt.get("result") or {}).get("is_error") else "ok",
            })

    verdicts: dict[str, dict[str, Any]] = {}
    for evidence_path in ws.glob("evidence/pre-M*-evidence.json"):
        evidence = _safe_read(evidence_path) or {}
        ref = evidence_path.relative_to(ws).as_posix()
        for step in evidence.get("execution_trace", evidence.get("executionTrace", [])) or []:
            if not isinstance(step, dict) or not step.get("tool"):
                continue
            group = _tool_group(step["tool"])
            for clause_id in step.get("clause_ids", step.get("clauseIds", [])) or []:
                actual.setdefault(str(clause_id), {}).setdefault(group, []).append({
                    "tool": str(step["tool"]), "source": "execution_trace", "index": ref,
                    "outcome": "error" if step.get("error") else "ok",
                })
        for clause in evidence.get("clauses", []) or []:
            if not isinstance(clause, dict):
                continue
            clause_id = str(clause.get("clause_id", clause.get("clauseId", "")))
            indexes = [ref] + [str(item["path"]) for item in clause.get("evidence", []) or [] if isinstance(item, dict) and item.get("path")]
            verdicts[clause_id] = {
                "verdict": clause.get("verdict", "?"),
                "reason": clause.get("manual_steps", clause.get("manualSteps")) or "; ".join(clause.get("warnings", []) or []),
                "indexes": indexes,
            }

    groups: dict[str, list[dict[str, Any]]] = {}
    for clause_id, rule in expected.items():
        for group in sorted(rule["expected_groups"]):
            calls = actual.get(clause_id, {}).get(group, [])
            verdict = verdicts.get(clause_id, {})
            if calls:
                state, reason = "已调用", None
            elif verdict.get("verdict") in {"PENDING_MANUAL", "INCONCLUSIVE"}:
                state, reason = "降级", verdict.get("reason") or "本次未形成自动化可复核结果"
            else:
                state, reason = "未调用", "未找到该条款对应的工具调用收据或执行轨迹"
            indexes = list(verdict.get("indexes", [])) + [call["index"] for call in calls]
            groups.setdefault(group, []).append({
                "clause": clause_id, "expected": group, "actual": calls,
                "behavior": rule["behavior"], "state": state, "reason": reason,
                "indexes": list(dict.fromkeys(indexes)),
            })
    return groups


_MODULE_NAMES = {
    "M0": "ICS 逻辑验证与概念性测试",
    "M1": "端口扫描与服务发现",
    "M2": "认证机制测试",
    "M3": "TLS 与通信分析",
    "M4": "软件更新与硬件安全",
    "M5": "漏洞扫描与数据保护",
}


def _derive_agents(events: list[dict], *, run_terminal: bool = False) -> list[dict]:
    """按 agent_id 聚合状态；终态 run 绝不把未闭合 trace 显示为仍在运行。"""
    states: dict[str, dict] = {}
    for e in events:
        if e.get("type") not in ("agent_start", "agent_end"):
            continue
        aid = e.get("agent_id", "")
        if not aid:
            continue
        s = states.setdefault(aid, {"agent_id": aid, "agent_type": e.get("agent_type", ""), "started": None, "ended": None, "outcome": None, "running": True})
        if e["type"] == "agent_start":
            s["started"] = e.get("ts")
            s["running"] = True
        else:
            s["ended"] = e.get("ts")
            s["running"] = False
            s["outcome"] = e.get("outcome")
            s["duration_ms"] = e.get("duration_ms")
    if run_terminal:
        # 强制停止或宿主异常可能来不及写 agent_end。原始 events.jsonl 必须保留，
        # 但控制台不能据一个悬空 agent_start 误报仍在执行。
        for state in states.values():
            if state["running"]:
                state["running"] = False
                state["outcome"] = "terminated"
                state["termination_reason"] = "run 已终态；未收到 agent_end"
    return [s for s in states.values()]


# ============================================================
# API
# ============================================================

@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "ts": datetime.now().isoformat()}


@app.get("/api/environment")
def environment() -> dict:
    """只读离线环境检查；不连接 DUT，也不回显任何 secret。"""
    return collect_environment_preflight(
        RUNTIME_SETTINGS,
        include_versions=False,
    )


@app.post("/api/workspace-picker")
def pick_workspace_directory() -> dict:
    """打开本机原生目录选择器；允许 AUTO_TEST_ROOT 或非 C: 数据盘的工作区。"""
    if os.name != "nt":
        raise HTTPException(status_code=501, detail="当前仅 Windows 本机控制台支持目录选择器")
    root = RUNTIME_SETTINGS.auto_test_root.resolve()
    try:
        import tkinter as tk
        from tkinter import filedialog
        dialog = tk.Tk()
        dialog.withdraw()
        dialog.attributes("-topmost", True)
        selected = filedialog.askdirectory(parent=dialog, initialdir=str(root), mustexist=True,
                                             title="选择工作区目录（C: 禁止，其他本地盘可选）")
        dialog.destroy()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"无法打开本机目录选择器: {exc}") from exc
    if not selected:
        return {"selected": False}
    try:
        workspace = RUNTIME_SETTINGS.resolve_workspace(selected, create=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="请选择非 C: 的具体工作区目录") from exc
    if workspace == root or workspace == Path(workspace.anchor):
        raise HTTPException(status_code=400, detail="请选择具体工作区目录，而不是磁盘或 AUTO_TEST_ROOT 根目录")
    workspace_id = str(workspace.relative_to(root)) if workspace.is_relative_to(root) else str(workspace)
    return {"selected": True, "workspace_id": workspace_id, "workspace": str(workspace)}


@app.post("/api/input-file-picker")
def pick_input_file(req: LocalFilePickerRequest) -> dict:
    """从 PATH_MAPPING 对应根目录选择输入文件，只返回本地引用，绝不复制源文件。"""
    if os.name != "nt":
        raise HTTPException(status_code=501, detail="当前仅 Windows 本机控制台支持文件选择器")
    if req.kind == "ixit":
        roots = RUNTIME_SETTINGS.input_roots
        title = "选择 ICS/IXIT 文件（PATH_MAPPING 默认目录）"
        filetypes = [("IXIT files", "*.xlsx *.json"), ("All files", "*.*")]
        label = "DIR.IXIT / DIR.INPUT"
    elif req.kind == "firmware":
        roots = RUNTIME_SETTINGS.firmware_roots
        title = "选择固件文件（PATH_MAPPING 默认目录）"
        filetypes = [("Firmware files", "*.bin *.img *.fw *.zip"), ("All files", "*.*")]
        label = "DIR.FIRMWARE"
    else:
        raise HTTPException(status_code=400, detail="未知的本地文件选择类型")

    roots = tuple(root.resolve() for root in roots if root.is_dir() and root.drive.upper() != "C:")
    if not roots:
        raise HTTPException(status_code=409, detail=f"PATH_MAPPING 未配置可用的非 C: {label} 目录")
    try:
        import tkinter as tk
        from tkinter import filedialog
        dialog = tk.Tk()
        dialog.withdraw()
        dialog.attributes("-topmost", True)
        selected = filedialog.askopenfilename(parent=dialog, initialdir=str(roots[0]), title=title, filetypes=filetypes)
        dialog.destroy()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"无法打开本机文件选择器: {exc}") from exc
    if not selected:
        return {"selected": False}
    source = Path(selected).resolve()
    if source.drive.upper() == "C:" or not source.is_file():
        raise HTTPException(status_code=400, detail="请选择映射目录内的非 C: 普通文件")
    allowed_root = next((root for root in roots if source.is_relative_to(root)), None)
    if allowed_root is None:
        raise HTTPException(status_code=400, detail="所选文件不在 PATH_MAPPING 对应的受控目录内")
    return {"selected": True, "path": str(source), "root": str(allowed_root), "kind": req.kind}


@app.post("/api/preflight")
def preflight(req: PreflightRequest) -> dict:
    """执行环境与可选 DUT 探活 preflight，并保存受控快照。"""
    result = collect_environment_preflight(
        RUNTIME_SETTINGS,
        dut_ip=req.dut_ip,
        include_versions=req.include_versions,
        probe_dut=req.probe_dut,
    )
    if req.workspace:
        try:
            ws = RUNTIME_SETTINGS.resolve_workspace(req.workspace, create=False)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not ws.is_dir():
            raise HTTPException(status_code=404, detail="workspace 不存在")
        snapshot = ws / "environment_snapshot.json"
        snapshot.write_text(
            json.dumps(result, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        result["snapshot"] = str(snapshot.relative_to(ws))
    return result


@app.post("/api/workspaces", status_code=201)
def create_workspace(req: WorkspaceCreate) -> dict:
    """在 AUTO_TEST_ROOT 内创建一个新的受控 workspace。"""
    name = req.name.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", name):
        raise HTTPException(status_code=400, detail="workspace name 仅允许字母、数字、点、下划线和连字符")
    try:
        ws = RUNTIME_SETTINGS.resolve_workspace(name, create=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if ws.exists():
        raise HTTPException(status_code=409, detail="workspace 已存在")

    from framework.workspace import init_workspace

    init_workspace(ws)
    (ws / "inputs").mkdir(exist_ok=True)
    return {"workspace_id": name, "workspace": str(ws), "status": "created"}


@app.post("/api/workspaces/{workspace_id}/inputs/ixit/reference", status_code=201)
def reference_ixit(workspace_id: str, req: LocalInputReference) -> dict:
    """从受控本地路径生成 Agent 消费的 normalized IXIT JSON。"""
    try:
        ws = RUNTIME_SETTINGS.resolve_workspace(workspace_id, create=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not ws.is_dir():
        raise HTTPException(status_code=404, detail="workspace 不存在")

    try:
        manifest = reference_ixit_source(ws, req.path, RUNTIME_SETTINGS.input_roots)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"workspace_id": workspace_id, "manifest": manifest}


@app.post("/api/workspaces/{workspace_id}/inputs/ixit")
def upload_ixit_deprecated(workspace_id: str) -> dict:
    raise HTTPException(status_code=410, detail="IXIT 不再上传或复制；请使用 /ixit/reference 登记工作机受控目录中的本地路径。")


@app.post("/api/workspaces/{workspace_id}/inputs/ixit-xlsx")
def upload_ixit_xlsx_deprecated(workspace_id: str) -> dict:
    raise HTTPException(status_code=410, detail="IXIT 不再上传或复制；请使用 /ixit/reference 登记本地 .xlsx 路径。")


@app.post("/api/workspaces/{workspace_id}/inputs/firmware/{role}/reference", status_code=201)
def reference_firmware(workspace_id: str, role: str, req: FirmwareReference) -> dict:
    """登记位于工作机受控目录下的 old/tampered 固件路径和 hash。"""
    try:
        ws = RUNTIME_SETTINGS.resolve_workspace(workspace_id, create=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not ws.is_dir():
        raise HTTPException(status_code=404, detail="workspace 不存在")
    try:
        manifest = reference_firmware_sample(ws, role, req.path, RUNTIME_SETTINGS.firmware_roots)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"workspace_id": workspace_id, "role": role, "manifest": manifest}


@app.post("/api/workspaces/{workspace_id}/inputs/firmware/tampered/generate", status_code=201)
def generate_tampered_firmware(workspace_id: str, req: FirmwareReference) -> dict:
    """从 new 固件自动生成 tampered 变体（确定性字节翻转），SHA-256 对比确认已更改。"""
    try:
        ws = RUNTIME_SETTINGS.resolve_workspace(workspace_id, create=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not ws.is_dir():
        raise HTTPException(status_code=404, detail="workspace 不存在")
    try:
        manifest = generate_tampered_from_new(ws, req.path, RUNTIME_SETTINGS.firmware_roots)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"workspace_id": workspace_id, "manifest": manifest}


@app.post("/api/workspaces/{workspace_id}/inputs/firmware/{role}")
def upload_firmware_deprecated(workspace_id: str, role: str) -> dict:
    """保留旧路由的明确拒绝，避免误以为浏览器上传是当前证据策略。"""
    raise HTTPException(
        status_code=410,
        detail="固件不再上传或复制；请使用 /reference 登记工作机受控目录中的本地路径。",
    )


@app.post("/api/runs", status_code=201)
def start_run(req: RunCreate) -> dict:
    if req.no_playwright:
        raise HTTPException(
            status_code=409,
            detail="Playwright MCP 是本地 ETSI 测试的强制通道，禁止 --no-playwright 降级运行",
        )
    try:
        ws = RUNTIME_SETTINGS.resolve_workspace(req.workspace, create=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    from framework.run_planner import build_run_plan
    from framework.run_workspace import create_isolated_run_workspace
    try:
        plan = build_run_plan(req.profile, req.modules)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not plan.certification_claim and req.profile not in {"functional-smoke", "functional-module"}:
        raise HTTPException(status_code=409, detail=f"{req.profile} 当前仅支持计划预览，尚不能启动")
    active_statuses = {"starting", "running", "cancellation_requested", "stopping", "orphaned"}
    if any(
        Path(meta.get("workspace", "")).resolve() == ws.resolve()
        and meta.get("status") in active_statuses
        for meta in _runs.values()
    ):
        raise HTTPException(status_code=409, detail="该 workspace 已有活动或未托管 run；请先确认其终态")
    try:
        dut = analyze_dut_target(req.dut_ip or "", probe=True)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if dut["reachability"] != "reachable":
        raise HTTPException(status_code=422, detail=f"DUT 启动前探活失败：{dut.get('reason') or '目标不可达'}")
    parent_ws = ws
    existing_state = _safe_read(ws / "pipeline_state.json")
    if existing_state and existing_state.get("current_state") not in {"done", "needs_review", "cancelled", "failed"}:
        raise HTTPException(status_code=409, detail="该 workspace 存在未完成 Pipeline；恢复功能尚未开放，不能创建第二个 run")
    if req.resume_failed and (not existing_state or existing_state.get("current_state") != "failed"):
        raise HTTPException(status_code=409, detail="仅可对 current_state=failed 的工作区请求失败恢复")
    if req.resume_cancelled_m0_audit and (not existing_state or existing_state.get("current_state") != "cancelled"):
        raise HTTPException(status_code=409, detail="仅可对 current_state=cancelled 的工作区恢复 M0 审计")
    if req.resume_failed_m0_audit and (not existing_state or existing_state.get("current_state") != "failed"):
        raise HTTPException(status_code=409, detail="仅可对 current_state=failed 的工作区恢复 M0 审计")
    if not plan.certification_claim:
        try:
            ws = create_isolated_run_workspace(parent_ws, plan)
        except (OSError, FileNotFoundError) as exc:
            raise HTTPException(status_code=409, detail=f"无法创建隔离功能性运行目录: {exc}") from exc
    (ws / "tokens").mkdir(exist_ok=True)
    # 只清除本次 run 的明确取消控制信号，避免复用 workspace 时误取消新进程。
    (ws / "tokens" / ".cancel_requested").unlink(missing_ok=True)

    run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    meta: dict = {
        "run_id": run_id,
        "workspace": str(ws),
        "parent_workspace": str(parent_ws),
        "pipeline": req.pipeline,
        "profile": req.profile,
        "certification_claim": plan.certification_claim,
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "status": "starting",
        "dut_ip": dut["url"],
    }
    write_run_config(
        ws,
        {
            "run_id": run_id,
            "pipeline": req.pipeline,
            "created_at": meta["started_at"],
            "dut_ip": dut["url"],
            "dut_host": dut["host"],
            "dut_port": dut["port"],
            "dut_probe": dut,
            "burp_host": req.burp_host,
            "burp_port": req.burp_port,
            "no_playwright": req.no_playwright,
            "simulation": req.mock,
            "resume_failed": req.resume_failed,
            "resume_cancelled_m0_audit": req.resume_cancelled_m0_audit,
            "resume_failed_m0_audit": req.resume_failed_m0_audit,
            "profile": req.profile,
            "modules": plan.selected_modules,
            "certification_claim": plan.certification_claim,
            "parent_workspace": str(parent_ws),
        },
    )

    cmd = RunManager.build_command(
        workspace=ws, pipeline=req.pipeline, mock=req.mock, no_playwright=req.no_playwright,
        resume_failed=req.resume_failed,
        resume_cancelled_m0_audit=req.resume_cancelled_m0_audit,
        resume_failed_m0_audit=req.resume_failed_m0_audit,
        profile=req.profile, modules=plan.selected_modules,
        run_workspace_ready=not plan.certification_claim,
    )
    child_env = RunManager.build_env(
        burp_host=req.burp_host, burp_port=req.burp_port,
    )
    try:
        proc = RunManager.start(
            command=cmd, project_root=PROJECT_ROOT, workspace=ws,
            env=child_env, popen_factory=subprocess.Popen,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"启动管线子进程失败: {e}")

    meta[_PROC] = proc
    meta["pid"] = getattr(proc, "pid", None)
    meta["status"] = "running"
    _runs[run_id] = meta
    _save_runs()

    return {
        "run_id": run_id,
        "workspace": str(ws),
        "parent_workspace": str(parent_ws),
        "profile": req.profile,
        "certification_claim": plan.certification_claim,
        "status": "running",
        "dut": dut,
        "command": " ".join(cmd),
    }


@app.post("/api/run-plan")
def preview_run_plan(req: RunPlanRequest) -> dict:
    """纯计划预览：不创建工作区、不连接 DUT、不启动任何 Agent。"""
    from framework.run_planner import build_run_plan
    try:
        plan = build_run_plan(req.profile, req.modules)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"plan": plan.model_dump(mode="json", by_alias=True)}


@app.post("/api/runs/{run_id}/resume-m0-audit", status_code=201)
def resume_m0_audit(run_id: str) -> dict:
    """从已停止/失败的 M0 审计快照派生一个受管恢复进程，不重做其他阶段。"""
    source = _runs.get(run_id)
    if source is None:
        raise HTTPException(status_code=404, detail=f"run 不存在: {run_id}")
    ws = Path(source["workspace"])
    state = _safe_read(ws / "pipeline_state.json") or {}
    interrupted_after_safe_stop = (
        state.get("current_state") == "m1_m5"
        and (ws / "tokens" / ".cancel_requested").exists()
    )
    if state.get("current_state") not in {"cancelled", "failed"} and not interrupted_after_safe_stop:
        raise HTTPException(status_code=409, detail="仅可恢复已停止/失败的快照，或带安全停止令牌的重启中断快照")
    if state.get("stage_statuses", {}).get("m0_audit") != "failed":
        raise HTTPException(status_code=409, detail="该快照不是可恢复的 M0 审计失败点")
    if source.get("profile", "certification-full") != "certification-full":
        raise HTTPException(status_code=409, detail="功能性 profile 不使用 M0 审计恢复")
    # 本次 source 若仅因电脑重启而遗留 cancellation_requested，令牌已明确
    # 要求停止，可由本恢复动作接管；其他活动 run 仍一律阻止双跑。
    if any(meta.get("run_id") != run_id and meta.get("workspace") == str(ws) and meta.get("status") in {"starting", "running", "cancellation_requested", "stopping"}
           for meta in _runs.values()):
        raise HTTPException(status_code=409, detail="该快照已有活动恢复进程")
    mode = "--resume-cancelled-m0-audit" if state["current_state"] == "cancelled" else "--resume-failed-m0-audit"
    new_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    cmd = RunManager.build_command(workspace=ws, pipeline=source.get("pipeline", "etsi-ts103701"),
                                   mock=False, no_playwright=False)
    cmd.append(mode)
    proc = RunManager.start(command=cmd, project_root=PROJECT_ROOT, workspace=ws,
                            env=RunManager.build_env(burp_host=None, burp_port=None),
                            popen_factory=subprocess.Popen)
    meta = {**{k: v for k, v in source.items() if k != _PROC}, "run_id": new_id, "resumes_run_id": run_id,
            "started_at": datetime.now().isoformat(timespec="seconds"), "status": "running", "pid": proc.pid,
            _PROC: proc}
    _runs[new_id] = meta
    _save_runs()
    return {"run_id": new_id, "workspace": str(ws), "resumes_run_id": run_id, "status": "running"}


@app.post("/api/runs/{run_id}/resume-m1m5", status_code=201)
def resume_m1m5(run_id: str) -> dict:
    """从 M1–M5 停止快照恢复：先回到 Traffic，再按 digest 复用 phase。"""
    source = _runs.get(run_id)
    if source is None:
        raise HTTPException(status_code=404, detail=f"run 不存在: {run_id}")
    ws = Path(source["workspace"])
    state = _safe_read(ws / "pipeline_state.json") or {}
    interrupted_after_safe_stop = (
        state.get("current_state") == "m1_m5"
        and (ws / "tokens" / ".cancel_requested").exists()
    )
    if state.get("current_state") not in {"cancelled", "failed"} and not interrupted_after_safe_stop:
        raise HTTPException(status_code=409, detail="仅可恢复已停止/失败的快照，或带安全停止令牌的重启中断快照")
    if state.get("stage_statuses", {}).get("m1_m5") not in {"failed", "in_progress", "awaiting_gate"}:
        raise HTTPException(status_code=409, detail="该快照未停在可恢复的 M1–M5 节点")
    if any(meta.get("run_id") != run_id and meta.get("workspace") == str(ws) and meta.get("status") in {"starting", "running", "cancellation_requested", "stopping"}
           for meta in _runs.values()):
        raise HTTPException(status_code=409, detail="该快照已有活动恢复进程")
    new_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    cmd = RunManager.build_command(
        workspace=ws, pipeline=source.get("pipeline", "etsi-ts103701"), mock=False, no_playwright=False,
        profile=source.get("profile", "certification-full"), modules=source.get("modules") or [],
        run_workspace_ready=source.get("profile") in {"functional-smoke", "functional-module"}, resume_m1m5=True,
    )
    proc = RunManager.start(command=cmd, project_root=PROJECT_ROOT, workspace=ws,
                            env=RunManager.build_env(burp_host=None, burp_port=None),
                            popen_factory=subprocess.Popen)
    meta = {**{k: v for k, v in source.items() if k != _PROC}, "run_id": new_id, "resumes_run_id": run_id,
            "started_at": datetime.now().isoformat(timespec="seconds"), "status": "running", "pid": proc.pid,
            _PROC: proc}
    _runs[new_id] = meta
    _save_runs()
    return {"run_id": new_id, "workspace": str(ws), "resumes_run_id": run_id,
            "status": "running", "message": "已恢复到 Traffic；请重新确认采集窗口，随后自动复用匹配的 phase 快照。"}


@app.post("/api/runs/{run_id}/resume-traffic", status_code=201)
def resume_traffic(run_id: str) -> dict:
    """Traffic 前置连接失败后的原地重试；保留 M0 和输入快照。"""
    source = _runs.get(run_id)
    if source is None:
        raise HTTPException(status_code=404, detail=f"run 不存在: {run_id}")
    ws = Path(source["workspace"])
    state = _safe_read(ws / "pipeline_state.json") or {}
    if state.get("current_state") not in {"needs_review", "failed", "cancelled"}:
        raise HTTPException(status_code=409, detail="仅可恢复 Traffic 前置失败的终态快照")
    if state.get("stage_statuses", {}).get("traffic") != "failed":
        raise HTTPException(status_code=409, detail="该快照不是 Traffic 失败点")
    if any(meta.get("workspace") == str(ws) and meta.get("status") in {"starting", "running", "cancellation_requested", "stopping"}
           for meta in _runs.values()):
        raise HTTPException(status_code=409, detail="该快照已有活动恢复进程")
    new_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    cmd = RunManager.build_command(
        workspace=ws, pipeline=source.get("pipeline", "etsi-ts103701"), mock=False, no_playwright=False,
        profile=source.get("profile", "certification-full"), modules=source.get("modules") or [],
        run_workspace_ready=source.get("profile") in {"functional-smoke", "functional-module"},
    )
    cmd.append("--resume-traffic")
    proc = RunManager.start(command=cmd, project_root=PROJECT_ROOT, workspace=ws,
                            env=RunManager.build_env(burp_host=None, burp_port=None),
                            popen_factory=subprocess.Popen)
    meta = {**{k: v for k, v in source.items() if k != _PROC}, "run_id": new_id, "resumes_run_id": run_id,
            "started_at": datetime.now().isoformat(timespec="seconds"), "status": "running", "pid": proc.pid,
            _PROC: proc}
    _runs[new_id] = meta
    _save_runs()
    return {"run_id": new_id, "workspace": str(ws), "resumes_run_id": run_id,
            "status": "running", "message": "已从 Traffic 原地重试；M0 与输入快照已保留。"}


def _run_status(run_id: str) -> dict:
    meta = _runs.get(run_id)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"run 不存在: {run_id}")
    running, orphaned = _reconcile_run(meta)

    ws = Path(meta["workspace"])

    # 1. pipeline_state
    raw_state = _safe_read(ws / "pipeline_state.json")
    state = dict(raw_state or {})
    current_state = state.get("current_state")
    terminal_statuses = {"done", "needs_review", "cancelled", "failed"}
    if (
        meta.get("status") in terminal_statuses
        and current_state not in terminal_statuses
    ):
        # 仅生成 API 展示覆盖，不回写中断前的 pipeline_state.json 或 events.jsonl。
        # 这样历史证据保持原样，而 UI 不会继续把已死亡的 run 当作进行中。
        state["current_state"] = meta["status"]
        stage_statuses = dict(state.get("stage_statuses") or {})
        if current_state:
            stage_statuses[current_state] = "failed"
        state["stage_statuses"] = stage_statuses
        state["display_termination_reason"] = "受管子进程已结束，原始 Pipeline 快照未写入终态"
        current_state = meta["status"]

    # 2. workspace_status
    ws_status = {}
    try:
        from framework.workspace import workspace_status
        ws_status = workspace_status(ws)
    except Exception:
        ws_status = {}

    # 3. events
    events = _read_events(ws)
    traffic = _derive_traffic(ws, events, current_state)

    return {
        "run_id": run_id,
        "workspace": str(ws),
        "status": meta["status"],
        "profile": meta.get("profile", "certification-full"),
        "certification_claim": meta.get("certification_claim", True),
        "exit_code": meta.get("exit_code"),
        "started_at": meta.get("started_at"),
        "dut_ip": meta.get("dut_ip"),
        "process": {
            "running": running,
            "pid": meta.get("pid"),
            "managed": meta.get(_PROC) is not None,
            "orphaned": orphaned,
        },
        "state": {
            "exists": raw_state is not None,
            "current_state": current_state,
            "stage_statuses": (state or {}).get("stage_statuses", {}),
            "completed_stages": (state or {}).get("completed_stages", []),
            "errors": (state or {}).get("errors", []),
            "gate_failures": (state or {}).get("gate_failures", {}),
            "review_required": (state or {}).get("review_required", False),
            "review_reasons": (state or {}).get("review_reasons", []),
            "started_at": (state or {}).get("started_at"),
            "updated_at": (state or {}).get("updated_at"),
            "terminal": (state or {}).get("current_state") in ("done", "needs_review", "cancelled", "failed"),
        },
        "workspace_status": ws_status,
        "modules": _derive_modules(ws, events),
        "tool_coverage": _read_tool_coverage(ws),
        "agents": _derive_agents(
            events,
            run_terminal=meta.get("status") in {"failed", "cancelled", "needs_review"},
        ),
        "traffic": traffic,
        "pause": _derive_pause(ws),
        "cancellation": _derive_cancellation(ws, meta, traffic, state),
    }


@app.get("/api/runs")
def list_runs() -> dict:
    out = []
    for rid, meta in _runs.items():
        running, orphaned = _reconcile_run(meta)
        out.append({
            "run_id": rid,
            "workspace": meta.get("workspace"),
            "status": meta.get("status"),
            "running": running,
            "orphaned": orphaned,
            "started_at": meta.get("started_at"),
            "dut_ip": meta.get("dut_ip"),
        })
    out.sort(key=lambda r: r["started_at"] or "", reverse=True)
    return {"runs": out}


@app.get("/api/runs/{run_id}")
def get_run(run_id: str) -> dict:
    return _run_status(run_id)


@app.delete("/api/runs/{run_id}")
def forget_run(run_id: str) -> dict:
    """只移除控制台注册记录；绝不删除 workspace 或任何证据。"""
    meta = _runs.get(run_id)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"run 不存在: {run_id}")
    running, orphaned = _reconcile_run(meta)
    if running or orphaned:
        raise HTTPException(status_code=409, detail="活动或未托管 run 不能移除登记；请先确认其终态")
    workspace = meta.get("workspace")
    _runs.pop(run_id, None)
    _save_runs()
    return {
        "run_id": run_id, "status": "forgotten", "workspace": workspace,
        "message": "已移除控制台登记；workspace、证据、报告和抓包均未删除。",
    }


@app.post("/api/runs/{run_id}/stop")
def request_stop_run(run_id: str) -> dict:
    """请求 Pipeline 在下一个安全点取消；不会直接终止任何 PID。"""
    meta = _runs.get(run_id)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"run 不存在: {run_id}")
    ws = Path(meta["workspace"])
    pipeline_state = _safe_read(ws / "pipeline_state.json") or {}
    if pipeline_state.get("current_state") in {"done", "needs_review", "cancelled", "failed"}:
        raise HTTPException(status_code=409, detail="Pipeline 已处于终态，无需取消")
    token_dir = ws / "tokens"
    token_dir.mkdir(parents=True, exist_ok=True)
    (token_dir / ".cancel_requested").touch()
    meta["status"] = "cancellation_requested"
    _save_runs()
    return {
        "run_id": run_id,
        "status": "cancellation_requested",
        "signal": "tokens/.cancel_requested",
        "message": "已请求在阶段安全点取消；不会直接终止进程。",
    }


@app.post("/api/runs/{run_id}/pause/continue")
def continue_paused_run(run_id: str) -> dict:
    """让因 transport 错误暂停的 run 恢复：AgentRunner 会重置重试状态并原样重发请求。"""
    meta = _runs.get(run_id)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"run 不存在: {run_id}")
    ws = Path(meta["workspace"])
    if not _derive_pause(ws).get("paused"):
        raise HTTPException(status_code=409, detail="该 run 未处于 transport 暂停状态")
    token_dir = ws / "tokens"
    token_dir.mkdir(parents=True, exist_ok=True)
    (token_dir / ".pause_continue").touch()
    return {
        "run_id": run_id,
        "signal": "tokens/.pause_continue",
        "message": "已请求继续；管线将重试失败的 API 调用（约 2 秒内生效）。",
    }


@app.post("/api/runs/{run_id}/traffic/confirm")
def traffic_confirm(run_id: str, req: TrafficConfirm) -> dict:
    """阶段 3.1 动作：状态写入后，再以 token 唤醒 Pipeline。"""
    meta = _runs.get(run_id)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"run 不存在: {run_id}")
    if req.action not in ("start", "done", "skip"):
        raise HTTPException(status_code=400, detail="action 必须是 start、done 或 skip")

    ws = Path(meta["workspace"])
    pipeline_state = _safe_read(ws / "pipeline_state.json") or {}
    if pipeline_state.get("current_state") != "traffic":
        raise HTTPException(status_code=409, detail="当前不在 Traffic 阶段，不能发送采集动作")
    store = TrafficStateStore(ws)
    traffic = store.read()
    if traffic is None:
        raise HTTPException(status_code=409, detail="Traffic 尚未准备就绪")
    status = traffic.get("status")
    if req.action == "start" and status != "WAITING_START":
        raise HTTPException(status_code=409, detail=f"Traffic 当前为 {status}，不能开始操作")
    if req.action == "done":
        if status != "WAITING_FINISH":
            raise HTTPException(status_code=409, detail=f"Traffic 当前为 {status}，请先开始操作")
        missing = [x["label"] for x in traffic.get("checklist", []) if x.get("required") and x.get("status") == "pending"]
        if missing:
            raise HTTPException(status_code=409, detail="仍有必做操作未记录：" + "；".join(missing))
    if req.action == "skip":
        if status not in {"WAITING_START", "WAITING_FINISH"}:
            raise HTTPException(status_code=409, detail=f"Traffic 当前为 {status}，不能跳过")
        if not (req.reason or "").strip():
            raise HTTPException(status_code=400, detail="skip 必须填写原因，便于报告标记待人工复核")

    store.record_action(req.action, reason=req.reason)
    token_dir = ws / "tokens"
    token_dir.mkdir(parents=True, exist_ok=True)
    # 只处理本次 Traffic 的三个明确控制文件，确保动作互斥。
    for name in {"traffic_user_start", "traffic_user_done", "traffic_user_skip"} - {f"traffic_user_{req.action}"}:
        (token_dir / name).unlink(missing_ok=True)
    (token_dir / f"traffic_user_{req.action}").touch()

    return {"run_id": run_id, "action": req.action, "signal": f"tokens/traffic_user_{req.action}", "traffic": store.read()}


@app.put("/api/runs/{run_id}/traffic/checklist/{item_id}")
def update_traffic_checklist(run_id: str, item_id: str, req: TrafficChecklistUpdate) -> dict:
    """持久化用户对阶段 3.1 操作项的完成/N-A/证据备注。"""
    meta = _runs.get(run_id)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"run 不存在: {run_id}")
    ws = Path(meta["workspace"])
    traffic = TrafficStateStore(ws).read()
    if traffic is None or traffic.get("status") not in {"COLLECTING", "WAITING_FINISH"}:
        raise HTTPException(status_code=409, detail="仅在正式操作窗口内可以更新 checklist")
    try:
        updated = TrafficStateStore(ws).update_check_item(item_id, req.status, note=req.note, evidence=req.evidence)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"run_id": run_id, "item_id": item_id, "traffic": updated}


@app.get("/api/runs/{run_id}/events")
def get_events(run_id: str, after: int = 0, limit: int = 500) -> dict:
    meta = _runs.get(run_id)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"run 不存在: {run_id}")
    ws = Path(meta["workspace"])
    events = _read_events(ws)
    tail = events[after: after + limit]
    return {
        "cursor": min(after + len(tail), len(events)),
        "total": len(events),
        "events": tail,
    }


@app.get("/api/runs/{run_id}/report")
def get_report(run_id: str) -> dict:
    meta = _runs.get(run_id)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"run 不存在: {run_id}")
    ws = Path(meta["workspace"])

    report_data = {}
    try:
        from run_pipeline import _query_report_data
        report_data = _query_report_data(types.SimpleNamespace(workspace=ws))
    except Exception:
        report_data = {"status": "error"}

    # 追加报告文件列表。Markdown 是原始记录，HTML 是独立可归档的展开视图。
    md_reports = sorted(ws.glob("认证检测报告_*.md"))
    html_reports = sorted((ws / "reports").glob("认证检测报告_*.html"))
    catalog = _artifact_catalog(ws)
    report_data["report_files"] = [str(f.relative_to(ws)) for f in [*md_reports, *html_reports]]
    report_data["report_artifacts"] = [
        {"id": artifact_id, "name": item["name"], "path": item["path"]}
        for artifact_id, item in catalog.items() if artifact_id.startswith("report-")
    ]
    report_data["workspace"] = str(ws)
    return report_data


@app.get("/api/runs/{run_id}/evidence-download")
def download_evidence(run_id: str, scope: str = "all", value: str | None = None):
    """下载单条款 / 大条款 / 全部的类型化证据包。

    只导出条款归档和其小型派生证据；共享 raw PCAP 不会被重复放进每一个包。
    未在 REPORT 阶段生成过包的历史工作区会在此处安全重建索引。
    """
    meta = _runs.get(run_id)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"run 不存在: {run_id}")
    ws = Path(meta["workspace"])
    try:
        from framework.reporting import PACKAGE_DIR, create_evidence_zip, write_report_bundle

        if not (ws / PACKAGE_DIR / "manifest.json").is_file():
            write_report_bundle(ws)
        archive = create_evidence_zip(ws, scope, value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return FileResponse(archive, media_type="application/zip", filename=archive.name)


@app.post("/api/runs/{run_id}/clauses/{clause_id}/pcap-slice")
def create_clause_pcap_slice(run_id: str, clause_id: str) -> dict:
    """明确请求后才为具备帧索引的条款生成最小 PCAP 派生件。"""
    meta = _runs.get(run_id)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"run 不存在: {run_id}")
    try:
        from framework.reporting import materialize_clause_pcap_slice

        return materialize_clause_pcap_slice(Path(meta["workspace"]), clause_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/runs/{run_id}/artifacts/{artifact_id}")
def get_artifact(run_id: str, artifact_id: str):
    """按受控 artifact-id 读取小型文本或打开独立 HTML 报告。"""
    meta = _runs.get(run_id)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"run 不存在: {run_id}")
    ws = Path(meta["workspace"]).resolve()
    entry = _artifact_catalog(ws).get(artifact_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="artifact 不存在或不允许公开")
    target = (ws / entry["path"]).resolve()
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="artifact 源文件不存在")
    if target.suffix in _ARTIFACT_TEXT_SUFFIXES:
        if target.stat().st_size > _MAX_ARTIFACT_TEXT_BYTES:
            raise HTTPException(status_code=413, detail="文本 artifact 超过预览上限，请下载条款证据包")
        return JSONResponse({
            "artifact_id": artifact_id, "name": entry["name"],
            "content": target.read_text(encoding="utf-8", errors="replace"),
        })
    if target.suffix == ".html":
        return FileResponse(target, media_type="text/html")
    raise HTTPException(status_code=415, detail="该 artifact 类型不支持预览")


# ── 静态前端 ──
if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")


if __name__ == "__main__":
    import argparse
    import uvicorn

    ap = argparse.ArgumentParser(description="ETSI Framework Web Console")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    print(f"ETSI Web Console → http://{args.host}:{args.port}  (static: {STATIC_DIR})")
    uvicorn.run(app, host=args.host, port=args.port)
