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
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── 项目根目录（server.py 所在目录的上级）──
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from framework.preflight import collect_environment_preflight
from framework.input_manager import reference_firmware_sample, reference_ixit_source, write_run_config
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
    try:
        numeric_pid = int(pid)
        if numeric_pid <= 0:
            return False
        os.kill(numeric_pid, 0)
        return True
    except (TypeError, ValueError, ProcessLookupError, OSError):
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
    burp_token: Optional[str] = None
    burp_host: Optional[str] = None
    burp_port: Optional[int] = None
    no_playwright: bool = False
    mock: bool = False


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


class WorkspaceCreate(BaseModel):
    name: str


class FirmwareReference(BaseModel):
    path: str


class LocalInputReference(BaseModel):
    path: str


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


def _derive_cancellation(ws: Path, meta: dict, traffic: dict, state: dict | None) -> dict:
    """把协作取消的事实拆为可观察步骤，绝不把“请求”显示为“已停止”。"""
    history = traffic.get("history", []) if isinstance(traffic, dict) else []
    by_event = {entry.get("event"): entry for entry in history if isinstance(entry, dict)}
    requested = (ws / "tokens" / ".cancel_requested").exists() or meta.get("status") == "cancellation_requested"
    pipeline_state = (state or {}).get("current_state")
    terminal = pipeline_state == "cancelled"
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


def _derive_modules(ws: Path) -> dict:
    """推导 M0-M5 各模块状态。"""
    modules = {}
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
            "flagged": audit_status == "REVIEW_REQUIRED",
            "retry_count": meta.get("retryCount", meta.get("retry_count", 0)),
            "status": meta.get("status", "not_started"),
        }
    return modules


_MODULE_NAMES = {
    "M0": "ICS 逻辑验证与概念性测试",
    "M1": "端口扫描与服务发现",
    "M2": "认证机制测试",
    "M3": "TLS 与通信分析",
    "M4": "软件更新与硬件安全",
    "M5": "漏洞扫描与数据保护",
}


def _derive_agents(events: list[dict]) -> list[dict]:
    """按 agent_id 聚合进行中/已完成状态。"""
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


@app.post("/api/preflight")
def preflight(req: PreflightRequest) -> dict:
    """执行离线 preflight，并可将快照保存到已授权 workspace。"""
    result = collect_environment_preflight(
        RUNTIME_SETTINGS,
        dut_ip=req.dut_ip,
        include_versions=req.include_versions,
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


@app.post("/api/workspaces/{workspace_id}/inputs/firmware/{role}")
def upload_firmware_deprecated(workspace_id: str, role: str) -> dict:
    """保留旧路由的明确拒绝，避免误以为浏览器上传是当前证据策略。"""
    raise HTTPException(
        status_code=410,
        detail="固件不再上传或复制；请使用 /reference 登记工作机受控目录中的本地路径。",
    )


@app.post("/api/runs", status_code=201)
def start_run(req: RunCreate) -> dict:
    try:
        ws = RUNTIME_SETTINGS.resolve_workspace(req.workspace, create=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    active_statuses = {"starting", "running", "cancellation_requested", "stopping", "orphaned"}
    if any(
        Path(meta.get("workspace", "")).resolve() == ws.resolve()
        and meta.get("status") in active_statuses
        for meta in _runs.values()
    ):
        raise HTTPException(status_code=409, detail="该 workspace 已有活动或未托管 run；请先确认其终态")
    existing_state = _safe_read(ws / "pipeline_state.json")
    if existing_state and existing_state.get("current_state") not in {"done", "needs_review", "cancelled", "failed"}:
        raise HTTPException(status_code=409, detail="该 workspace 存在未完成 Pipeline；恢复功能尚未开放，不能创建第二个 run")
    (ws / "tokens").mkdir(exist_ok=True)
    # 只清除本次 run 的明确取消控制信号，避免复用 workspace 时误取消新进程。
    (ws / "tokens" / ".cancel_requested").unlink(missing_ok=True)

    run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    meta: dict = {
        "run_id": run_id,
        "workspace": str(ws),
        "pipeline": req.pipeline,
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "status": "starting",
        "dut_ip": req.dut_ip,
    }
    write_run_config(
        ws,
        {
            "run_id": run_id,
            "pipeline": req.pipeline,
            "created_at": meta["started_at"],
            "dut_ip": req.dut_ip,
            "burp_host": req.burp_host,
            "burp_port": req.burp_port,
            "no_playwright": req.no_playwright,
            "simulation": req.mock,
        },
    )

    cmd = RunManager.build_command(
        workspace=ws, pipeline=req.pipeline, mock=req.mock, no_playwright=req.no_playwright,
    )
    child_env = RunManager.build_env(
        burp_token=req.burp_token, burp_host=req.burp_host, burp_port=req.burp_port,
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
        "status": "running",
        "command": " ".join(cmd),
    }


def _run_status(run_id: str) -> dict:
    meta = _runs.get(run_id)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"run 不存在: {run_id}")
    running, orphaned = _reconcile_run(meta)

    ws = Path(meta["workspace"])

    # 1. pipeline_state
    state = _safe_read(ws / "pipeline_state.json")
    current_state = state.get("current_state") if state else None

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
            "exists": state is not None,
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
        "modules": _derive_modules(ws),
        "agents": _derive_agents(events),
        "traffic": traffic,
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
