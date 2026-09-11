"""ETSI Agent Framework — CLI 工具箱 + 管线运行入口。

命令:
    # 管线运行 (v0.3 — 代码驱动管线 + MCP SDK)
    python run_pipeline.py run --workspace <path> [--mock] [--non-interactive]
        [--burp-host <host>] [--burp-port <port>]
        [--no-playwright]

    # 工作区管理
    python run_pipeline.py workspace-init --path <path>
    python run_pipeline.py workspace-status --path <path>

    # 查询工具
    python run_pipeline.py wait-file --path <file> --timeout 1800
    python run_pipeline.py query-evidence --path <file> [--field <path>]
    python run_pipeline.py query-tokens --workspace <path>
    python run_pipeline.py query-report-data --workspace <path>
    python run_pipeline.py query-list-evidence --workspace <path>

所有命令返回 JSON 到 stdout。
"""

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(prog="run_pipeline.py", description="ETSI Agent Framework CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- run: 运行完整管线 ---
    p = subparsers.add_parser("run", help="运行 ETSI 认证检测管线")
    p.add_argument("--workspace", required=True, help="工作区路径")
    p.add_argument("--pipeline", default="etsi-ts103701", help="管线名称 (默认 etsi-ts103701)")
    p.add_argument("--profile", default="certification-full", choices=[
        "certification-full", "functional-smoke", "functional-module", "audit-only", "report-rebuild",
    ], help="运行目标；非认证 profile 会创建独立 runs/ 工作区")
    p.add_argument("--modules", nargs="*", default=[], help="functional-module 的 M1–M5 模块")
    p.add_argument("--run-workspace-ready", action="store_true",
                   help="调用方已创建隔离 run 根；仅供 Web 控制台使用")
    p.add_argument("--mock", action="store_true", help="使用 Mock API 客户端（测试用）")
    p.add_argument("--non-interactive", action="store_true", help="非交互模式（跳过用户确认）")
    p.add_argument("--control-mode", default="terminal",
                   choices=["terminal", "web"],
                   help="流量采集确认方式: terminal=终端 input() (默认), web=轮询控制文件 (前端驱动)")
    p.add_argument("--burp-host", default=None, help="BurpMCP 主机 (默认 127.0.0.1)")
    p.add_argument("--burp-port", type=int, default=None, help="BurpMCP 端口 (默认 9876)")
    p.add_argument("--no-playwright", action="store_true", help="已禁用：ETSI 本地测试必须连接 Playwright MCP")
    p.add_argument("--resume-failed", action="store_true", help="恢复失败的 M0 概念阶段，复用有效条款快照")
    p.add_argument("--resume-cancelled-m0-audit", action="store_true",
                   help="恢复被安全停止的 M0 审计；保留 M0 概念证据和 L1 结果")
    p.add_argument("--resume-failed-m0-audit", action="store_true",
                    help="恢复失败的 M0 审计；保留 M0 概念证据和 L1 结果")
    p.add_argument("--resume-m1m5", action="store_true",
                    help="从 M1–M5 失败/停止快照恢复；重新确认 Traffic，并复用 digest 匹配的 phase")
    p.add_argument("--resume-traffic", action="store_true",
                    help="从 Traffic 前置连接失败点恢复；保留既有工作区与 M0 快照")
    p.add_argument("--skills-root", default=None, help="skills 根目录 (默认: 项目内 skills/ → fallback ~/.claude/skills)")

    # --- plan: 仅解析运行目标，不连接 DUT、不启动 Agent ---
    p = subparsers.add_parser("plan", help="预览运行模式 DAG 与认证边界")
    p.add_argument("--profile", required=True, choices=[
        "certification-full", "functional-smoke", "functional-module", "audit-only", "report-rebuild",
    ])
    p.add_argument("--modules", nargs="*", default=[], help="functional-module 的 M1–M5 模块")

    # --- workspace 管理 ---
    p = subparsers.add_parser("workspace-init", help="创建工作区目录")
    p.add_argument("--path", required=True)

    p = subparsers.add_parser("workspace-status", help="查询工作区状态")
    p.add_argument("--path", required=True)

    p = subparsers.add_parser("wait-file", help="轮询等待文件就绪")
    p.add_argument("--path", required=True)
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--interval", type=float, default=5.0)

    p = subparsers.add_parser("query-evidence", help="查询 evidence JSON")
    p.add_argument("--path", required=True)
    p.add_argument("--field", default=None)

    p = subparsers.add_parser("query-tokens", help="查询令牌状态")
    p.add_argument("--workspace", required=True)

    p = subparsers.add_parser("query-report-data", help="汇总报告数据")
    p.add_argument("--workspace", required=True)

    p = subparsers.add_parser("query-list-evidence", help="列出 evidence 文件")
    p.add_argument("--workspace", required=True)

    args = parser.parse_args()
    try:
        result = _dispatch(args)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        # 子进程退出码是 Web RunManager 判断成功/失败的第一信号。
        # 结构化 error 或未到 DONE 的 run 均不得以 exit 0 伪装成功。
        if result.get("status") != "ok":
            sys.exit(1)
        if args.command == "run" and result.get("final_state") != "done":
            sys.exit(1)
    except Exception as e:
        print(json.dumps({"status": "error", "error": str(e)}, ensure_ascii=False))
        sys.exit(1)


def _dispatch(args) -> dict:
    cmd = args.command

    if cmd == "run":
        return asyncio.run(_run_pipeline(args))

    elif cmd == "plan":
        from framework.run_planner import build_run_plan
        return {"status": "ok", "plan": build_run_plan(args.profile, args.modules).model_dump(mode="json", by_alias=True)}

    elif cmd == "workspace-init":
        from framework.workspace import init_workspace
        return init_workspace(args.path)

    elif cmd == "workspace-status":
        from framework.workspace import workspace_status
        return workspace_status(args.path)

    elif cmd == "wait-file":
        return _wait_file(args)

    elif cmd == "query-evidence":
        return _query_evidence(args)

    elif cmd == "query-tokens":
        from framework.workspace import workspace_status
        ws = workspace_status(args.workspace)
        return {"status": "ok", "tokens_present": ws["tokens_present"], "tokens_missing": ws["tokens_missing"]}

    elif cmd == "query-report-data":
        return _query_report_data(args)

    elif cmd == "query-list-evidence":
        from framework.workspace import workspace_status
        ws = workspace_status(args.workspace)
        return {"status": "ok", "evidence_files": ws["evidence_files"], "audit_files": ws["audit_files"]}

    return {"status": "error", "error": f"未知命令: {cmd}"}


# ============================================================
# run 命令 — 运行完整管线
# ============================================================


async def _run_pipeline(args) -> dict:
    """运行 ETSI 认证检测管线。

    1. 初始化 MCPClientManager (Burp SSE + Playwright stdio)
    2. 注册 ETSI 管线到 AgentRegistry
    3. 创建 AgentOrchestrator 并驱动管线到完成
    """
    workspace = Path(args.workspace).resolve()
    from framework.run_planner import build_run_plan
    from framework.run_workspace import create_isolated_run_workspace
    run_plan = build_run_plan(args.profile, args.modules)
    if not run_plan.certification_claim:
        if args.profile not in ("functional-smoke", "functional-module"):
            raise ValueError(f"{args.profile} 当前仅支持 plan 预览，执行器尚未实现")
        if args.resume_failed or args.resume_cancelled_m0_audit or args.resume_failed_m0_audit:
            raise ValueError("非认证 profile 不使用 M0 恢复参数；每次运行创建独立 runs/ 快照")
        if not args.run_workspace_ready:
            workspace = create_isolated_run_workspace(workspace, run_plan)
    from contracts.pipeline import PipelineState
    if sum((args.resume_failed, args.resume_cancelled_m0_audit, args.resume_failed_m0_audit, args.resume_m1m5, args.resume_traffic)) > 1:
        raise ValueError("一次只能选择一种恢复模式")
    if args.resume_failed:
        _resume_failed_m0_concept(workspace)
    if args.resume_cancelled_m0_audit:
        _resume_m0_audit(workspace, PipelineState.CANCELLED)
    if args.resume_failed_m0_audit:
        _resume_m0_audit(workspace, PipelineState.FAILED)
    if args.resume_m1m5:
        _resume_m1m5_via_traffic(workspace)
        os.environ["SNAPSHOT_RESUME"] = "1"
    if args.resume_traffic:
        _resume_traffic(workspace)
    if args.no_playwright:
        return {
            "status": "blocked",
            "error": "Playwright MCP 是本地 ETSI 测试的强制通道，禁止 --no-playwright 降级运行。",
        }
    # 优先使用项目内 skills/，fallback 到 ~/.claude/skills
    if args.skills_root:
        skills_root = Path(args.skills_root)
    else:
        _local_skills = Path(__file__).parent / "skills"
        skills_root = _local_skills if _local_skills.is_dir() else Path.home() / ".claude" / "skills"

    # API 客户端
    if args.mock:
        from tests.mock_api import MockAPIClient, bind_mock_client
        _fixtures = Path(__file__).resolve().parent / "tests" / "fixtures"
        api_client = bind_mock_client(MockAPIClient(fixtures_dir=_fixtures))
    else:
        import anthropic
        from framework.model_credentials import load_model_credentials
        from framework.model_config import get_configured_model

        credentials = load_model_credentials()
        get_configured_model()
        if not credentials["ANTHROPIC_API_KEY"] and not credentials["ANTHROPIC_AUTH_TOKEN"]:
            raise RuntimeError(
                "未配置模型凭据：请在 ~/.claude/settings.json 的 env 中设置 "
                "ANTHROPIC_AUTH_TOKEN 或 ANTHROPIC_API_KEY。"
            )
        # AgentRunner 的消息调用是 async；必须使用异步客户端，
        # 否则真实 API 响应对象会在 await 时失败（mock 不会暴露此问题）。
        api_client = anthropic.AsyncAnthropic(
            api_key=credentials["ANTHROPIC_API_KEY"],
            auth_token=credentials["ANTHROPIC_AUTH_TOKEN"],
            base_url=credentials["ANTHROPIC_BASE_URL"],
            # 显式超时：跳过 SDK 1.0 对非流式 max_tokens>21333 的"必须流式"检查，
            # 保留 32000 输出预算，避免复杂条款输出截断。
            timeout=3600.0,
        )

    # MCP 连接
    from framework.mcp_client import MCPClientManager

    mcp_manager = MCPClientManager(workspace=workspace)
    await mcp_manager.__aenter__()

    mcp_status = {"burp": False, "playwright": False}

    # Burp MCP (SSE)
    mcp_status["burp"] = await mcp_manager.connect_burp(
        host=args.burp_host,
        port=args.burp_port,
    )

    # Playwright MCP (stdio)
    mcp_status["playwright"] = await mcp_manager.connect_playwright()
    # 这是本次运行的连接事实快照，供 Web Traffic 面板展示；不能把“尝试连接”
    # 误显示成“已就绪”。不包含 token 等敏感值。
    (workspace / "mcp_status.json").write_text(
        json.dumps({
            "burp": {
                "connected": mcp_status["burp"],
                "reason": None if mcp_status["burp"] else "Burp MCP 连接失败",
            },
            "playwright": {
                "connected": mcp_status["playwright"],
                "reason": None if mcp_status["playwright"] else mcp_manager.playwright_error,
            },
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if not mcp_status["playwright"]:
        await mcp_manager.__aexit__(None, None, None)
        return {
            "status": "blocked",
            "error": mcp_manager.playwright_error or "Playwright MCP 未就绪",
            "mcp": mcp_status,
        }

    # 注册管线
    from framework.registry import AgentRegistry
    from pipelines.etsi.registry import register as register_etsi

    registry = AgentRegistry(skills_root)
    register_etsi(registry, skills_root)
    registry.verify_or_raise()

    # 创建编排器并运行
    from framework.orchestrator import AgentOrchestrator

    orchestrator = AgentOrchestrator(
        workspace=workspace,
        registry=registry,
        api_client=api_client,
        non_interactive=args.non_interactive,
        mcp_manager=mcp_manager,
        control_mode=args.control_mode,
    )

    try:
        result = await orchestrator.run_pipeline(args.pipeline, run_plan=run_plan)
        return {
            "status": "ok",
            "pipeline_id": result.pipeline_id,
            "final_state": result.current_state.value if result.current_state else "unknown",
            "mcp": mcp_status,
            "run_profile": run_plan.profile.value,
            "certification_claim": run_plan.certification_claim,
            "workspace": str(workspace),
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "mcp": mcp_status,
        }
    finally:
        await mcp_manager.__aexit__(None, None, None)


def _resume_failed_m0_concept(workspace: Path) -> None:
    """显式解除 M0 概念阶段失败终态；不修改已有 evidence/checkpoint。"""
    from contracts.pipeline import PipelineSnapshot, PipelineState, StageStatus

    state_path = workspace / "pipeline_state.json"
    if not state_path.exists():
        raise ValueError("未找到 pipeline_state.json，无法从失败点恢复")
    snapshot = PipelineSnapshot.model_validate_json(state_path.read_text(encoding="utf-8"))
    if (snapshot.current_state != PipelineState.FAILED
            or snapshot.stage_statuses.get(PipelineState.M0_CONCEPT.value) != StageStatus.FAILED):
        raise ValueError("--resume-failed 仅适用于 current_state=failed 且 m0_concept=failed 的工作区")

    audit_dir = workspace / "audit" / "resume-history"
    audit_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    audit_path = audit_dir / f"m0_concept_failed_{timestamp}.json"
    audit_path.write_text(json.dumps({
        "action": "resume_failed_m0_concept",
        "resumed_at": datetime.now().isoformat(timespec="seconds"),
        "previous_snapshot": snapshot.model_dump(mode="json"),
        "reason": "explicit --resume-failed; preserve valid M0 clause checkpoints",
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    snapshot.current_state = PipelineState.M0_CONCEPT
    snapshot.stage_statuses[PipelineState.M0_CONCEPT.value] = StageStatus.PENDING
    snapshot.failed_stages = [x for x in snapshot.failed_stages if x != PipelineState.M0_CONCEPT.value]
    snapshot.errors = [x for x in snapshot.errors if not x.startswith("m0_concept:")]
    snapshot.updated_at = datetime.now()
    tmp_path = state_path.with_suffix(".json.resume.tmp")
    tmp_path.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
    tmp_path.replace(state_path)


def _resume_m1m5_via_traffic(workspace: Path) -> None:
    """恢复 M1–M5 前强制回到 Traffic；PhaseEngine 仅复用 digest 匹配的 phase。"""
    from contracts.pipeline import PipelineSnapshot, PipelineState, StageStatus

    state_path = workspace / "pipeline_state.json"
    if not state_path.exists():
        raise ValueError("未找到 pipeline_state.json，无法恢复 M1–M5")
    snapshot = PipelineSnapshot.model_validate_json(state_path.read_text(encoding="utf-8"))
    m1_status = snapshot.stage_statuses.get(PipelineState.M1_M5_PARALLEL.value)
    interrupted_after_safe_stop = (
        snapshot.current_state == PipelineState.M1_M5_PARALLEL
        and (workspace / "tokens" / ".cancel_requested").exists()
    )
    if ((snapshot.current_state not in (PipelineState.FAILED, PipelineState.CANCELLED)
         and not interrupted_after_safe_stop)
            or m1_status not in (StageStatus.FAILED, StageStatus.IN_PROGRESS, StageStatus.AWAITING_GATE)):
        raise ValueError("--resume-m1m5 仅适用于停在 M1–M5 的 failed/cancelled 快照，或带安全停止令牌的重启中断快照")
    history = workspace / "audit" / "resume-history"
    history.mkdir(parents=True, exist_ok=True)
    (history / f"m1m5_via_traffic_{datetime.now():%Y%m%d_%H%M%S}.json").write_text(json.dumps({
        "action": "resume_m1m5_via_traffic", "resumed_at": datetime.now().isoformat(),
        "previous_snapshot": snapshot.model_dump(mode="json"),
        "interrupted_after_safe_stop": interrupted_after_safe_stop,
        "rule": "Traffic is non-idempotent: re-confirm before phase snapshot reuse.",
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    snapshot.current_state = PipelineState.TRAFFIC_COLLECT
    snapshot.stage_statuses[PipelineState.TRAFFIC_COLLECT.value] = StageStatus.PENDING
    snapshot.stage_statuses[PipelineState.M1_M5_PARALLEL.value] = StageStatus.PENDING
    snapshot.failed_stages = [stage for stage in snapshot.failed_stages
                              if stage not in (PipelineState.TRAFFIC_COLLECT.value, PipelineState.M1_M5_PARALLEL.value)]
    snapshot.errors.append("M1–M5 resume requested: Traffic must be reconfirmed; matching phase snapshots may be reused.")
    snapshot.updated_at = datetime.now()
    tmp = state_path.with_suffix(".json.resume.tmp")
    tmp.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
    tmp.replace(state_path)
    (workspace / "tokens" / ".cancel_requested").unlink(missing_ok=True)


def _resume_traffic(workspace: Path) -> None:
    """从 Traffic 前置条件失败点恢复，不重跑 M0 或要求重新填写输入。"""
    from contracts.pipeline import PipelineSnapshot, PipelineState, StageStatus

    state_path = workspace / "pipeline_state.json"
    if not state_path.exists():
        raise ValueError("未找到 pipeline_state.json，无法恢复 Traffic")
    snapshot = PipelineSnapshot.model_validate_json(state_path.read_text(encoding="utf-8"))
    traffic_status = snapshot.stage_statuses.get(PipelineState.TRAFFIC_COLLECT.value)
    if (snapshot.current_state not in (PipelineState.NEEDS_REVIEW, PipelineState.FAILED, PipelineState.CANCELLED)
            or traffic_status != StageStatus.FAILED):
        raise ValueError("--resume-traffic 仅适用于 Traffic 前置失败的终态快照")
    history = workspace / "audit" / "resume-history"
    history.mkdir(parents=True, exist_ok=True)
    (history / f"traffic_{datetime.now():%Y%m%d_%H%M%S}.json").write_text(json.dumps({
        "action": "resume_traffic", "resumed_at": datetime.now().isoformat(),
        "previous_snapshot": snapshot.model_dump(mode="json"),
        "rule": "Traffic retry preserves prior M0 outputs and requires a new interactive capture attempt.",
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    snapshot.current_state = PipelineState.TRAFFIC_COLLECT
    snapshot.stage_statuses[PipelineState.TRAFFIC_COLLECT.value] = StageStatus.PENDING
    snapshot.failed_stages = [stage for stage in snapshot.failed_stages if stage != PipelineState.TRAFFIC_COLLECT.value]
    # 该恢复入口只针对 Traffic 前置失败。清掉已被显式重试的旧 Traffic
    # 终态标记，避免新一轮通过后仍被通用状态机收敛为 needs_review。
    snapshot.errors = [
        error for error in snapshot.errors
        if not error.startswith("Traffic retry requested")
    ]
    snapshot.review_reasons = [
        reason for reason in snapshot.review_reasons
        if not reason.startswith("Traffic BLOCKED:")
    ]
    snapshot.review_required = bool(snapshot.review_reasons)
    snapshot.updated_at = datetime.now()
    tmp = state_path.with_suffix(".json.resume.tmp")
    tmp.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
    tmp.replace(state_path)
    (workspace / "tokens" / ".cancel_requested").unlink(missing_ok=True)


def _resume_m0_audit(workspace: Path, expected_terminal_state) -> None:
    """从受控终态回到 M0 审计，不重跑概念性条款。"""
    from contracts.pipeline import PipelineSnapshot, PipelineState, StageStatus

    state_path = workspace / "pipeline_state.json"
    if not state_path.exists():
        raise ValueError("未找到 pipeline_state.json，无法恢复 M0 审计")
    snapshot = PipelineSnapshot.model_validate_json(state_path.read_text(encoding="utf-8"))
    required = workspace / "evidence" / "pre-M0-evidence.json"
    if (snapshot.current_state != expected_terminal_state
            or snapshot.stage_statuses.get(PipelineState.M0_AUDIT.value) != StageStatus.FAILED
            or not required.exists()):
        raise ValueError("仅可恢复停在 m0_audit 的、具有 M0 evidence 的工作区")

    audit_dir = workspace / "audit" / "resume-history"
    audit_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    (audit_dir / f"m0_audit_{expected_terminal_state.value}_{timestamp}.json").write_text(json.dumps({
        "action": "resume_m0_audit",
        "resumed_at": datetime.now().isoformat(timespec="seconds"),
        "previous_snapshot": snapshot.model_dump(mode="json"),
        "preserved_inputs": ["evidence/pre-M0-evidence.json", ".l1_M0_PASSED"],
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    snapshot.current_state = PipelineState.M0_AUDIT
    snapshot.stage_statuses[PipelineState.M0_AUDIT.value] = StageStatus.PENDING
    snapshot.failed_stages = [x for x in snapshot.failed_stages if x != PipelineState.M0_AUDIT.value]
    snapshot.errors = [x for x in snapshot.errors if x != "取消请求在阶段安全点被确认"]
    snapshot.gate_failures.pop("m0_audit->traffic", None)
    snapshot.updated_at = datetime.now()
    (workspace / "tokens" / ".cancel_requested").unlink(missing_ok=True)
    (workspace / "tokens" / ".audit_M0_ERROR").unlink(missing_ok=True)
    tmp_path = state_path.with_suffix(".json.resume.tmp")
    tmp_path.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
    tmp_path.replace(state_path)


# ============================================================
# 命令实现
# ============================================================


def _wait_file(args) -> dict:
    path = Path(args.path)
    elapsed = 0.0
    while elapsed < args.timeout:
        if path.exists() and path.stat().st_size > 0:
            return {"status": "ok", "path": str(path), "size_bytes": path.stat().st_size, "waited_seconds": round(elapsed, 1)}
        time.sleep(args.interval)
        elapsed += args.interval
    return {"status": "timeout", "path": str(path), "timeout_seconds": args.timeout,
            "exists": path.exists(), "size_bytes": path.stat().st_size if path.exists() else 0}


def _query_evidence(args) -> dict:
    path = Path(args.path)
    if not path.exists():
        return {"status": "error", "error": f"文件不存在: {path}"}
    data = json.loads(path.read_text(encoding="utf-8"))

    if not args.field:
        sc = data.get("selfCheck", data.get("self_check", {}))
        meta = data.get("meta", {})
        counts = {}
        for c in data.get("clauses", []):
            v = c.get("verdict", "?")
            counts[v] = counts.get(v, 0) + 1
        return {"status": "ok", "module": meta.get("moduleId", "?"),
                "clause_count": len(data.get("clauses", [])),
                "self_check": {"total_expected": sc.get("totalExpected", sc.get("total_expected")),
                               "actual_in_json": sc.get("actualInJson", sc.get("actual_in_json")),
                               "missing": sc.get("missingClauses", sc.get("missing_clauses", [])),
                               "has_errors": sc.get("hasErrors", sc.get("has_errors", False))},
                "verdicts": counts}
    return {"status": "ok", "field": args.field, "value": _resolve_field(data, args.field)}


def _query_report_data(args) -> dict:
    """提供 Web / CLI 共用的报告数据，唯一来源为 framework.reporting。"""
    from framework.reporting import load_report_data

    return {"status": "ok", **load_report_data(Path(args.workspace))}


# ============================================================
# 工具函数
# ============================================================


def _resolve_field(data: dict, field_path: str):
    parts = field_path.split(".")
    current = data
    for part in parts:
        if "[" in part and "=" in part:
            arr_name, rest = part.split("[", 1)
            condition = rest.rstrip("]")
            key, value = condition.split("=", 1)
            arr = current.get(arr_name, [])
            found = None
            for item in arr:
                if str(item.get(key, "")) == value:
                    found = item
                    break
            current = found
            if current is None:
                return None
        elif "[" in part:
            arr_name, rest = part.split("[", 1)
            idx = int(rest.rstrip("]"))
            current = current.get(arr_name, [])[idx]
        else:
            current = current.get(part) if isinstance(current, dict) else None
            if current is None:
                return None
    return current


def _extract_product_info(workspace: Path) -> dict:
    """从 ixit.json 提取产品信息（与 ReportGenerationStage 字段一致）。"""
    default = {
        "product_name": "Unknown",
        "model": "Unknown-Model",
        "product_version": "Unknown",
        "hardware_version": "Unknown",
        "firmware": "Unknown",
        "vendor": "Unknown",
        "device_type": "IoT 设备",
    }
    ixit_path = workspace / "ixit.json"
    if not ixit_path.exists():
        return default
    try:
        data = json.loads(ixit_path.read_text(encoding="utf-8"))
        # 新 schema: meta.dut_identification 为 {section: {field: value}} 嵌套结构
        dut_id = data.get("meta", {}).get("dut_identification", {})
        flat = {}
        if isinstance(dut_id, dict):
            for fields in dut_id.values():
                if isinstance(fields, dict):
                    for field, value in fields.items():
                        if field and value:
                            flat[str(field).lower()] = str(value)

        def grab(*keywords):
            for key, val in flat.items():
                if any(kw in key for kw in keywords):
                    return val
            return None

        return {
            "product_name": grab("product name", "device name") or "Unknown",
            "model": grab("model") or "Unknown-Model",
            "product_version": grab("product version", "device version") or "Unknown",
            "hardware_version": grab("hardware version", "hardware revision") or "Unknown",
            "firmware": grab("firmware", "software version") or "Unknown",
            "vendor": grab("vendor", "manufacturer", "supplier", "brand", "trade name", "organisation", "organization") or "Unknown",
            "device_type": grab("device type", "product category") or "IoT 设备",
        }
    except Exception:
        return default


def _extract_test_date(workspace: Path) -> str:
    state_path = workspace / "pipeline_state.json"
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            started = state.get("started_at", "")
            if started:
                return started[:10]
        except Exception:
            pass
    return datetime.now().strftime("%Y-%m-%d")


if __name__ == "__main__":
    main()
