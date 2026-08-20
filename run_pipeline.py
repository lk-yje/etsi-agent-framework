"""ETSI Agent Framework — CLI 工具箱 + 管线运行入口。

命令:
    # 管线运行 (v0.3 — 代码驱动管线 + MCP SDK)
    python run_pipeline.py run --workspace <path> [--mock] [--non-interactive]
        [--burp-token <token>] [--burp-host <host>] [--burp-port <port>]
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
    p.add_argument("--mock", action="store_true", help="使用 Mock API 客户端（测试用）")
    p.add_argument("--non-interactive", action="store_true", help="非交互模式（跳过用户确认）")
    p.add_argument("--control-mode", default="terminal",
                   choices=["terminal", "web"],
                   help="流量采集确认方式: terminal=终端 input() (默认), web=轮询控制文件 (前端驱动)")
    p.add_argument("--burp-token", default=None, help="BurpMCP Bearer Token")
    p.add_argument("--burp-host", default=None, help="BurpMCP 主机 (默认 127.0.0.1)")
    p.add_argument("--burp-port", type=int, default=None, help="BurpMCP 端口 (默认 9876)")
    p.add_argument("--no-playwright", action="store_true", help="不启动 Playwright MCP")
    p.add_argument("--skills-root", default=None, help="skills 根目录 (默认: 项目内 skills/ → fallback ~/.claude/skills)")

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
        # AgentRunner 的消息调用是 async；必须使用异步客户端，
        # 否则真实 API 响应对象会在 await 时失败（mock 不会暴露此问题）。
        api_client = anthropic.AsyncAnthropic(
            api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
            base_url=os.environ.get("ANTHROPIC_BASE_URL", None),
        )

    # MCP 连接
    from framework.mcp_client import MCPClientManager

    mcp_manager = MCPClientManager()
    await mcp_manager.__aenter__()

    mcp_status = {"burp": False, "playwright": False}

    # Burp MCP (SSE)
    burp_token = args.burp_token or os.environ.get("BURP_MCP_TOKEN", "")
    if burp_token:
        mcp_status["burp"] = await mcp_manager.connect_burp(
            host=args.burp_host,
            port=args.burp_port,
            token=burp_token,
        )
    else:
        print(json.dumps({"info": "Burp MCP skipped — no BURP_MCP_TOKEN set"}, ensure_ascii=False), file=sys.stderr)

    # Playwright MCP (stdio)
    if not args.no_playwright:
        mcp_status["playwright"] = await mcp_manager.connect_playwright()
    else:
        print(json.dumps({"info": "Playwright MCP skipped via --no-playwright"}, ensure_ascii=False), file=sys.stderr)

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
        result = await orchestrator.run_pipeline(args.pipeline)
        return {
            "status": "ok",
            "pipeline_id": result.pipeline_id,
            "final_state": result.current_state.value if result.current_state else "unknown",
            "mcp": mcp_status,
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "mcp": mcp_status,
        }
    finally:
        await mcp_manager.__aexit__(None, None, None)


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
