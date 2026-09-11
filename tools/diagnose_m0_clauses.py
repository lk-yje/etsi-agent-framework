"""隔离执行 M0 Work Clause Agent + Auditor Agent，供审计分歧诊断使用。

不推进认证状态机、不发令牌、不改写正式 evidence；所有产物仅落在
``workspace/diagnostics/m0-agent-diagnosis``，因此可安全用于定位模型/提示词/合约问题。
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import anthropic

# 作为 ``python tools/diagnose_m0_clauses.py`` 执行时，Python 仅把 tools/
# 放入 sys.path；显式加入项目根，保持与 run_pipeline.py 相同的导入语义。
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from contracts.evidence import EvidenceManifest, SelfCheck
from framework.file_bus import FileBus
from framework.gate_checker import L2AuditGate
from framework.model_credentials import load_model_credentials
from framework.orchestrator import AgentOrchestrator
from framework.registry import AgentRegistry
from framework.telemetry import Telemetry
from pipelines.etsi.pipeline import M0AuditStage
from pipelines.etsi.registry import register as register_etsi
from framework.conceptual_catalog import load_conceptual_catalog
from framework.m0_concept import execute_conceptual_clause


async def diagnose(workspace: Path, clause_ids: list[str]) -> Path:
    skills_root = PROJECT_ROOT / "skills"
    credentials = load_model_credentials()
    if not credentials["ANTHROPIC_API_KEY"] and not credentials["ANTHROPIC_AUTH_TOKEN"]:
        raise RuntimeError("未配置 ANTHROPIC_API_KEY 或 ANTHROPIC_AUTH_TOKEN")
    client = anthropic.AsyncAnthropic(
        api_key=credentials["ANTHROPIC_API_KEY"],
        auth_token=credentials["ANTHROPIC_AUTH_TOKEN"],
        base_url=credentials["ANTHROPIC_BASE_URL"], timeout=3600.0,
    )
    registry = AgentRegistry(skills_root)
    register_etsi(registry, skills_root)
    registry.verify_or_raise()
    orchestrator = AgentOrchestrator(workspace, registry, client, non_interactive=True)
    pipe_def = registry.get_pipeline("etsi-ts103701")
    pipe = SimpleNamespace(
        runner=orchestrator.runner, tool_registry=orchestrator.tool_registry,
        pipe_def=pipe_def,
    )
    catalog = {item.clause_id: item for item in load_conceptual_catalog().clauses}
    unknown = sorted(set(clause_ids) - set(catalog))
    if unknown:
        raise ValueError(f"非 M0 概念条款: {unknown}")

    bus = FileBus(workspace)
    run_dir = workspace / "diagnostics" / "m0-agent-diagnosis" / datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for index, clause_id in enumerate(clause_ids, start=1):
        clause, trace = await execute_conceptual_clause(catalog[clause_id], workspace, pipe)
        work_path = run_dir / f"{clause_id}-work.json"
        work_path.write_text(json.dumps({
            "clause": clause.model_dump(mode="json", by_alias=True),
            "executionTrace": [step.model_dump(mode="json", by_alias=True) for step in trace],
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        source = EvidenceManifest(
            meta={"moduleId": "M0", "scope": "diagnostic"}, executionTrace=trace,
            clauses=[clause], selfCheck=SelfCheck(totalExpected=1, actualInJson=1),
        )
        audit_input = M0AuditStage._build_batch_evidence(
            source, [catalog[clause_id]], batch_index=index,
            batch_count=len(clause_ids), retry_count=0,
        )
        input_relative = str((run_dir / f"{clause_id}-audit-input.json").relative_to(workspace)).replace("\\", "/")
        output_relative = str((run_dir / f"{clause_id}-audit.json").relative_to(workspace)).replace("\\", "/")
        bus.write_json(input_relative, audit_input.model_dump(mode="json", by_alias=True))
        audit = await L2AuditGate("M0").run_audit(
            workspace, orchestrator.runner, pipe_def, evidence_path=input_relative,
            output_path=output_relative, audit_label=f"diagnose_{clause_id.replace('-', '_')}",
        )
        results.append({
            "clause_id": clause_id, "work_verdict": clause.verdict,
            "audit_verdict": audit.verdict, "findings": len(audit.findings),
            "work_file": work_path.name, "audit_file": f"{clause_id}-audit.json",
        })
    summary = {"created_at": datetime.now().isoformat(), "results": results}
    (run_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return run_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="M0 Work/Auditor isolated diagnosis")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--clauses", nargs="+", required=True)
    args = parser.parse_args()
    print(asyncio.run(diagnose(Path(args.workspace).resolve(), args.clauses)))


if __name__ == "__main__":
    main()
