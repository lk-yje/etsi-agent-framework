"""端到端管线测试 — 使用 Mock API + 最小 fixture 数据跑完整管线。

验证:
1. 管线状态机正确跃迁 INIT → ... → DONE
2. Work Agent 通过 AgentConfig + PromptCompiler 编译 prompt
3. Evidence 写入文件总线
4. 审计队列触发
5. 最终报告生成
"""

import json
import sys
import tempfile
from pathlib import Path
import pytest

# Make sure we can import from tests/ directory
sys.path.insert(0, str(Path(__file__).parent))
from mock_api import MockAPIClient, bind_mock_client

from contracts.module import PipelineDef
from framework.registry import AgentRegistry
from framework.orchestrator import AgentOrchestrator


@pytest.fixture
def fixtures_dir():
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def etsi_pipeline_def(fixtures_dir):
    """构建最小 ETSI 管线定义（仅用本地 fixture 文件）"""
    from contracts.module import ModuleDef

    # 最小 personas（用 fixture）
    work_persona = fixtures_dir / "work_persona_test.md"
    work_persona.write_text(
        "## 角色\n你是 ETSI 检测员\n"
        "## 约束\n不编造结果。FAIL 必附证据。\n"
        "## 输出\n按 evidence-schema.json 格式输出 JSON\n",
        encoding="utf-8",
    )

    audit_persona = fixtures_dir / "audit_persona_test.md"
    audit_persona.write_text(
        "## 角色\n你是 ETSI 审计专家\n"
        "## 约束\n不做补充测试。只读文件。\n"
        "## 输出\n按 audit-output-schema.json 格式输出 JSON\n",
        encoding="utf-8",
    )

    clause_ref = fixtures_dir / "clause_ref_test.md"
    clause_ref.write_text("## 条款参考\n5.6-1: 接口文档化\n5.6-2: 信息泄露\n", encoding="utf-8")

    verdict = fixtures_dir / "verdict_test.md"
    verdict.write_text("## 裁决条件\nPASS: 所有条件满足\n", encoding="utf-8")

    audit_checklist = fixtures_dir / "audit_checklist_test.md"
    audit_checklist.write_text("## 审计判断细则\n5.6-1: 检查 nmap vs IXIT\n", encoding="utf-8")

    common_errors = fixtures_dir / "common_errors_test.md"
    common_errors.write_text("## 常见误判\nescape_clause 被忽略\n", encoding="utf-8")

    evidence_standards = fixtures_dir / "evidence_standards_test.md"
    evidence_standards.write_text("## 证据分级\nL1: 完整可复现\n", encoding="utf-8")

    modules = tuple(
        ModuleDef(
            id=f"M{i}",
            name=f"Test Module {i}",
            clauses=("5.6-1", "5.6-2") if i == 1 else ("5.6-5",),
            ammo_paths=(),
            tools=(),
        )
        for i in range(1, 6)
    )

    return PipelineDef(
        name="etsi-ts103701",
        description="ETSI test pipeline",
        modules=modules,
        work_agent_persona=work_persona,
        audit_agent_persona=audit_persona,
        shared_knowledge=(clause_ref, verdict),
        audit_only_knowledge=(audit_checklist, common_errors, evidence_standards),
        work_ammo_knowledge=(),
        required_tokens=(
            ".evidence_M1_complete", ".evidence_M2_complete",
            ".evidence_M3_complete", ".evidence_M4_complete",
            ".evidence_M5_complete",
            ".audit_M1_ACCEPTED", ".audit_M2_ACCEPTED",
            ".audit_M3_ACCEPTED", ".audit_M4_ACCEPTED",
            ".audit_M5_ACCEPTED",
            ".audit_ROUND2_ACCEPTED",
        ),
        phase_gate_script=Path("dummy.py"),
        pipeline_class="pipelines.etsi.pipeline.ETSIPipeline",
    )


class TestE2EPipeline:
    """端到端管线测试"""

    @staticmethod
    def _empty_path_resolver():
        """创建空的 PathResolver（不加载真实工具路径，避免启动 tshark/xray）"""
        from framework.path_resolver import PathResolver
        return PathResolver(Path("__nonexistent_path_mapping__.json"))

    @pytest.mark.skip(reason="E2E full pipeline requires mock API with tool-use loop support — run manually")
    def test_full_pipeline_runs_to_completion(self, fixtures_dir, etsi_pipeline_def):
        """完整管线 INIT → DONE（Mock API）"""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            workspace = Path(tmp)

            # 复制 ixit fixture 到工作区
            ixit_src = fixtures_dir / "mini_ixit.json"
            (workspace / "ixit.json").write_text(
                ixit_src.read_text(encoding="utf-8"),
            )

            # 注册管线
            registry = AgentRegistry(Path("skills"))
            registry.register_pipeline("etsi-ts103701", etsi_pipeline_def)
            violations = registry.verify_isolation()
            assert len(violations) == 0, f"Isolation violations: {violations}"

            # 创建 Mock API 客户端
            api_client = MockAPIClient(fixtures_dir)
            bind_mock_client(api_client)

            # 创建编排器并运行
            orchestrator = AgentOrchestrator(
                workspace, registry, api_client,
                non_interactive=True,
                path_resolver=self._empty_path_resolver(),
            )

            import asyncio
            result = asyncio.run(orchestrator.run_pipeline("etsi-ts103701"))

            # 验证管线完成
            assert result.current_state.value == "done", (
                f"Expected DONE, got {result.current_state.value}"
            )

            # 验证产物
            bus = orchestrator.bus
            assert bus.evidence_count() >= 5, f"Expected >=5 evidence files, got {bus.evidence_count()}"
            assert bus.audit_count() >= 5, f"Expected >=5 audit files, got {bus.audit_count()}"

            # 验证报告已生成 (文件名动态生成, 用 glob 匹配)
            reports = list(workspace.glob("认证检测报告_*.md"))
            assert len(reports) > 0, f"Report not generated in {workspace}"
            report = reports[0]
            report_content = report.read_text(encoding="utf-8")
            assert "ETSI TS 103 701" in report_content
            assert "| 条款 | 裁决 |" in report_content
            # REPORT 阶段同时固化 Web/下载共用数据与条款证据包；Markdown 原始记录仍保留。
            assert (workspace / "reports" / "report-data.json").is_file()
            assert list((workspace / "reports").glob("认证检测报告_*.html"))
            assert (workspace / "evidence-packages" / "manifest.json").is_file()

    @pytest.mark.skip(reason="E2E full pipeline requires mock API with tool-use loop support — run manually")
    def test_pipeline_evidence_files_valid(self, fixtures_dir, etsi_pipeline_def):
        """生成的 evidence 文件可被 Pydantic 解析"""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            workspace = Path(tmp)

            ixit_src = fixtures_dir / "mini_ixit.json"
            (workspace / "ixit.json").write_text(ixit_src.read_text(encoding="utf-8"))

            registry = AgentRegistry(Path("skills"))
            registry.register_pipeline("etsi-ts103701", etsi_pipeline_def)

            api_client = MockAPIClient(fixtures_dir)
            bind_mock_client(api_client)

            orchestrator = AgentOrchestrator(
                workspace, registry, api_client,
                non_interactive=True,
                path_resolver=self._empty_path_resolver(),
            )

            import asyncio
            asyncio.run(orchestrator.run_pipeline("etsi-ts103701"))

            # 验证每个 evidence 文件
            from contracts.evidence import EvidenceManifest

            for ev_file in orchestrator.bus.list_evidence_files():
                data = json.loads(ev_file.read_text(encoding="utf-8"))
                evidence = EvidenceManifest(**data)
                assert len(evidence.execution_trace) > 0
                assert evidence.self_check is not None

    @pytest.mark.skip(reason="E2E full pipeline requires mock API with tool-use loop support — run manually")
    def test_pipeline_handles_missing_ixit(self, fixtures_dir, etsi_pipeline_def):
        """缺少 ixit.json → ENV_CHECK 阶段应自动复制 fixture"""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            workspace = Path(tmp)
            # 不复制 ixit.json — orchestrator 应该从 fixture 自动复制

            registry = AgentRegistry(Path("skills"))
            registry.register_pipeline("etsi-ts103701", etsi_pipeline_def)

            api_client = MockAPIClient(fixtures_dir)
            bind_mock_client(api_client)

            orchestrator = AgentOrchestrator(
                workspace, registry, api_client,
                non_interactive=True,
                path_resolver=self._empty_path_resolver(),
            )

            import asyncio
            result = asyncio.run(orchestrator.run_pipeline("etsi-ts103701"))

            # 应该自动复制了 fixture
            ixit = workspace / "ixit.json"
            assert ixit.exists(), "ixit.json should have been auto-copied from fixture"

    def test_isolation_enforced_on_work_agents(self, fixtures_dir, etsi_pipeline_def):
        """Work Agent 的 prompt 编译会强制执行隔离检查"""
        from pipelines.etsi.agents import WORK_AGENT_FORBIDDEN
        from framework.agent_runner import PromptCompiler, IsolationViolation, AgentConfig

        modules = [m for m in etsi_pipeline_def.modules if m.id == "M1"]
        for module in modules:
            config = AgentConfig(
                agent_id=f"work_{module.id}_v1",
                agent_type="work",
                persona_path=etsi_pipeline_def.work_agent_persona,
                knowledge_paths=etsi_pipeline_def.shared_knowledge + module.ammo_paths,
                tool_manifest=module.tools,
                forbidden_patterns=WORK_AGENT_FORBIDDEN,
            )
            # 验证: 干净的配置 → 编译成功
            prompt = PromptCompiler.compile(config, {
                "task": "test",
                "workspace": "/tmp",
            })
            assert len(prompt) > 0
            assert "ETSI" in prompt
            # 验证: 不包含审计关键词
            for forbidden in PromptCompiler.DEFAULT_FORBIDDEN:
                assert forbidden not in prompt, (
                    f"Work Agent prompt 包含禁止模式: '{forbidden}'"
                )
