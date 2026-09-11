"""注册表隔离验证测试 — 启动时管线级隔离检查"""

import tempfile
from pathlib import Path
import pytest

from contracts.module import ModuleDef, PipelineDef
from framework.agent_runner import PromptCompiler, AgentConfig
from framework.registry import AgentRegistry, RegistryViolation


def _temp_file(content: str) -> Path:
    tmp = tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w", encoding="utf-8")
    tmp.write(content)
    tmp.close()
    return Path(tmp.name)


def _make_work_persona() -> Path:
    return _temp_file("## 角色\n你是 ETSI 检测员\n## 约束\n不做破坏性操作\n")


def _make_audit_persona() -> Path:
    return _temp_file("## 角色\n你是 ETSI 审计专家\n## 约束\n不做补充测试\n")


def _make_clean_module() -> ModuleDef:
    return ModuleDef(
        id="M1",
        name="test module",
        clauses=("5.6-1",),
        ammo_paths=(),
        tools=(),
    )


class TestRegistryIsolationCleanPipeline:
    """干净的管线 → 零违规"""

    def test_clean_pipeline_passes(self):
        work_persona = _make_work_persona()
        audit_persona = _make_audit_persona()
        clause_ref = _temp_file("## 条款\n5.6-1\n")
        verdict = _temp_file("## 裁决\nPASS\n")
        audit_checklist = _temp_file("## 审计细则\n")
        common_errors = _temp_file("## 误判\n")

        pipeline_def = PipelineDef(
            name="test_clean",
            description="clean pipeline",
            modules=(_make_clean_module(),),
            work_agent_persona=work_persona,
            audit_agent_persona=audit_persona,
            shared_knowledge=(clause_ref, verdict),
            audit_only_knowledge=(audit_checklist, common_errors),
            work_ammo_knowledge=(),
            required_tokens=(),
            phase_gate_script=Path("dummy.py"),
        )

        registry = AgentRegistry(Path("skills"))
        registry.register_pipeline("test_clean", pipeline_def)
        violations = registry.verify_isolation()

        assert len(violations) == 0, f"期望零违规，实际: {violations}"


class TestRegistryIsolationDetectsContamination:
    """检测审计污染"""

    def test_audit_files_in_shared_detected(self):
        """审计专用文件出现在 shared_knowledge → 检测到违规"""
        work_persona = _make_work_persona()
        audit_persona = _make_audit_persona()
        audit_checklist = _temp_file("## audit-checklist\n")
        common_errors = _temp_file("## common-errors\n")

        pipeline_def = PipelineDef(
            name="contaminated",
            description="bad",
            modules=(_make_clean_module(),),
            work_agent_persona=work_persona,
            audit_agent_persona=audit_persona,
            shared_knowledge=(audit_checklist,),  # ← 污染!
            audit_only_knowledge=(audit_checklist, common_errors),
            work_ammo_knowledge=(),
            required_tokens=(),
            phase_gate_script=Path("dummy.py"),
        )

        registry = AgentRegistry(Path("skills"))
        registry.register_pipeline("contaminated", pipeline_def)
        violations = registry.verify_isolation()

        # 应该检测到审计文件被放入 shared_knowledge
        assert len(violations) > 0
        assert any("shared_knowledge" in v.lower() or "audit-checklist" in v.lower() for v in violations)

    def test_work_persona_contains_audit_pattern(self):
        """Work Agent persona 含禁止模式 → 检测到违规"""
        bad_persona = _temp_file("## 角色\n你是检测员\n完成后由审计 Agent etsi-report-auditor 审查\n")
        audit_persona = _make_audit_persona()
        clause_ref = _temp_file("## 条款\n")
        verdict = _temp_file("## 裁决\n")
        audit_checklist = _temp_file("## 审计细则\n")

        pipeline_def = PipelineDef(
            name="bad_persona",
            description="bad persona",
            modules=(_make_clean_module(),),
            work_agent_persona=bad_persona,
            audit_agent_persona=audit_persona,
            shared_knowledge=(clause_ref, verdict),
            audit_only_knowledge=(audit_checklist,),
            work_ammo_knowledge=(),
            required_tokens=(),
            phase_gate_script=Path("dummy.py"),
        )

        registry = AgentRegistry(Path("skills"))
        registry.register_pipeline("bad_persona", pipeline_def)
        violations = registry.verify_isolation()

        assert len(violations) > 0
        assert any("persona" in v.lower() or "etsi-report-auditor" in v.lower() for v in violations)


class TestRegistryVerifyOrRaise:
    """verify_or_raise 在违规时抛 RegistryViolation"""

    def test_clean_pipeline_does_not_raise(self):
        work_persona = _make_work_persona()
        audit_persona = _make_audit_persona()
        clause_ref = _temp_file("## 条款\n")
        verdict = _temp_file("## 裁决\n")
        audit_checklist = _temp_file("## 审计细则\n")

        pipeline_def = PipelineDef(
            name="clean",
            description="clean",
            modules=(_make_clean_module(),),
            work_agent_persona=work_persona,
            audit_agent_persona=audit_persona,
            shared_knowledge=(clause_ref, verdict),
            audit_only_knowledge=(audit_checklist,),
            work_ammo_knowledge=(),
            required_tokens=(),
            phase_gate_script=Path("dummy.py"),
        )

        registry = AgentRegistry(Path("skills"))
        registry.register_pipeline("clean", pipeline_def)
        registry.verify_or_raise()  # 不应抛异常

    def test_contaminated_pipeline_raises(self):
        """被污染的管线 → verify_or_raise 抛 RegistryViolation"""
        bad_persona = _temp_file("## 角色\n审计 Agent 会检查你的工作\n")
        audit_persona = _make_audit_persona()
        clause_ref = _temp_file("## 条款\n")
        verdict = _temp_file("## 裁决\n")
        audit_checklist = _temp_file("## 审计细则\n")

        pipeline_def = PipelineDef(
            name="bad",
            description="bad",
            modules=(_make_clean_module(),),
            work_agent_persona=bad_persona,
            audit_agent_persona=audit_persona,
            shared_knowledge=(clause_ref, verdict),
            audit_only_knowledge=(audit_checklist,),
            work_ammo_knowledge=(),
            required_tokens=(),
            phase_gate_script=Path("dummy.py"),
        )

        registry = AgentRegistry(Path("skills"))
        registry.register_pipeline("bad", pipeline_def)

        with pytest.raises(RegistryViolation) as exc:
            registry.verify_or_raise()

        assert "bad" in str(exc.value).lower() or "etsi-report-auditor" in str(exc.value).lower()
