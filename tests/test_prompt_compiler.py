"""隔离约束编译时测试 — 框架的核心质量保证。

验证:
1. Work Agent 配置含审计文件 → IsolationViolation
2. Work Agent persona 含审计模式 → IsolationViolation
3. Audit Agent 可以加载审计专用文件
4. 合法 Work Agent 配置 → 编译成功
"""

import tempfile
from pathlib import Path
import pytest

from framework.agent_runner import (
    AgentConfig,
    PromptCompiler,
    IsolationViolation,
)


def _temp_file(content: str, suffix: str = ".md") -> Path:
    """创建临时文件"""
    tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="w", encoding="utf-8")
    tmp.write(content)
    tmp.close()
    return Path(tmp.name)


class TestWorkAgentRejectsAuditKnowledge:
    """Work Agent 知识库含审计文件 → 编译时拒绝"""

    def test_rejects_audit_checklist(self):
        """Work Agent knowledge_paths 含 audit-checklist 内容 → IsolationViolation"""
        persona = _temp_file("## 角色\n你是检测员\n")
        audit_file = _temp_file("## audit-checklist\n审计判断细则\n检查 escape_clause\n")

        config = AgentConfig(
            agent_id="test_work",
            agent_type="work",
            persona_path=persona,
            knowledge_paths=(audit_file,),
            tool_manifest=(),
        )

        with pytest.raises(IsolationViolation) as exc:
            PromptCompiler.compile(config, {"task": "test", "workspace": "/tmp"})

        assert "audit-checklist" in str(exc.value).lower()

    def test_rejects_common_errors(self):
        """Work Agent knowledge_paths 含 common-errors 内容 → IsolationViolation"""
        persona = _temp_file("## 角色\n你是检测员\n")
        errors_file = _temp_file("## common-errors\n常见误判\nescape_clause\n")

        config = AgentConfig(
            agent_id="test_work",
            agent_type="work",
            persona_path=persona,
            knowledge_paths=(errors_file,),
            tool_manifest=(),
        )

        with pytest.raises(IsolationViolation):
            PromptCompiler.compile(config, {"task": "test", "workspace": "/tmp"})

    def test_rejects_evidence_standards(self):
        """Work Agent knowledge_paths 含 evidence-standards 内容 → IsolationViolation"""
        persona = _temp_file("## 角色\n你是检测员\n")
        standards_file = _temp_file("## evidence-standards\n证据分级\nL1: 完整\nL4: 无证据\n")

        config = AgentConfig(
            agent_id="test_work",
            agent_type="work",
            persona_path=persona,
            knowledge_paths=(standards_file,),
            tool_manifest=(),
        )

        with pytest.raises(IsolationViolation):
            PromptCompiler.compile(config, {"task": "test", "workspace": "/tmp"})


class TestWorkAgentRejectsAuditPatternInPersona:
    """Work Agent persona 自身含审计模式 → 编译时拒绝"""

    def test_rejects_auditor_name_in_persona(self):
        """Persona 中含 'etsi-report-auditor' → IsolationViolation"""
        persona = _temp_file("## 角色\n你是检测员。完成后等待 etsi-report-auditor 审查\n")

        config = AgentConfig(
            agent_id="test_work",
            agent_type="work",
            persona_path=persona,
            knowledge_paths=(),
            tool_manifest=(),
        )

        with pytest.raises(IsolationViolation):
            PromptCompiler.compile(config, {"task": "test", "workspace": "/tmp"})

    def test_rejects_harness_violation_text(self):
        """Persona 中含 'Harness 违规' → IsolationViolation"""
        persona = _temp_file("## 约束\nHarness 违规 = REJECT\n")

        config = AgentConfig(
            agent_id="test_work",
            agent_type="work",
            persona_path=persona,
            knowledge_paths=(),
            tool_manifest=(),
        )

        with pytest.raises(IsolationViolation):
            PromptCompiler.compile(config, {"task": "test", "workspace": "/tmp"})

    def test_rejects_audit_memo_text(self):
        """Persona 中含 '审计备忘录' → IsolationViolation"""
        persona = _temp_file("## 注意\n请按照审计备忘录修正\n")

        config = AgentConfig(
            agent_id="test_work",
            agent_type="work",
            persona_path=persona,
            knowledge_paths=(),
            tool_manifest=(),
        )

        with pytest.raises(IsolationViolation):
            PromptCompiler.compile(config, {"task": "test", "workspace": "/tmp"})


class TestAuditAgentAllowsAuditFiles:
    """Audit Agent 可以加载审计专用文件"""

    def test_audit_agent_loads_audit_checklist(self):
        """Audit Agent 加载 audit-checklist.md → 编译成功"""
        persona = _temp_file("## 角色\n你是审计专家\n")
        audit_file = _temp_file("## 审计判断细则\n检查 escape_clause\n")

        config = AgentConfig(
            agent_id="test_auditor",
            agent_type="audit",
            persona_path=persona,
            knowledge_paths=(audit_file,),
            tool_manifest=(),
        )

        prompt = PromptCompiler.compile(config, {"task": "审计 M1", "workspace": "/tmp"})
        assert "审计判断细则" in prompt

    def test_audit_agent_loads_all_audit_files(self):
        """Audit Agent 加载全部审计文件 → 不抛异常"""
        persona = _temp_file("## 角色\n你是审计专家\n")
        checklist = _temp_file("## audit-checklist\n")
        errors = _temp_file("## common-errors\n")
        standards = _temp_file("## evidence-standards\n")

        config = AgentConfig(
            agent_id="test_auditor",
            agent_type="audit",
            persona_path=persona,
            knowledge_paths=(checklist, errors, standards),
            tool_manifest=(),
        )

        # 不应该抛异常
        prompt = PromptCompiler.compile(config, {"task": "审计", "workspace": "/tmp"})
        assert len(prompt) > 0


class TestCleanWorkAgentCompiles:
    """干净的 Work Agent 配置 → 编译成功"""

    def test_clean_work_agent_compiles(self):
        """合法 Work Agent 配置（无审计引用）→ 正常编译"""
        persona = _temp_file("## 角色\n你是 ETSI 检测员\n## 约束\n1. 不编造结果\n")
        clause_ref = _temp_file("## 条款参考\n5.6-1: 接口文档化\n")
        verdict = _temp_file("## 裁决条件\nPASS: 条件满足\n")

        config = AgentConfig(
            agent_id="test_work_clean",
            agent_type="work",
            persona_path=persona,
            knowledge_paths=(clause_ref, verdict),
            tool_manifest=("bash", "burp_mcp"),
        )

        prompt = PromptCompiler.compile(
            config,
            {
                "task": "执行 M1 模块检测",
                "workspace": "/workspace/test/",
                "inputs": ["nmap_tcp.txt"],
            },
        )

        # 编译成功，含关键内容
        assert "ETSI 检测员" in prompt
        assert "条款参考" in prompt
        assert "裁决条件" in prompt
        assert "M1 模块检测" in prompt
        assert "/workspace/test/" in prompt

        # 不含任何审计相关模式
        assert "审计" not in prompt
        assert "audit-checklist" not in prompt
        assert "Harness 违规" not in prompt


class TestIsolationViolationMessage:
    """IsolationViolation 异常消息包含诊断信息"""

    def test_exception_contains_agent_id_and_source(self):
        """异常消息含 agent_id 和来源文件"""
        persona = _temp_file("## 角色\n审计 Agent 会检查\n")

        config = AgentConfig(
            agent_id="BAD_WORK_AGENT_001",
            agent_type="work",
            persona_path=persona,
            knowledge_paths=(),
            tool_manifest=(),
        )

        with pytest.raises(IsolationViolation) as exc:
            PromptCompiler.compile(config, {"task": "test", "workspace": "/tmp"})

        msg = str(exc.value)
        assert "BAD_WORK_AGENT_001" in msg
        assert str(persona) in msg
