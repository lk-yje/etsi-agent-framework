"""pytest 共享 fixture"""

import tempfile
from pathlib import Path
import pytest


@pytest.fixture
def temp_workspace():
    """创建临时工作区"""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


@pytest.fixture
def temp_skills_dir():
    """创建临时 skills 目录（含最小 prompt 文件）"""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        # 创建最小 persona 文件
        work_persona = root / "work_persona.md"
        work_persona.write_text(
            "## 角色\n你是 ETSI 检测员\n## 约束\n不做破坏性操作\n", encoding="utf-8"
        )

        audit_persona = root / "audit_persona.md"
        audit_persona.write_text(
            "## 角色\n你是 ETSI 审计专家\n## 约束\n不做补充测试\n", encoding="utf-8"
        )

        # 创建知识库文件
        clause_ref = root / "clause-reference.md"
        clause_ref.write_text("## 条款参考\n5.6-1: 接口文档化\n", encoding="utf-8")

        verdict = root / "verdict-criteria.md"
        verdict.write_text("## 裁决条件\nPASS: 所有条件满足\n", encoding="utf-8")

        audit_checklist = root / "audit-checklist.md"
        audit_checklist.write_text("## 审计判断细则\n5.6-1: 检查 nmap 结果\n", encoding="utf-8")

        common_errors = root / "common-errors.md"
        common_errors.write_text("## 常见误判\nescape_clause 被忽略\n", encoding="utf-8")

        evidence_standards = root / "evidence-standards.md"
        evidence_standards.write_text("## 证据分级\nL1: 完整可复现\n", encoding="utf-8")

        ammo = root / "web-sqli.md"
        ammo.write_text("## SQL 注入弹药库\n' OR '1'='1\n", encoding="utf-8")

        yield root
