"""ETSI 管线 Agent 配置 — Work/Audit Agent 的 Prompt 编译配置。

核心隔离设计:
- Work Agent: 看不到审计标准，看不到审计 Agent 的存在
- Audit Agent: 仅有本轮输入的受限只读检索工具，看不到弹药库、命令或写入工具

审计打回时复用 build_work_config()，不创建新 Agent 类型。
Retry 的 Work Agent 与首次 Work Agent 配置相同，task 格式一致，不包含审计信息。

路径约定:
- skills_root 由 run_pipeline.py 传入（默认项目内 skills/）
- personas 使用框架自带的干净版本（pipelines/etsi/personas/）
- 知识库文件和弹药库从 skills/ 目录加载
"""

import json
from pathlib import Path
from typing import Tuple

from framework.agent_runner import AgentConfig
from framework.model_config import get_configured_model

# 干净 persona（无审计引用，通过 Isolation 检查）
PERSONAS_ROOT = Path(__file__).parent / "personas"

# 模型选择统一固定在 framework.model_config，避免各阶段出现漂移。

# ============================================================
# Work Agent 基础配置
# ============================================================

WORK_AGENT_FORBIDDEN: Tuple[str, ...] = (
    "etsi-report-auditor",
    "audit-checklist",
    "common-errors",
    "evidence-standards",
    "Harness 违规",
    "审计 Agent",
    "审计结果",
    "审计备忘录",
)

# 使用框架自带的干净 persona，不含审计引用
WORK_AGENT_PERSONA = PERSONAS_ROOT / "work-agent.md"

# clause_tool_map.json 的绝对路径（framework/ 下，不依赖 skills_root）
CLAUSE_TOOL_MAP = Path(__file__).resolve().parent.parent.parent / "framework" / "clause_tool_map.json"


def build_clause_recipe_text(clause_ids) -> str:
    """从 clause_tool_map.json 切出指定条款的 recipe，拼成紧凑文本。

    供 task_ctx 注入，让 Work Agent 明确每条款该跑哪个脚本、用哪些 Burp 工具、怎么做。
    无 recipe 或文件缺失时降级为空串（不阻塞派发）。

    Args:
        clause_ids: 条款号序列，如 ("5.6-2", "5.6-1")

    Returns:
        紧凑 recipe 文本块（多行），或空串。
    """
    if not CLAUSE_TOOL_MAP.exists():
        return ""
    try:
        data = json.loads(CLAUSE_TOOL_MAP.read_text(encoding="utf-8"))
    except Exception:
        return ""

    lines = ["\n## 条款测试 recipe"]
    for cid in clause_ids:
        entry = data.get(cid)
        if not entry:
            lines.append(f"- {cid}: (无 recipe)")
            continue
        head = f"- {cid}[{entry.get('automation', '?')}]"
        workflow = entry.get("workflow", "")
        if workflow:
            head += f" | workflow: {workflow}"
        pre_script = entry.get("pre_script", "")
        if pre_script:
            head += f" | 前置脚本: {pre_script}"
        script = entry.get("script", "")
        if script:
            head += f" | 脚本: {script}"
        burp = entry.get("tools", {}).get("burp_mcp", [])
        if burp:
            head += f" | burp: {','.join(burp)}"
        traffic = entry.get("tools", {}).get("traffic_intelligence", [])
        if traffic:
            head += f" | traffic: {','.join(traffic)}"
        lines.append(head)
        method = entry.get("method", "")
        if method:
            lines.append(f"    方法: {method}")
        for field, label in (
            ("ixit_tables", "IXIT 表"),
            ("evidence_artifacts", "证据产物"),
            ("preconditions", "前提"),
        ):
            values = entry.get(field, [])
            if values:
                lines.append(f"    {label}: {'; '.join(values)}")
        oracle = entry.get("oracle", {})
        if oracle:
            lines.append(
                "    裁决: "
                + " | ".join(
                    f"{name}={oracle[name]}"
                    for name in ("pass", "fail", "inconclusive")
                    if oracle.get(name)
                )
            )
        manual_boundary = entry.get("manual_boundary", "")
        if manual_boundary:
            lines.append(f"    人工边界: {manual_boundary}")
    return "\n".join(lines)


def get_work_shared_knowledge(skills_root: Path) -> Tuple[Path, ...]:
    """M1–M5 Work Agent 的功能性共享知识库。

    概念性条款解释与裁决规则仅服务于 M0 / Audit，不能随 Work Agent
    进入 M1–M5，避免把文档分析写成现场功能测试结论。

    Args:
        skills_root: skills 根目录，如项目内 skills/
    """
    base = Path(skills_root) if not isinstance(skills_root, Path) else skills_root
    report_ref = base / "etsi-ts103701-report" / "references"
    return (
        # 能力矩阵是 Work Agent 选择已获准工具与预期产物的公共索引。
        # 它不含概念裁决规则，可安全用于功能性执行。
        report_ref / "capability-matrix.md",
        report_ref / "tool-error-kb.json",
    )


def get_conceptual_shared_knowledge(skills_root: Path) -> Tuple[Path, ...]:
    """M0 与 Audit 可用的概念性条款参考，绝不直接注入 M1–M5 Work。"""
    base = Path(skills_root) if not isinstance(skills_root, Path) else skills_root
    report_ref = base / "etsi-ts103701-report" / "references"
    return (
        report_ref / "clause-reference.md",
        report_ref / "verdict-criteria.md",
    )


def build_work_config(module, skills_root: Path | None = None) -> AgentConfig:
    """为指定模块构建 Work Agent 配置。

    Args:
        module: ModuleDef 实例
        skills_root: skills 根目录（可选，用于解析弹药库路径）

    Returns:
        不可变 AgentConfig（frozen dataclass）
    """
    # 解析 skills_root
    root = Path(skills_root) if skills_root else Path("skills")

    # 公共知识 + 模块专属弹药库
    all_knowledge = tuple(get_work_shared_knowledge(root)) + module.ammo_paths

    return AgentConfig(
        agent_id=f"work_{module.id}_v1",
        agent_type="work",
        persona_path=WORK_AGENT_PERSONA,
        knowledge_paths=all_knowledge,
        tool_manifest=module.tools,
        forbidden_patterns=WORK_AGENT_FORBIDDEN,
        model=get_configured_model(),
    )


# ============================================================
# Audit Agent 基础配置
# ============================================================

# 使用框架自带的干净 persona
AUDIT_AGENT_PERSONA = PERSONAS_ROOT / "audit-agent.md"


def get_audit_only_knowledge(skills_root: Path) -> Tuple[Path, ...]:
    """Audit Agent 专用知识库（仅 Audit Agent 可读）。

    Args:
        skills_root: skills 根目录
    """
    base = Path(skills_root) if not isinstance(skills_root, Path) else skills_root
    auditor_ref = base / "etsi-report-auditor" / "references"
    return (
        auditor_ref / "audit-checklist.md",
        auditor_ref / "common-errors.md",
        auditor_ref / "evidence-standards.md",
    )


def get_audit_shared_knowledge(skills_root: Path) -> Tuple[Path, ...]:
    """Audit Agent 共享知识库（与 Work Agent 共享的参考文件）。

    Args:
        skills_root: skills 根目录
    """
    base = Path(skills_root) if not isinstance(skills_root, Path) else skills_root
    report_ref = base / "etsi-ts103701-report" / "references"
    return (
        report_ref / "verdict-criteria.md",
    )


def build_audit_config(module_id: str, skills_root: Path | None = None) -> AgentConfig:
    """为指定模块构建 Audit Agent 配置。

    Args:
        module_id: 模块 ID (M0-M5)
        skills_root: skills 根目录
    """
    root = Path(skills_root) if skills_root else Path("skills")
    return AgentConfig(
        agent_id=f"audit_{module_id}_v1",
        agent_type="audit",
        persona_path=AUDIT_AGENT_PERSONA,
        knowledge_paths=(
            get_audit_shared_knowledge(root) + get_audit_only_knowledge(root)
        ),
        tool_manifest=(),
        forbidden_patterns=(),
        model=get_configured_model(),
    )
