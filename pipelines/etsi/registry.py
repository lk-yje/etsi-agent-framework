"""ETSI 管线注册 — 组装 PipelineDef 并注册到 AgentRegistry。

启动时调用 register(registry, skills_root) 即可完成 ETSI 管线的注册和隔离验证。

用法:
    from framework.registry import AgentRegistry
    from pipelines.etsi.registry import register

    registry = AgentRegistry(skills_root)
    register(registry, skills_root)
    registry.verify_or_raise()  # 隔离检查
"""

from pathlib import Path

from contracts.module import PipelineDef
from framework.registry import AgentRegistry

from pipelines.etsi.modules import build_etsi_modules
from pipelines.etsi.agents import (
    WORK_AGENT_PERSONA,
    AUDIT_AGENT_PERSONA,
    get_work_shared_knowledge,
    get_audit_only_knowledge,
    get_audit_shared_knowledge,
)


def build_etsi_pipeline_def(skills_root: Path) -> PipelineDef:
    """从 skills_root 构建完整的 ETSI 管线定义。

    Args:
        skills_root: skills 根目录 (e.g., C:/Users/<user>/.claude/skills)

    Returns:
        完整的 PipelineDef（frozen dataclass）
    """
    root = Path(skills_root) if not isinstance(skills_root, Path) else skills_root

    all_modules = build_etsi_modules(root)  # (M0, M1, M2, M3, M4, M5)

    # 弹药库路径（汇总去重）
    work_ammo: set[Path] = set()
    for m in all_modules:
        if m.id != "M0":
            work_ammo.update(m.ammo_paths)

    return PipelineDef(
        name="etsi-ts103701",
        description="ETSI TS 103 701 认证检测管线 — IoT 设备基线安全认证",
        modules=all_modules,
        work_agent_persona=WORK_AGENT_PERSONA,
        audit_agent_persona=AUDIT_AGENT_PERSONA,
        shared_knowledge=(
            get_work_shared_knowledge(root) + get_audit_shared_knowledge(root)
        ),
        audit_only_knowledge=get_audit_only_knowledge(root),
        work_ammo_knowledge=tuple(work_ammo),
        required_tokens=(
            ".evidence_M0_complete",
            ".evidence_M1_complete",
            ".evidence_M2_complete",
            ".evidence_M3_complete",
            ".evidence_M4_complete",
            ".evidence_M5_complete",
            ".audit_M0_ACCEPTED",
            ".audit_M1_ACCEPTED",
            ".audit_M2_ACCEPTED",
            ".audit_M3_ACCEPTED",
            ".audit_M4_ACCEPTED",
            ".audit_M5_ACCEPTED",
            ".audit_ROUND2_ACCEPTED",
        ),
        phase_gate_script=Path("scripts/pipeline_phase_gate.py"),
        pipeline_class="pipelines.etsi.pipeline.ETSIPipeline",
    )


def register(registry: AgentRegistry, skills_root: Path | None = None) -> None:
    """将 ETSI 管线注册到 Registry 并验证隔离约束。

    Args:
        registry: AgentRegistry 实例
        skills_root: skills 根目录。不传则使用当前目录下的 skills/
    """
    root = Path(skills_root) if skills_root else Path("skills")
    pipeline_def = build_etsi_pipeline_def(root)
    registry.register_pipeline(pipeline_def.name, pipeline_def)
