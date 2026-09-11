"""管线模块定义合约 — ModuleDef, PipelineDef"""

from dataclasses import dataclass
from pathlib import Path
from typing import Tuple, Optional


@dataclass(frozen=True)
class ModuleDef:
    """单个测试模块定义。

    每个模块 = 一组条款 + 需要的弹药库 + 需要的工具 + 可选依赖。

    M3 依赖 M2 的前端加密分析结果:
      depends_on="M2"
      upstream_inputs=("evidence/pre-M2-evidence.json",)
    """
    id: str                          # "M0", "M1", ...
    name: str                        # 人类可读名称
    clauses: Tuple[str, ...]         # 条款 ID 列表（不可变）
    ammo_paths: Tuple[Path, ...]     # 弹药库路径（不可变）
    tools: Tuple[str, ...]           # 需要的工具（不可变）
    depends_on: Optional[str] = None  # 依赖的模块 ID
    upstream_inputs: Tuple[str, ...] = ()  # 从上游模块读取的文件路径


@dataclass(frozen=True)
class PipelineDef:
    """管线定义 — 注册到 AgentRegistry 的完整管线配置"""
    name: str
    description: str
    modules: Tuple[ModuleDef, ...]
    work_agent_persona: Path         # 工作 Agent persona markdown 路径
    audit_agent_persona: Path        # 审计 Agent persona markdown 路径
    shared_knowledge: Tuple[Path, ...]  # 共享知识库（Work + Audit 都可读）
    audit_only_knowledge: Tuple[Path, ...]  # 仅 Audit Agent 可读
    work_ammo_knowledge: Tuple[Path, ...]   # 弹药库（仅 Work Agent 按模块加载）
    required_tokens: Tuple[str, ...]  # 阶段闸门令牌列表
    phase_gate_script: Path          # pipeline_phase_gate.py 路径
    pipeline_class: str = ""         # 管线类的完全限定路径
