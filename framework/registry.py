"""Agent/Skill 注册表。

启动时加载所有管线定义，验证隔离约束。
"""

from pathlib import Path
from typing import Dict, List, Optional

from contracts.module import ModuleDef, PipelineDef
from framework.agent_runner import PromptCompiler


class RegistryViolation(Exception):
    """注册表隔离验证违规"""

    def __init__(self, violations: List[str]):
        self.violations = violations
        super().__init__(
            "\n" + "=" * 60 + "\n"
            " 注册表隔离验证失败:\n" +
            "\n".join(f"  ❌ {v}" for v in violations) +
            "\n" + "=" * 60
        )


class AgentRegistry:
    """Agent/Skill 注册表。

    启动时加载，验证隔离约束，提供配置查询。

    用法:
        registry = AgentRegistry(Path("skills"))
        registry.register_pipeline("etsi-ts103701", etsi_pipeline_def)
        violations = registry.verify_isolation()
        if violations:
            raise RegistryViolation(violations)
    """

    def __init__(self, skills_root: Path):
        self.skills_root = Path(skills_root)
        self._pipelines: Dict[str, PipelineDef] = {}
        self._verified: bool = False

    def register_pipeline(self, name: str, pipeline_def: PipelineDef) -> None:
        """注册一个管线定义"""
        self._pipelines[name] = pipeline_def
        self._verified = False  # 注册新管线后需重新验证

    def get_pipeline(self, name: str) -> Optional[PipelineDef]:
        """按名称获取管线定义"""
        return self._pipelines.get(name)

    def list_pipelines(self) -> List[str]:
        """列出所有已注册管线名称"""
        return list(self._pipelines.keys())

    def verify_isolation(self) -> List[str]:
        """验证所有已注册管线的隔离约束。

        检查:
        1. 审计专用知识库不出现在任何 Work Agent 的知识库中
        2. Work Agent persona 文件不包含审计禁止模式
        3. 弹药库不出现在 Audit Agent 知识库中

        返回违规列表（空列表 = 全部通过）。
        """
        violations: List[str] = []

        for pipe_name, pipe_def in self._pipelines.items():
            # 收集审计专用知识库文件名
            audit_only_names = {f.name for f in pipe_def.audit_only_knowledge}
            # 收集弹药库文件名
            ammo_names = {f.name for f in pipe_def.work_ammo_knowledge}

            # 检查 1: 审计文件不出现在 shared_knowledge 中
            shared_names = {f.name for f in pipe_def.shared_knowledge}
            audit_in_shared = audit_only_names & shared_names
            if audit_in_shared:
                violations.append(
                    f"[{pipe_name}] 审计专用文件出现在 shared_knowledge: {audit_in_shared}"
                )

            # 检查 2: Work Agent persona 不含审计禁止模式
            work_persona_content = pipe_def.work_agent_persona.read_text(encoding="utf-8")
            for pattern in PromptCompiler.DEFAULT_FORBIDDEN:
                if pattern.lower() in work_persona_content.lower():
                    violations.append(
                        f"[{pipe_name}] Work Agent persona 包含禁止模式: '{pattern}'"
                    )

            # 检查 3: 弹药库不出现在 Audit Agent persona 中
            audit_persona_content = pipe_def.audit_agent_persona.read_text(encoding="utf-8")
            for ammo_name in ammo_names:
                if ammo_name in audit_persona_content:
                    violations.append(
                        f"[{pipe_name}] 弹药库 '{ammo_name}' 出现在 Audit Agent persona 中"
                    )

            # 检查 4: 审计专用文件不出现在 shared 中
            for audit_file in audit_only_names:
                if audit_file in shared_names:
                    violations.append(
                        f"[{pipe_name}] 审计专用文件 '{audit_file}' 在 shared_knowledge 中"
                    )

        self._verified = len(violations) == 0
        return violations

    def verify_or_raise(self) -> None:
        """验证隔离约束，违规则抛出 RegistryViolation"""
        violations = self.verify_isolation()
        if violations:
            raise RegistryViolation(violations)

    @property
    def is_verified(self) -> bool:
        return self._verified

    @property
    def pipeline_count(self) -> int:
        return len(self._pipelines)
