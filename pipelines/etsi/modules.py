"""ETSI TS 103 701 模块定义 — M0~M5 条款分配 + 弹药库映射。

从 module-split.md 迁移而来。每个模块定义其覆盖的条款、需要的弹药库、工具集。

路径约定:
- 所有 skills 路径通过 build_etsi_modules(skills_root) 动态构造
- 避免模块级 Path("skills") 硬编码导致的路径解析问题
"""

from pathlib import Path
from typing import Tuple, Dict

from contracts.module import ModuleDef


def build_etsi_modules(skills_root: Path) -> Tuple:
    """构造 ETSI M0-M5 模块定义（Tuple[ModuleDef, ...]）。

    Args:
        skills_root: skills 根目录，如项目内 skills/

    Returns:
        (M0_ICS_VALIDATION, M1_ATTACK_SURFACE, M2_AUTH, M3_COMMUNICATION, M4_UPDATE, M5_INPUT_VALIDATION)
    """
    root = Path(skills_root) if not isinstance(skills_root, Path) else skills_root
    report_ref = root / "etsi-ts103701-report" / "references"
    exploit_ref = root / "exploit" / "references"

    # ===== M0: ICS 逻辑验证 =====
    M0_ICS_VALIDATION = ModuleDef(
        id="M0",
        name="ICS 逻辑验证与概念性测试",
        clauses=(),
        ammo_paths=(),
        tools=("ixit_readonly",),
    )

    # ===== M1: 攻击面与端口 =====
    M1_ATTACK_SURFACE = ModuleDef(
        id="M1",
        name="攻击面与端口",
        clauses=(
            "5.5-2", "5.5-4", "5.5-5",
            "5.6-1", "5.6-2", "5.6-3", "5.6-4", "5.6-5",
            "5.6-6", "5.6-7", "5.6-8", "5.6-9",
        ),
        ammo_paths=(
            report_ref / "auth-diff-workflow.md",
        ),
        tools=("bash", "burp_mcp"),
    )

    # ===== M2: 认证与口令 =====
    M2_AUTH = ModuleDef(
        id="M2",
        name="认证与口令",
        clauses=(
            "5.1-1", "5.1-2", "5.1-3", "5.1-4", "5.1-5",
        ),
        ammo_paths=(
            exploit_ref / "web-logic-auth.md",
        ),
        tools=("bash", "burp_mcp", "playwright_mcp"),
    )

    # ===== M3: 通信加密 =====
    M3_COMMUNICATION = ModuleDef(
        id="M3",
        name="通信加密",
        clauses=(
            "5.5-1", "5.5-6", "5.5-7",
            "5.5-3", "5.5-8", "5.8-1", "5.8-2",
        ),
        ammo_paths=(),
        tools=("bash", "burp_mcp"),
        depends_on="M2",  # 需要 M2 的前端加密分析结果
        upstream_inputs=("evidence/pre-M2-evidence.json",),  # M2 产出的前端加密分析
    )

    # ===== M4: 更新与完整性 =====
    M4_UPDATE = ModuleDef(
        id="M4",
        name="更新与完整性",
        clauses=(
            "5.3-1", "5.3-2", "5.3-3", "5.3-4", "5.3-5",
            "5.3-6", "5.3-7", "5.3-8", "5.3-9", "5.3-10",
            "5.3-11", "5.3-12",
            "5.3-13", "5.3-14", "5.3-15", "5.3-16",
            "5.4-1", "5.4-2", "5.4-3", "5.4-4",
            "5.7-1", "5.7-2",
        ),
        ammo_paths=(),
        tools=("bash", "burp_mcp", "playwright_mcp"),
    )

    # ===== M5: 输入验证与数据保护 =====
    M5_INPUT_VALIDATION = ModuleDef(
        id="M5",
        name="输入验证与数据保护",
        clauses=(
            "4-1", "5.2-1", "5.2-2", "5.2-3",
            "5.8-3",
            "5.9-1", "5.9-2", "5.9-3",
            "5.10",
            "5.11-1", "5.11-2", "5.11-3", "5.11-4",
            "5.12-1", "5.12-2", "5.12-3",
            "5.13-1",
            "6-1", "6-2", "6-3", "6-4", "6-5",
        ),
        ammo_paths=(
            report_ref / "auth-diff-workflow.md",
            exploit_ref / "web-sqli.md",
            exploit_ref / "web-xss.md",
            exploit_ref / "web-rce.md",
            exploit_ref / "web-traversal.md",
        ),
        tools=("bash", "burp_mcp", "playwright_mcp"),
    )

    return (M0_ICS_VALIDATION, M1_ATTACK_SURFACE, M2_AUTH, M3_COMMUNICATION, M4_UPDATE, M5_INPUT_VALIDATION)


# ===== 兼容旧接口：模块级常量 (使用默认 skills 路径) =====
_DEFAULT_ROOT = Path("skills")

# 模块列表（按执行顺序）
ETSI_MODULES: Tuple[ModuleDef, ...] = tuple(
    m for m in build_etsi_modules(_DEFAULT_ROOT) if m.id != "M0"
)

# M0 单独引用
_DEFAULT_MODULES = build_etsi_modules(_DEFAULT_ROOT)
M0_ICS_VALIDATION = _DEFAULT_MODULES[0]

# 模块查找表
MODULE_MAP: Dict[str, ModuleDef] = {
    m.id: m for m in _DEFAULT_MODULES
}
