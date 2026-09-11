"""将用户运行目标解析为显式 DAG；本模块不执行 Agent、不发认证令牌。"""

from contracts.run_plan import RunNode, RunPlan, RunProfile


_FUNCTIONAL_MODULES = ("M1", "M2", "M3", "M4", "M5")
_DEPENDENCIES = {"M1": (), "M2": (), "M3": ("M2",), "M4": (), "M5": ()}


def build_run_plan(profile: RunProfile | str, selected_modules: list[str] | None = None) -> RunPlan:
    profile = RunProfile(profile)
    chosen = list(dict.fromkeys(selected_modules or []))
    invalid = sorted(set(chosen) - set(_FUNCTIONAL_MODULES))
    if invalid:
        raise ValueError(f"functional-module 仅支持 M1–M5: {invalid}")

    if profile == RunProfile.CERTIFICATION_FULL:
        return RunPlan(
            profile=profile, certificationClaim=True,
            nodes=[
                RunNode(id="init", label="初始化"),
                RunNode(id="env_check", label="环境检查", dependsOn=["init"]),
                RunNode(id="ics_parse", label="ICS/IXIT 解析", dependsOn=["env_check"]),
                RunNode(id="m0", label="M0 概念测试", dependsOn=["ics_parse"]),
                RunNode(id="m0_audit", label="M0 L2 审计", dependsOn=["m0"], certificationGate=True),
                RunNode(id="traffic", label="流量采集", dependsOn=["m0_audit"]),
                RunNode(id="m1_m5", label="M1–M5 功能测试", dependsOn=["traffic"]),
                RunNode(id="cross", label="跨模块审计", dependsOn=["m1_m5"], certificationGate=True),
                RunNode(id="report", label="认证报告", dependsOn=["cross"]),
            ], requiredInputs=["ixit.json", "DUT", "Playwright MCP"],
        )

    if profile == RunProfile.FUNCTIONAL_SMOKE:
        chosen = list(_FUNCTIONAL_MODULES)
    elif profile == RunProfile.FUNCTIONAL_MODULE:
        if not chosen:
            raise ValueError("functional-module 必须指定至少一个模块")
        expanded = set(chosen)
        for module in chosen:
            expanded.update(_DEPENDENCIES[module])
        chosen = [module for module in _FUNCTIONAL_MODULES if module in expanded]
    elif profile == RunProfile.AUDIT_ONLY:
        return RunPlan(profile=profile, certificationClaim=False,
                       nodes=[RunNode(id="audit", label="审计已有证据")],
                       requiredInputs=["已有 evidence"], risks=["不执行 DUT 测试，不构成认证结论"])
    elif profile == RunProfile.REPORT_REBUILD:
        return RunPlan(profile=profile, certificationClaim=False,
                       nodes=[RunNode(id="report", label="重建已有报告")],
                       requiredInputs=["已有 evidence 与 audit-results"], risks=["不执行 DUT 测试，不构成认证结论"])
    else:
        raise AssertionError(f"unsupported profile: {profile}")

    nodes = [RunNode(id="traffic", label="流量采集（需人工确认）")]
    for module in chosen:
        nodes.append(RunNode(id=module.lower(), label=f"{module} 功能测试", dependsOn=["traffic", *[dep.lower() for dep in _DEPENDENCIES[module]]]))
    return RunPlan(
        profile=profile, certificationClaim=False, selectedModules=chosen, nodes=nodes,
        requiredInputs=["ixit.json", "DUT", "Playwright MCP", "tshark", "人工流量窗口确认"],
        skippedGates=["M0 L1/L2 认证 gate", "跨模块认证 gate"],
        risks=["仅用于功能性验证；不得作为 ETSI 认证通过结论", "缺少输入或工具时必须 blocked，不允许降级"],
    )
