#!/usr/bin/env python3
"""
ETSI Pipeline Phase Gate — 阶段 4 入口机械闸门。

用法:
  python pipeline_phase_gate.py <workspace_path>

检查项 (全部 7 枚通行令牌):
  1. .audit_M0_ACCEPTED  — M0 ICS 验证已审计通过
  2. .audit_M1_ACCEPTED  — M1 攻击面已审计通过
  3. .audit_M2_ACCEPTED  — M2 认证已审计通过
  4. .audit_M3_ACCEPTED  — M3 通信加密已审计通过
  5. .audit_M4_ACCEPTED  — M4 更新完整性已审计通过
  6. .audit_M5_ACCEPTED  — M5 输入验证已审计通过
  7. .audit_ROUND2_ACCEPTED — 跨模块一致性审计通过

退出码:
  0 = 全部 7 枚令牌就绪 → 闸门通过 → 进入阶段 4
  1 = 缺失令牌 → 打印缺失清单 → 禁止进入阶段 4
"""

import os
import sys

# 全部 7 枚通行令牌
ALL_TOKENS = [
    ".audit_M0_ACCEPTED",
    ".audit_M1_ACCEPTED",
    ".audit_M2_ACCEPTED",
    ".audit_M3_ACCEPTED",
    ".audit_M4_ACCEPTED",
    ".audit_M5_ACCEPTED",
    ".audit_ROUND2_ACCEPTED",
]

# 人性化描述
TOKEN_LABELS = {
    ".audit_M0_ACCEPTED": "M0 ICS 逻辑验证审计",
    ".audit_M1_ACCEPTED": "M1 攻击面与端口审计",
    ".audit_M2_ACCEPTED": "M2 认证与口令审计",
    ".audit_M3_ACCEPTED": "M3 通信加密审计",
    ".audit_M4_ACCEPTED": "M4 更新与完整性审计",
    ".audit_M5_ACCEPTED": "M5 输入验证与数据保护审计",
    ".audit_ROUND2_ACCEPTED": "Round 2 跨模块一致性审计",
}

# 各令牌的阻断点说明
TOKEN_GATE = {
    ".audit_M0_ACCEPTED": "[BLOCK] 阻断 M1-M5 派发 (Phase 2 → Phase 3)",
    ".audit_M1_ACCEPTED": "—",
    ".audit_M2_ACCEPTED": "—",
    ".audit_M3_ACCEPTED": "—",
    ".audit_M4_ACCEPTED": "—",
    ".audit_M5_ACCEPTED": "—",
    ".audit_ROUND2_ACCEPTED": "[BLOCK] 阻断阶段 4 入口 (Phase 3 → Phase 4)",
}


def check_phase_gate(workspace: str) -> tuple[bool, list[str], dict]:
    """Returns: (passed, issues, token_status)"""
    issues: list[str] = []
    token_status: dict[str, bool] = {}

    for token_file in ALL_TOKENS:
        token_path = os.path.join(workspace, token_file)
        present = os.path.exists(token_path)
        token_status[token_file] = present

        if not present:
            label = TOKEN_LABELS.get(token_file, token_file)
            gate = TOKEN_GATE.get(token_file, "")
            issues.append(f"[FAIL] 缺失令牌: `{token_file}` — {label} {gate}")

    # 附加检查: evidence JSON 存在性 (令牌之外的额外验证)
    evidence_files = [
        "evidence_M0_ics_validation.json",
        "evidence_M1_attack_surface.json",
        "evidence_M2_auth_password.json",
        "evidence_M3_comm_crypto.json",
        "evidence_M4_update_integrity.json",
        "evidence_M5_input_dataprotection.json",
    ]
    for ef in evidence_files:
        ef_path = os.path.join(workspace, ef)
        if not os.path.exists(ef_path):
            issues.append(f"[WARN] evidence JSON 缺失: `{ef}` (令牌存在但文件丢失)")

    return len([i for i in issues if i.startswith("[FAIL]")]) == 0, issues, token_status


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: python pipeline_phase_gate.py <workspace_path>", file=sys.stderr)
        return 2

    workspace = sys.argv[1]

    if not os.path.isdir(workspace):
        print(f"[FAIL] 工作区不存在: {workspace}", file=sys.stderr)
        return 1

    passed, issues, token_status = check_phase_gate(workspace)

    # -- 打印状态报告 -------------------------------------------
    print(f"\n{'='*60}")
    print(f"[GATE] Phase Gate — 阶段 4 入口闸门")
    print(f"   工作区: {workspace}")
    print(f"{'='*60}")

    print(f"\n[LIST] 通行令牌状态:")
    present_count = 0
    for token_file in ALL_TOKENS:
        label = TOKEN_LABELS.get(token_file, token_file)
        if token_status[token_file]:
            print(f"   [OK] {token_file} — {label}")
            present_count += 1
        else:
            print(f"   [FAIL] {token_file} — {label}")

    print(f"\n   令牌就绪: {present_count}/{len(ALL_TOKENS)}")

    if issues:
        blocking = [i for i in issues if i.startswith("[FAIL]")]
        warnings = [i for i in issues if i.startswith("[WARN]")]
        print(f"\n[BLOCK] 闸门未通过 — {len(blocking)} 个阻断问题, {len(warnings)} 个警告:")
        for i in issues:
            print(f"   {i}")
        print(f"\n[STOP] 禁止进入阶段 4。请完成以上审计项后重试。")
        return 1

    print(f"\n[OK] 闸门通过 — 全部 {len(ALL_TOKENS)} 枚令牌就绪，可以进入阶段 4 生成报告。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
