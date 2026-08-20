#!/usr/bin/env python3
"""
ETSI Mx Pre-Evidence JSON L1 机械化验证。

用法:
  python validate_evidence.py <pre-evidence_Mx_*.json>

退出码:
  0 = L1 通过 → 打印条款摘要表 → 进入审计队列 Step B (etsi-report-auditor)
  1 = L1 不通过 → 打印逐条错误清单 → 主线程直接打回 Mx (不占 retry 次数)

这是确定性计算 —— 不要在 LLM 里做这件事。
"""

import json
import os
import sys
from typing import Optional


# -- 允许的枚举值 ---------------------------------------------
VALID_VERDICTS = {"PASS", "FAIL", "NA", "INCONCLUSIVE", "PENDING_MANUAL"}
VALID_EVIDENCE_LEVELS = {"L1", "L2", "L3", "L4", "L5"}
VALID_EVIDENCE_TYPES = {
    "nmap", "tshark", "burp", "curl", "sqlmap", "xray",
    "playwright", "ixit", "netstat", "other"
}
VALID_TAGS = {
    "escape-clause", "all-conditions", "manual-only", "inherited",
    "constrained-device", "conditional", "pass-without-evidence", "ics-na"
}
VALID_PHASES = {"preflight", "tool_call", "reasoning", "pivot", "self_check", "delivery"}


def validate_evidence(evidence_path: str) -> tuple[bool, list[str], Optional[dict]]:
    errors: list[str] = []

    # 0. 文件存在
    if not os.path.exists(evidence_path):
        return False, [f"[FAIL] 文件不存在: {evidence_path}"], None

    # 1. JSON 可解析
    try:
        with open(evidence_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return False, [f"[FAIL] JSON 解析失败: {e}"], None
    except Exception as e:
        return False, [f"[FAIL] 读取文件失败: {e}"], None

    # 2. 顶层必需字段
    required_top = ["meta", "executionTrace", "clauses", "selfCheck"]
    for key in required_top:
        if key not in data:
            errors.append(f"[FAIL] 缺少顶层字段: `{key}`")
    if errors:
        return False, errors, None

    meta = data["meta"]
    clauses = data["clauses"]
    trace = data.get("executionTrace", {})
    sc = data.get("selfCheck", {})

    # -- 2.5 meta 字段检查 --------------------------------------
    for fld in ["moduleId", "dutIp", "ixitJsonPath", "generatedAt", "clauseCount", "retryCount", "status"]:
        if fld not in meta:
            errors.append(f"[FAIL] meta 缺少字段: `{fld}`")

    if meta.get("status") != "pending_audit":
        errors.append(
            f"[FAIL] meta.status 必须为 `pending_audit`，当前为 `{meta.get('status')}`。"
            f"agent 交付时写 pending_audit，审计 ACCEPT 后由主线程脚本改写。"
        )

    if not isinstance(meta.get("retryCount"), int) or meta["retryCount"] < 0:
        errors.append(f"[FAIL] meta.retryCount 必须为非负整数，当前为 `{meta.get('retryCount')}`")

    # -- 3. 条款数对账 ------------------------------------------
    if not isinstance(clauses, list):
        errors.append("[FAIL] `clauses` 必须是数组，不能是对象")
        return False, errors, None

    expected = sc.get("totalExpected", 0)
    actual = sc.get("actualInJson", len(clauses))

    if expected != actual:
        errors.append(f"[FAIL] 条款数不对: selfCheck.totalExpected={expected}, selfCheck.actualInJson={actual}, clauses 数组实际长度={len(clauses)}")
    if expected != len(clauses):
        errors.append(f"[FAIL] selfCheck.totalExpected={expected} 但 clauses 数组实际有 {len(clauses)} 条")

    # -- 4. 缺失条款 --------------------------------------------
    missing = sc.get("missingClauses", [])
    if missing:
        errors.append(f"[FAIL] 缺失条款 ({len(missing)} 条): {missing}")

    # -- 5. 逐条款检查 ------------------------------------------
    clause_ids_seen: set[str] = set()
    for i, c in enumerate(clauses):
        cid = c.get("clauseId", f"clauses[{i}]")

        # 必填字段
        for fld in ["clauseId", "provisionText", "icsStatus", "icsSupport", "verdict", "reason"]:
            if not c.get(fld):
                errors.append(f"[FAIL] {cid}: 缺少必填字段 `{fld}`")

        # verdict 枚举
        v = c.get("verdict")
        if v and v not in VALID_VERDICTS:
            errors.append(f"[FAIL] {cid}: verdict=`{v}` 不在允许值 {VALID_VERDICTS} 中")

        # FAIL 必须含预期 vs 实际
        if v == "FAIL":
            if not c.get("expectedBehavior", "").strip():
                errors.append(f"[FAIL] {cid}: verdict=FAIL 但缺少 `expectedBehavior`")
            if not c.get("actualBehavior", "").strip():
                errors.append(f"[FAIL] {cid}: verdict=FAIL 但缺少 `actualBehavior`")

        # reason 非空
        if not c.get("reason", "").strip():
            errors.append(f"[FAIL] {cid}: `reason` 为空 — 必须包含完整推理链")

        # icsSupport 枚举
        sup = c.get("icsSupport")
        if sup and sup not in ("Y", "N", "N/A"):
            errors.append(f"[FAIL] {cid}: icsSupport=`{sup}` 不在允许值 ['Y', 'N', 'N/A'] 中")

        # tags 枚举
        for t in c.get("tags", []):
            if t not in VALID_TAGS:
                errors.append(f"[FAIL] {cid}: tag=`{t}` 不在允许值 {VALID_TAGS} 中")

        # -- evidence 检查 --------------------------------------
        ev_list = c.get("evidence", [])
        if v in ("PASS", "FAIL") and not ev_list:
            errors.append(f"[FAIL] {cid}: verdict={v} 但 evidence 为空 — 至少需要 1 条证据")

        for j, ev in enumerate(ev_list):
            # type 枚举
            et = ev.get("type")
            if et and et not in VALID_EVIDENCE_TYPES:
                errors.append(f"[FAIL] {cid}: evidence[{j}].type=`{et}` 不在允许值中")

            # level 枚举 + L4/L5 拒绝
            lv = ev.get("level")
            if lv and lv not in VALID_EVIDENCE_LEVELS:
                errors.append(f"[FAIL] {cid}: evidence[{j}].level=`{lv}` 不在允许值 {VALID_EVIDENCE_LEVELS} 中")
            if lv in ("L4", "L5"):
                errors.append(f"[FAIL] {cid}: evidence[{j}] level={lv} — L4=无证据, L5=证据矛盾, 裁决不成立。请补充 L2+ 证据或将 verdict 改为 INCONCLUSIVE。")

            # description 非空
            if not ev.get("description", "").strip():
                errors.append(f"[FAIL] {cid}: evidence[{j}].description 为空")

            # FAIL 时 evidence 的 expectedVsActual
            if v == "FAIL" and not ev.get("expectedVsActual", "").strip():
                errors.append(f"[FAIL] {cid}: evidence[{j}] verdict=FAIL 但缺少 `expectedVsActual`")

        # -- PENDING_MANUAL 检查 --------------------------------
        if v == "PENDING_MANUAL":
            ms = c.get("manualSteps")
            if not ms or not str(ms).strip():
                errors.append(f"[FAIL] {cid}: verdict=PENDING_MANUAL 但 `manualSteps` 为空 — 必须写具体操作步骤")

        # -- ICS N/A 检查 ---------------------------------------
        if sup == "N/A" and v == "NA":
            if not c.get("reason", "").strip():
                errors.append(f"[FAIL] {cid}: ICS=N/A 但 reason 为空 — 必须说明不适用理由")

        # 重号检查
        if cid in clause_ids_seen:
            errors.append(f"[FAIL] {cid}: clauseId 重复")
        clause_ids_seen.add(cid)

    # -- 6. selfCheck 内部一致性 ---------------------------------
    fail_clauses = sc.get("failClauses", [])
    for fc in fail_clauses:
        fc_id = fc.get("clauseId", "?")
        if not fc.get("hasExpectedVsActual"):
            errors.append(f"[FAIL] selfCheck.failClauses: {fc_id} hasExpectedVsActual=false — FAIL 条款必须含预期 vs 实际对照")

    pm_clauses = sc.get("pendingManualClauses", [])
    for pid in pm_clauses:
        clause = next((c for c in clauses if c["clauseId"] == pid), None)
        if clause:
            ms = clause.get("manualSteps")
            if not ms or not str(ms).strip():
                errors.append(f"[FAIL] {pid}: selfCheck 标记为 PENDING_MANUAL 但 manualSteps 为空")

    # -- 7. 同伴 MD 文件 ----------------------------------------
    # 注意: 新流程下 agent 不写 MD，改为检查 pre-evidence 文件名前缀
    fname = os.path.basename(evidence_path)
    if not fname.startswith("pre-evidence_"):
        errors.append(f"[WARN] 文件名应为 `pre-evidence_Mx_<name>.json`，当前为 `{fname}`")

    # -- 8. executionTrace 结构完整性 ---------------------------
    if not isinstance(trace, dict):
        errors.append("[FAIL] executionTrace 缺失或格式错误 — 无法审计执行过程 (Harness 违规)")
    else:
        if trace.get("totalRounds", 0) == 0:
            errors.append("[FAIL] executionTrace.totalRounds = 0 — agent 未记录任何执行步骤 (Harness 违规)")

        steps = trace.get("steps", [])
        if not steps:
            errors.append("[FAIL] executionTrace.steps 为空 — 无关键步骤记录 (Harness 违规)")
        else:
            # preflight 步骤
            preflight_steps = [s for s in steps if s.get("phase") == "preflight"]
            if not preflight_steps:
                errors.append("[FAIL] executionTrace 缺少 preflight 步骤 — agent 可能跳过了前置检查 (Harness 违规)")

            # phase 枚举
            for s in steps:
                ph = s.get("phase")
                if ph and ph not in VALID_PHASES:
                    errors.append(f"[FAIL] executionTrace.steps[{s.get('seq', '?')}]: phase=`{ph}` 不在允许值中")

            # clauseIds 覆盖
            all_clause_ids = {c["clauseId"] for c in clauses}
            traced_clause_ids: set[str] = set()
            for s in steps:
                for cid in s.get("clauseIds", []):
                    traced_clause_ids.add(cid)
            uncovered = all_clause_ids - traced_clause_ids
            if uncovered:
                errors.append(
                    f"[FAIL] executionTrace 未覆盖条款 ({len(uncovered)} 条): {sorted(uncovered)}"
                    f" — 这些条款无执行轨迹支撑 (Harness 违规)"
                )

    # -- 9. hasErrors 强制检查 ----------------------------------
    if sc.get("hasErrors"):
        errors.append("[FAIL] selfCheck.hasErrors=true — agent 自检未通过，不得交付")

    if errors:
        return False, errors, data
    return True, [], data


def print_summary(data: dict) -> None:
    """打印条款摘要表，供审计 agent Step 2 使用。"""
    sc = data["selfCheck"]
    meta = data["meta"]

    print(f"\n{'='*65}")
    print(
        f"[OK] L1 PASSED | {meta['moduleId']} {meta.get('moduleName', '')} | "
        f"{sc['totalExpected']} 条款 | {sc.get('failCount', 0)} FAIL | "
        f"{sc.get('pendingManual', 0)} 手工 | status={meta.get('status', '?')}"
    )
    print(f"{'='*65}")
    print(f"{'clauseId':<12} {'verdict':<18} {'ics':<12} {'evidence':<10} {'tags'}")
    print("-" * 65)

    for c in data["clauses"]:
        ev_count = len(c.get("evidence", []))
        ev_levels = ",".join(sorted({e.get("level", "?") for e in c.get("evidence", [])}))
        tags = ",".join(c.get("tags", [])) or "-"
        print(
            f"{c['clauseId']:<12} {c.get('verdict', '?'):<18} "
            f"{c.get('icsStatus', '?')}/{c.get('icsSupport', '?'):<6} "
            f"{ev_count}条({ev_levels})  {tags[:30]}"
        )

    # executionTrace 摘要
    trace = data.get("executionTrace", {})
    if trace:
        steps = trace.get("steps", [])
        all_cids = {c["clauseId"] for c in data["clauses"]}
        traced = set()
        for s in steps:
            for cid in s.get("clauseIds", []):
                traced.add(cid)
        uncovered = all_cids - traced
        pf = len([s for s in steps if s.get("phase") == "preflight"])
        piv = len([s for s in steps if s.get("phase") == "pivot"])
        print(f"\n--- executionTrace ---")
        print(f"  总轮次: {trace.get('totalRounds', '?')} | 步骤: {len(steps)} | preflight: {pf} | pivot: {piv}")
        print(f"  覆盖条款: {len(traced)}/{len(all_cids)}", end="")
        if uncovered:
            print(f" [WARN] 未覆盖: {sorted(uncovered)}")
        else:
            print(" [OK]")
        warnings = trace.get("warnings", [])
        if warnings:
            print(f"  agent 警告 ({len(warnings)}):")
            for w in warnings:
                print(f"    [WARN] {w}")


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: python validate_evidence.py <pre-evidence_Mx_*.json>", file=sys.stderr)
        return 2

    evidence_path = sys.argv[1]
    passed, errors, data = validate_evidence(evidence_path)

    if not passed:
        print(f"\n[FAIL] L1 FAILED — {len(errors)} 个错误:")
        for e in errors:
            print(f"  {e}")
        print(f"\n-> 修正以上错误后重新运行 L1 验证。Harness/L1 违规不计入 retry 次数。")
        return 1

    if data:
        print_summary(data)

    return 0


if __name__ == "__main__":
    sys.exit(main())
