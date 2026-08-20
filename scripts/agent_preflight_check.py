#!/usr/bin/env python3
"""
Agent Pre-Delivery Self-Check

Drop-in validation that work-agents run BEFORE declaring completion.
Returns exit code 0 only when L1 passes — agent must NOT report done on failure.

Usage (agent runs this before final summary):
  python scripts/agent_preflight_check.py <pre-evidence-json-path>

Exit codes:
  0 — All checks pass, safe to deliver
  1 — L1 validation failed, fix before delivery
  2 — Non-L1 quality issues (shallow evidence, missing executionTrace, etc.)

This is the agent-side counterpart of validate_evidence.py (main-thread L1).
It adds agent-actionable checks beyond just schema validation.
"""

import json
import os
import sys


def human_verdict_counts(clauses: list) -> dict:
    counts = {}
    for c in clauses:
        v = c["verdict"]
        counts[v] = counts.get(v, 0) + 1
    return counts


def check_evidence_shallowness(clauses: list) -> list:
    """Flag clauses with suspiciously few/weak evidence."""
    warnings = []
    for c in clauses:
        v = c["verdict"]
        ev = c.get("evidence", [])
        cid = c["clauseId"]

        if v in ("PASS", "FAIL") and len(ev) == 0:
            warnings.append(f"{cid}: verdict={v} but evidence[] is empty")
        if v == "FAIL":
            expected = c.get("expectedBehavior")
            actual = c.get("actualBehavior")
            if not expected:
                warnings.append(f"{cid}: FAIL but expectedBehavior is empty")
            if not actual:
                warnings.append(f"{cid}: FAIL but actualBehavior is empty")
            # Check evidence-level expectedVsActual
            for i, e in enumerate(ev):
                if not e.get("expectedVsActual"):
                    warnings.append(f"{cid}: evidence[{i}] FAIL but missing expectedVsActual")
        if v == "PENDING_MANUAL" and not c.get("manualSteps"):
            warnings.append(f"{cid}: PENDING_MANUAL but manualSteps is empty")

    return warnings


def check_execution_trace(et: dict, clause_count: int) -> list:
    """Flag missing or suspicious execution traces."""
    warnings = []
    steps = et.get("steps", [])
    total_rounds = et.get("totalRounds", 0)

    if total_rounds == 0:
        warnings.append("executionTrace.totalRounds=0 — agent recorded no steps. Delivery rejected.")
    if len(steps) == 0:
        warnings.append("executionTrace.steps is empty — no trace of agent activity.")

    # Check that each clause appears in at least one step
    covered_clauses = set()
    for s in steps:
        for cid in s.get("clauseIds", []):
            covered_clauses.add(cid)

    if len(covered_clauses) < clause_count * 0.5:
        warnings.append(
            f"executionTrace covers only {len(covered_clauses)}/{clause_count} clauses "
            f"(< 50%). Trace is too sparse."
        )

    return warnings


def check_evidence_levels(clauses: list) -> list:
    """Flag L4/L5 evidence (immediate delivery rejection)."""
    errors = []
    for c in clauses:
        for i, e in enumerate(c.get("evidence", [])):
            level = e.get("level", "")
            if level in ("L4", "L5"):
                errors.append(
                    f"{c['clauseId']}: evidence[{i}].level={level} — "
                    f"L4/L5 evidence is rejected per evidence-standards.md. "
                    f"Downgrade to L3 or provide actual evidence."
                )
    return errors


def main():
    if len(sys.argv) < 2:
        print("Usage: python agent_preflight_check.py <evidence-json-path>")
        sys.exit(2)

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"[FAIL] File not found: {path}")
        sys.exit(2)

    # 1. Load and basic parse
    try:
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[FAIL] Invalid JSON: {e}")
        print("Fix: re-save as UTF-8 without BOM, ensure all braces match.")
        sys.exit(1)
    except Exception as e:
        print(f"[FAIL] Cannot read file: {e}")
        sys.exit(1)

    clauses = data.get("clauses", [])
    meta = data.get("meta", {})
    sc = data.get("selfCheck", {})
    et = data.get("executionTrace", {})

    all_warnings = []

    # 2. Structural checks
    if sc.get("hasErrors", True):
        all_warnings.append("selfCheck.hasErrors is true — agent marked own work as broken.")

    if len(clauses) == 0:
        all_warnings.append("clauses[] is empty — no clauses delivered.")

    # 3. Evidence shallowness
    all_warnings.extend(check_evidence_shallowness(clauses))

    # 4. Evidence level check
    level_errors = check_evidence_levels(clauses)
    if level_errors:
        print("[FAIL] L4/L5 evidence detected — this is a hard rejection:")
        for e in level_errors:
            print(f"  {e}")
        print()
        print("L4 = no evidence, L5 = contradictory evidence.")
        print("Fix: provide actual tool output, frame numbers, or at minimum mark as L3 with justification.")
        sys.exit(1)

    # 5. Execution trace
    all_warnings.extend(check_execution_trace(et, len(clauses)))

    # 6. Enum checks (catch natural-language values before L1 sees them)
    valid_types = {"nmap", "tshark", "burp", "curl", "sqlmap", "xray", "playwright", "ixit", "netstat", "other"}
    valid_phases = {"preflight", "tool_call", "reasoning", "pivot", "self_check", "delivery"}
    valid_tags = {"escape-clause", "all-conditions", "manual-only", "inherited", "constrained-device", "conditional", "pass-without-evidence", "ics-na"}

    for c in clauses:
        cid = c["clauseId"]
        if c.get("icsSupport") not in ("Y", "N", "N/A"):
            all_warnings.append(f"{cid}: icsSupport='{c['icsSupport']}' not in [Y,N,N/A]")
        if c.get("verdict") not in ("PASS", "FAIL", "NA", "INCONCLUSIVE", "PENDING_MANUAL"):
            all_warnings.append(f"{cid}: verdict='{c['verdict']}' not in enum")
        for i, e in enumerate(c.get("evidence", [])):
            if e.get("type") not in valid_types:
                all_warnings.append(f"{cid}: evidence[{i}].type='{e.get('type', 'MISSING')}' not in valid enum. Use one of: {sorted(valid_types)}")
            if e.get("level") not in ("L1", "L2", "L3", "L4", "L5"):
                all_warnings.append(f"{cid}: evidence[{i}].level='{e.get('level')}' not in [L1-L5]")
        for tag in c.get("tags", []):
            if tag not in valid_tags:
                all_warnings.append(f"{cid}: tag='{tag}' not in valid tags enum")

    for s in et.get("steps", []):
        if s.get("phase") not in valid_phases:
            all_warnings.append(f"executionTrace step {s.get('seq')}: phase='{s.get('phase')}' not in valid enum")

    # 7. Report
    counts = human_verdict_counts(clauses)
    print(f"[CHECK] Module: {meta.get('moduleId', '?')} | {len(clauses)} clauses")
    print(f"[CHECK] Verdicts: {counts}")
    print(f"[CHECK] Evidence items: {sum(len(c.get('evidence',[])) for c in clauses)}")
    print(f"[CHECK] executionTrace: {et.get('totalRounds', 0)} rounds, {len(et.get('steps', []))} steps")

    if all_warnings:
        print(f"\n[WARN] {len(all_warnings)} issue(s) — fix before delivery:")
        for w in all_warnings:
            print(f"  - {w}")
        print()
        print("Above issues will cause L1 rejection. Fix them before reporting completion.")
        sys.exit(1)

    print(f"\n[OK] Preflight passed. Safe to deliver and report completion.")
    print(f"     Main thread will still run validate_evidence.py for final L1.")
    sys.exit(0)


if __name__ == "__main__":
    main()
