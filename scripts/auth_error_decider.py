#!/usr/bin/env python3
"""
Auth Step — FC-Loop Pivot: 工具错误 → KB 自动查表 → 输出决策。

agent 在任何工具调用失败时执行此脚本。输入错误文本 + 工具名，
脚本匹配 tool-error-kb.json 中的已知签名，输出决策指令。
agent 只需执行返回值，不需要自己做错误分析。

用法:
  python auth_error_decider.py <tool_name> "<error_text>"
  python auth_error_decider.py burp_mcp "auth_diff returned status_code:0 for all levels"

输出 (JSON):
  {
    "kb_hit": true,
    "signature": "AUTH_DIFF_CRLF_TIMEOUT",
    "decision": "retry_different_params",
    "instruction": "将 request 参数中所有 \\n 替换为 \\r\\n...",
    "retry_params": "...",
    "on_retry_fail": { "decision": "degrade_semiauto", "reason": "..." },
    "fallback_chain": [...]
  }

退出码:
  0 = KB 命中，decision 可用
  1 = KB 未命中 (走通用决策树，decision 由通用逻辑生成)
  2 = KB 文件不可用
"""

import json
import os
import re
import sys
from typing import Optional


# -- 通用决策树 (KB 未命中时使用) ----------------------------------
GENERIC_DECISION_TREE = {
    "transient_patterns": [
        (r"timeout|timed.out|ECONNREFUSED|Connection refused|connection reset", "retry"),
        (r"500 Internal Server|503 Service|502 Bad Gateway|429", "retry"),
    ],
    "permanent_patterns": [
        (r"Permission denied|requires root|Access denied|not authorized", "report_to_main"),
        (r"file not found|no such file|command not found|not recognized", "skip_with_inconclusive"),
        (r"WAF|IPS|blocked|banned|rate limit exceeded", "degrade_semiauto"),
    ],
}


def load_kb(kb_path: Optional[str] = None) -> dict:
    """加载 tool-error-kb.json。"""
    if kb_path is None:
        _script_dir = os.path.dirname(os.path.abspath(__file__))
        # 优先: 项目内 skills/ 目录
        _local = os.path.join(_script_dir, "..", "skills", "etsi-ts103701-report", "references", "tool-error-kb.json")
        # 次选: ~/.claude/skills
        _home = os.path.join(os.path.expanduser("~"), ".claude", "skills", "etsi-ts103701-report", "references", "tool-error-kb.json")
        if os.path.exists(_local):
            kb_path = _local
        elif os.path.exists(_home):
            kb_path = _home
        else:
            raise FileNotFoundError(f"tool-error-kb.json not found at {_local} or {_home}")
    with open(kb_path, "r", encoding="utf-8") as f:
        return json.load(f)


def match_signature(error_text: str, kb: dict, tool_name: str) -> Optional[dict]:
    """在 KB 中匹配错误签名。返回匹配的 entry 或 None。"""
    tool_name_lower = tool_name.lower()

    # 先精确匹配工具名
    for entry in kb.get("entries", []):
        entry_tool = entry.get("tool", "").lower()
        if tool_name_lower == entry_tool or tool_name_lower in entry_tool or entry_tool in tool_name_lower:
            for err in entry.get("errors", []):
                for pattern in err.get("patterns", []):
                    if re.search(pattern, error_text, re.IGNORECASE):
                        return {
                            "tool": entry["tool"],
                            "error_entry": err,
                            "matched_pattern": pattern,
                        }

    # 再模糊匹配 (generic 条目)
    for entry in kb.get("entries", []):
        if entry.get("tool") == "generic":
            for err in entry.get("errors", []):
                for pattern in err.get("patterns", []):
                    if re.search(pattern, error_text, re.IGNORECASE):
                        return {
                            "tool": "generic",
                            "error_entry": err,
                            "matched_pattern": pattern,
                        }

    return None


def generic_decision(error_text: str) -> dict:
    """通用决策树: 从错误文本推断决策。"""
    error_lower = error_text.lower()

    # 瞬态 → retry
    for pattern, decision in GENERIC_DECISION_TREE["transient_patterns"]:
        if re.search(pattern, error_text, re.IGNORECASE):
            return {
                "signature": "GENERIC_TRANSIENT",
                "decision": decision,
                "reason": f"匹配瞬态错误模式: '{pattern}'",
                "retry_params": "同参数重试 1 次",
                "on_retry_fail": {"decision": "skip_with_inconclusive", "reason": "重试仍失败 → 永久错误"},
            }

    # 永久 → 不重试
    for pattern, decision in GENERIC_DECISION_TREE["permanent_patterns"]:
        if re.search(pattern, error_text, re.IGNORECASE):
            return {
                "signature": "GENERIC_PERMANENT",
                "decision": decision,
                "reason": f"匹配永久错误模式: '{pattern}'",
                "retry_params": None,
                "on_retry_fail": None,
            }

    # 兜底: retry 1 次
    return {
        "signature": "GENERIC_UNKNOWN",
        "decision": "retry",
        "reason": "未匹配任何已知模式，视为未知瞬态错误",
        "retry_params": "同参数重试 1 次",
        "on_retry_fail": {"decision": "skip_with_inconclusive", "reason": "未知错误，重试仍失败"},
    }


def decide(tool_name: str, error_text: str, kb_path: Optional[str] = None) -> dict:
    """主决策函数。"""
    try:
        kb = load_kb(kb_path)
    except FileNotFoundError as e:
        return {
            "kb_hit": False,
            "kb_error": str(e),
            "signature": "KB_UNAVAILABLE",
            "decision": "retry",
            "reason": "tool-error-kb.json 不可用，走通用决策树: retry 1 次",
            "retry_params": "同参数重试 1 次",
            "on_retry_fail": {"decision": "skip_with_inconclusive", "reason": "KB 不可用 + 重试失败"},
            "fallback_chain": ["KB_UNAVAILABLE → retry → onRetryFail: skip_with_inconclusive"],
        }

    match = match_signature(error_text, kb, tool_name)

    if match:
        err = match["error_entry"]
        on_rf = err.get("onRetryFail") or {}
        return {
            "kb_hit": True,
            "signature": err["signature"],
            "matched_pattern": match["matched_pattern"],
            "tool": match["tool"],
            "root_cause": err.get("rootCause", ""),
            "decision": err["decision"],
            "retry_params": err.get("retryParams"),
            "alternative": err.get("alternative"),
            "on_retry_fail": {
                "decision": on_rf.get("decision", "skip_with_inconclusive"),
                "reason": on_rf.get("reason", ""),
            },
            "history": err.get("history", []),
            "fallback_chain": [
                f"{err['signature']} → {err['decision']}",
            ],
        }

    # KB 未命中 → 通用决策树
    generic = generic_decision(error_text)
    return {
        "kb_hit": False,
        "signature": generic["signature"],
        "decision": generic["decision"],
        "reason": generic["reason"],
        "retry_params": generic.get("retry_params"),
        "on_retry_fail": generic.get("on_retry_fail"),
        "fallback_chain": [f"KB_MISS → {generic['signature']} → {generic['decision']}"],
    }


def main():
    if len(sys.argv) < 3:
        print("用法: python auth_error_decider.py <tool_name> '<error_text>'", file=sys.stderr)
        print("示例: python auth_error_decider.py burp_mcp 'status_code:0 response_time_ms:80'", file=sys.stderr)
        sys.exit(2)

    tool_name = sys.argv[1]
    error_text = sys.argv[2]
    kb_path = sys.argv[3] if len(sys.argv) > 3 else None

    result = decide(tool_name, error_text, kb_path)
    print(json.dumps(result, indent=2, ensure_ascii=False))

    if result.get("kb_hit"):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
