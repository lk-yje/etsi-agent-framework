"""从当前条款目录生成真机验收表；不连接 DUT、不执行工具。"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "framework" / "clause_tool_map.json"
OUTPUT = Path(__file__).resolve().parent / "条款验收清单.md"


def main() -> None:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    lines = [
        "# full / partial 条款真机验收清单", "",
        "> 由当前 `framework/clause_tool_map.json` 生成；仅列 full/partial，manual 条款进入报告手工指引。", "",
        "| 条款 | 自动化等级 | 当前工具类别 | 当前方法 | 签收 |", "|---|---|---|---|---|",
    ]
    for clause_id, entry in catalog.items():
        automation = entry.get("automation")
        if automation not in {"full", "partial"}:
            continue
        tool_groups = [f"{kind}: {' / '.join(values)}" for kind, values in entry.get("tools", {}).items() if values]
        tools = "; ".join(tool_groups) or "既有产物/人工边界"
        method = str(entry.get("method", "")).replace("|", "\\|")
        lines.append(f"| {clause_id} | {automation} | {tools} | {method} | ☐ |")
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"已生成：{OUTPUT}")


if __name__ == "__main__":
    main()
