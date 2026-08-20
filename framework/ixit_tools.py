"""只读 IXIT 检索工具，供概念性条款使用。

概念性测试需要从多个 IXIT 表定位声明，但不需要通用 shell、写文件或网络能力。
本模块把可审计的定位结果（JSON pointer + offset）返回给 Work Agent；正式
EvidenceManifest 仍由 Agent 返回，再交给 PhaseEngine 校验与原子落盘。
"""

from __future__ import annotations

import json
from pathlib import Path

from framework.tools import ToolDef, ToolParam, ToolRegistry


IXIT_READONLY_CATEGORY = "ixit_readonly"
_MAX_CHARS = 32_000


def build_ixit_readonly_registry(registry: ToolRegistry, workspace: Path) -> None:
    """Register bounded, local-only IXIT readers against one workspace."""
    root = Path(workspace).resolve()

    def load_ixit() -> dict:
        source = root / "ixit.json"
        if not source.is_file():
            raise FileNotFoundError("ixit.json 不存在；概念性测试需要已归一化的本地输入")
        data = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("ixit.json 顶层必须为 object")
        return data

    def bounded_json(value: object, pointer: str, offset: int, max_chars: int) -> str:
        text = json.dumps(value, ensure_ascii=False, indent=2)
        start = max(0, offset)
        length = min(max(1, max_chars), _MAX_CHARS)
        return json.dumps({
            "source": f"ixit.json#{pointer}",
            "offset": start,
            "total_chars": len(text),
            "content": text[start:start + length],
        }, ensure_ascii=False)

    async def read_ixit_table(params: dict) -> str:
        table_name = str(params.get("table_name", "")).strip()
        tables = load_ixit().get("ixit_tables", {})
        if not table_name:
            raise ValueError("table_name 不能为空")
        if table_name not in tables:
            available = ", ".join(sorted(tables))
            raise KeyError(f"IXIT 表不存在: {table_name}; 可用表: {available}")
        return bounded_json(
            tables[table_name],
            f"/ixit_tables/{table_name}",
            int(params.get("offset", 0)),
            int(params.get("max_chars", 16000)),
        )

    async def read_ics_clause(params: dict) -> str:
        clause_id = str(params.get("clause_id", "")).strip()
        if not clause_id:
            raise ValueError("clause_id 不能为空")
        matches = [
            {"index": index, "entry": item}
            for index, item in enumerate(load_ixit().get("ics", []))
            if isinstance(item, dict) and clause_id in str(item.get("reference", ""))
        ]
        if not matches:
            raise KeyError(f"ICS 中未找到条款: {clause_id}")
        return bounded_json(
            matches,
            "/ics",
            int(params.get("offset", 0)),
            int(params.get("max_chars", 16000)),
        )

    async def read_ics_list(params: dict) -> str:
        """Read the entire ICS list (paged) — for document-completeness clauses
        that must scan every recommendation rather than filter by one clause ID."""
        data = load_ixit().get("ics", [])
        return bounded_json(
            data,
            "/ics",
            int(params.get("offset", 0)),
            int(params.get("max_chars", 32000)),
        )

    async def search_ixit(params: dict) -> str:
        query = str(params.get("query", "")).strip()
        if not query:
            raise ValueError("query 不能为空")
        scope = str(params.get("scope", "all")).strip().lower()
        data = load_ixit()
        haystacks: list[tuple[str, object]] = []
        if scope in {"all", "ics"}:
            haystacks.append(("/ics", data.get("ics", [])))
        if scope in {"all", "tables"}:
            haystacks.extend(
                (f"/ixit_tables/{name}", table)
                for name, table in data.get("ixit_tables", {}).items()
            )
        if scope not in {"all", "ics", "tables"}:
            raise ValueError("scope 只能是 all、ics 或 tables")

        limit = min(max(1, int(params.get("max_results", 8))), 20)
        needle = query.casefold()
        results: list[dict] = []
        for pointer, value in haystacks:
            text = json.dumps(value, ensure_ascii=False)
            index = text.casefold().find(needle)
            if index < 0:
                continue
            results.append({
                "source": f"ixit.json#{pointer}",
                "offset": index,
                "context": text[max(0, index - 320):index + len(query) + 640],
            })
            if len(results) >= limit:
                break
        return json.dumps({"query": query, "results": results}, ensure_ascii=False)

    definitions = [
        ToolDef(
            name="read_ixit_table",
            description="Read one named IXIT table from this run's local normalized ixit.json. Read-only.",
            parameters=[
                ToolParam("table_name", "string", "Exact IXIT table name, e.g. 16-CodeMin"),
                ToolParam("offset", "integer", "Character offset", required=False),
                ToolParam("max_chars", "integer", "Maximum characters (<=16000)", required=False),
            ],
        ),
        ToolDef(
            name="read_ics_clause",
            description="Read ICS entries matching one ETSI clause ID from this run's local ixit.json. Read-only.",
            parameters=[
                ToolParam("clause_id", "string", "Clause ID, e.g. 5.6-6"),
                ToolParam("offset", "integer", "Character offset", required=False),
                ToolParam("max_chars", "integer", "Maximum characters (<=16000)", required=False),
            ],
        ),
        ToolDef(
            name="read_ics_list",
            description="Read the entire ICS list (paged by offset) from this run's local ixit.json. Read-only.",
            parameters=[
                ToolParam("offset", "integer", "Character offset", required=False),
                ToolParam("max_chars", "integer", "Maximum characters (<=32000)", required=False),
            ],
        ),
        ToolDef(
            name="search_ixit",
            description="Search local ICS and IXIT tables and return bounded, pointer-addressable matches. Read-only.",
            parameters=[
                ToolParam("query", "string", "Literal text to find"),
                ToolParam("scope", "string", "all, ics, or tables", required=False, enum=["all", "ics", "tables"]),
                ToolParam("max_results", "integer", "Maximum matches (<=20)", required=False),
            ],
        ),
    ]
    registry.register(definitions)
    registry.set_executor("read_ixit_table", read_ixit_table)
    registry.set_executor("read_ics_clause", read_ics_clause)
    registry.set_executor("read_ics_list", read_ics_list)
    registry.set_executor("search_ixit", search_ixit)
    for definition in definitions:
        registry.add_to_category(IXIT_READONLY_CATEGORY, definition.name)
