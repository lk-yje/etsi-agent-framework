"""Audit Agent 的受限只读工作区工具。

Audit 需要独立复核 IXIT 与 evidence，却不能获得 Work Agent 的命令、写入或
MCP 攻击能力。本模块只暴露当前 audit task 明确列出的输入文件，并在路径、
读取量和工具集合三个层面限制访问。
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from framework.tools import ToolDef, ToolParam, ToolRegistry


AUDIT_READONLY_CATEGORY = "audit_readonly"


def build_audit_readonly_registry(
    workspace: Path,
    allowed_inputs: Iterable[str],
) -> ToolRegistry:
    """构建仅能读取本轮审计输入的工具注册表。

    ``allowed_inputs`` 必须是相对工作区的文件路径。工具不会列目录、不会跟随
    到工作区外，也不会暴露 bash/write_file/python_script。IXIT 较大时，Agent
    可以先用 ``search_audit_input`` 定位表名，再使用 ``read_audit_input`` 分段取证。
    """
    root = Path(workspace).resolve()
    allowed: set[Path] = set()
    for item in allowed_inputs:
        candidate = Path(item)
        if candidate.is_absolute():
            raise ValueError(f"Audit input must be workspace-relative: {item}")
        resolved = (root / candidate).resolve()
        if not resolved.is_relative_to(root):
            raise ValueError(f"Audit input escapes workspace: {item}")
        allowed.add(resolved)

    def resolve_allowed(raw_path: object) -> Path:
        requested = Path(str(raw_path or ""))
        if requested.is_absolute():
            raise PermissionError("Audit reader accepts workspace-relative paths only")
        resolved = (root / requested).resolve()
        if not resolved.is_relative_to(root) or resolved not in allowed:
            raise PermissionError("Audit reader path is not an allowed task input")
        if not resolved.is_file():
            raise FileNotFoundError(f"Audit input not found: {requested}")
        return resolved

    async def read_audit_input(params: dict) -> str:
        path = resolve_allowed(params.get("path"))
        offset = max(0, int(params.get("offset", 0)))
        max_chars = min(max(1, int(params.get("max_chars", 12000))), 20000)
        text = path.read_text(encoding="utf-8")
        return text[offset: offset + max_chars]

    async def search_audit_input(params: dict) -> str:
        path = resolve_allowed(params.get("path"))
        query = str(params.get("query", "")).strip()
        if not query:
            raise ValueError("query must not be empty")
        max_results = min(max(1, int(params.get("max_results", 8))), 20)
        context_chars = min(max(0, int(params.get("context_chars", 240))), 1000)
        text = path.read_text(encoding="utf-8")
        lowered = text.casefold()
        needle = query.casefold()
        cursor = 0
        snippets: list[str] = []
        while len(snippets) < max_results:
            index = lowered.find(needle, cursor)
            if index < 0:
                break
            start = max(0, index - context_chars)
            end = min(len(text), index + len(query) + context_chars)
            snippets.append(f"[offset {start}]\n{text[start:end]}")
            cursor = index + len(query)
        return "\n\n---\n\n".join(snippets) or "(no matches)"

    registry = ToolRegistry()
    registry.register([
        ToolDef(
            name="read_audit_input",
            description=(
                "Read a bounded text segment from a file explicitly listed as an "
                "input to this audit task. Paths are workspace-relative and read-only."
            ),
            parameters=[
                ToolParam("path", "string", "Workspace-relative input file path"),
                ToolParam("offset", "integer", "Character offset; default 0", required=False),
                ToolParam("max_chars", "integer", "Characters to read; max 20000", required=False),
            ],
        ),
        ToolDef(
            name="search_audit_input",
            description=(
                "Search a file explicitly listed as an input to this audit task and "
                "return bounded contextual snippets. Use it to locate IXIT table names "
                "or evidence fields before reading a larger segment."
            ),
            parameters=[
                ToolParam("path", "string", "Workspace-relative input file path"),
                ToolParam("query", "string", "Literal text to search for"),
                ToolParam("max_results", "integer", "Maximum matches; default 8", required=False),
                ToolParam("context_chars", "integer", "Context per match; default 240", required=False),
            ],
        ),
    ])
    registry.set_executor("read_audit_input", read_audit_input)
    registry.set_executor("search_audit_input", search_audit_input)
    registry.add_to_category(AUDIT_READONLY_CATEGORY, "read_audit_input")
    registry.add_to_category(AUDIT_READONLY_CATEGORY, "search_audit_input")
    return registry
