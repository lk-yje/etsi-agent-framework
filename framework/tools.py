"""Tool 系统 — 工具定义、注册表、执行器。

AgentRunner 的多轮 tool-use 循环依赖此模块。
工具定义遵循 Anthropic Messages API tool 格式。

MCP 集成 (v0.3):
- BurpMCP-Ultra: 通过 MCP SSE 协议连接 (mcp.client.sse)
- Playwright MCP: 通过 MCP stdio 协议连接 (mcp.client.stdio)
- 动态工具发现: 从 MCP 服务器 tools/list 自动注册
- 使用 MCPClientManager + MCPToolAdapter
"""

import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Callable, Awaitable, Any

# ============================================================
# Tool 定义 (Anthropic-compatible JSON Schema)
# ============================================================


@dataclass(frozen=True)
class ToolParam:
    """工具参数定义"""
    name: str
    type: str = "string"
    description: str = ""
    required: bool = True
    enum: Optional[List[str]] = None


@dataclass(frozen=True)
class ToolDef:
    """单个工具定义 — 对应 Anthropic tool JSON Schema"""
    name: str
    description: str
    parameters: List[ToolParam]

    def to_anthropic_schema(self) -> dict:
        """转换为 Anthropic Messages API 的 tool 格式"""
        props = {}
        required = []
        for p in self.parameters:
            prop_def: dict = {"type": p.type, "description": p.description}
            if p.enum:
                prop_def["enum"] = p.enum
            props[p.name] = prop_def
            if p.required:
                required.append(p.name)

        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": props,
                "required": required,
            },
        }


# ============================================================
# Tool 执行结果
# ============================================================


@dataclass
class ToolResult:
    """工具执行结果"""
    tool_use_id: str
    tool_name: str
    content: str
    is_error: bool = False

    def to_anthropic_block(self) -> dict:
        return {
            "type": "tool_result",
            "tool_use_id": self.tool_use_id,
            "content": self.content,
            "is_error": self.is_error,
        }


# ============================================================
# Tool 执行器类型
# ============================================================

ToolExecutor = Callable[[dict], Awaitable[str]]
"""工具执行函数: 接收参数 dict，返回结果字符串"""


# ============================================================
# 内置执行器
# ============================================================


class BuiltinExecutors:
    """内置工具执行器 — 不依赖外部服务的基础工具"""

    @staticmethod
    async def bash(params: dict) -> str:
        """执行 bash 命令"""
        command = params.get("command", "")
        timeout = int(params.get("timeout", 120))

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            result = stdout.decode("utf-8", errors="replace")
            if stderr:
                result += "\n[stderr]\n" + stderr.decode("utf-8", errors="replace")
            return result or "(no output)"
        except asyncio.TimeoutError:
            return f"(timeout after {timeout}s)"
        except Exception as e:
            return f"(error: {e})"

    @staticmethod
    async def read_file(params: dict) -> str:
        """读取工作区文件"""
        path = params.get("path", "")
        try:
            return Path(path).read_text(encoding="utf-8")
        except Exception as e:
            return f"(read error: {e})"

    @staticmethod
    async def write_file(params: dict) -> str:
        """写入工作区文件"""
        path = params.get("path", "")
        content = params.get("content", "")
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            return f"written: {path} ({len(content)} bytes)"
        except Exception as e:
            return f"(write error: {e})"

    @staticmethod
    async def python_script(params: dict) -> str:
        """执行 Python 脚本"""
        script = params.get("script", "")
        try:
            # 安全限制: 在子进程中执行
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-c", script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=30
            )
            result = stdout.decode("utf-8", errors="replace")
            if stderr:
                result += "\n[stderr]\n" + stderr.decode("utf-8", errors="replace")
            return result or "(no output)"
        except Exception as e:
            return f"(error: {e})"


# ============================================================
# 标准工具定义
# ============================================================

STANDARD_TOOLS = [
    ToolDef(
        name="bash",
        description="Execute a shell command and return its output. Use for nmap scans, curl requests, tshark analysis, and other CLI tools.",
        parameters=[
            ToolParam("command", "string", "The shell command to execute"),
            ToolParam("timeout", "integer", "Timeout in seconds (default 120)", required=False),
        ],
    ),
    ToolDef(
        name="read_file",
        description="Read the contents of a file in the workspace. Use to read IXIT JSON, nmap output, pcap analysis results.",
        parameters=[
            ToolParam("path", "string", "Relative or absolute path to the file"),
        ],
    ),
    ToolDef(
        name="write_file",
        description="Write content to a file in the workspace. Use to save command output, evidence artifacts.",
        parameters=[
            ToolParam("path", "string", "File path to write to"),
            ToolParam("content", "string", "Content to write"),
        ],
    ),
    ToolDef(
        name="python_script",
        description="Execute a Python script for data analysis or validation.",
        parameters=[
            ToolParam("script", "string", "Python code to execute"),
        ],
    ),
]

# ============================================================
# 工具分类常量 — ModuleDef.tools 中的分类名映射
# ============================================================

# ModuleDef.tools 中使用的分类名
CATEGORY_STANDARD = "bash"          # 标准 CLI 工具 (bash, read_file, write_file, python_script)
CATEGORY_BURP_MCP = "burp_mcp"     # BurpMCP-Ultra 工具 (server_name="burp")
CATEGORY_PLAYWRIGHT = "playwright_mcp"  # Playwright MCP 工具 (server_name="playwright")

# 标准工具名列表 (对应 CATEGORY_STANDARD)
STANDARD_TOOL_NAMES = [t.name for t in STANDARD_TOOLS]

# server_name → 分类名映射
_SERVER_CATEGORY_MAP = {
    "burp": CATEGORY_BURP_MCP,
    "playwright": CATEGORY_PLAYWRIGHT,
}


def _server_to_category(server_name: str) -> Optional[str]:
    """MCP server_name 转工具分类名。"""
    return _SERVER_CATEGORY_MAP.get(server_name)


# ============================================================
# MCP 工具适配器
# ============================================================


class MCPToolAdapter:
    """将 MCPClientManager 的工具适配到 ToolRegistry。

    通过 MCP SDK 的 tools/list 动态发现工具，转换为 ToolDef，
    并创建闭包 executor 路由到 MCPClientManager.call_tool()。

    用法:
        adapter = MCPToolAdapter(mcp_manager)
        count = await adapter.register_all(registry)
    """

    def __init__(self, mcp_manager):
        """
        Args:
            mcp_manager: MCPClientManager 实例 (已连接)
        """
        self.mcp = mcp_manager

    async def register_all(self, registry: "ToolRegistry") -> int:
        """从所有连接的 MCP 服务器发现并注册工具。

        同时将工具按 server_name 归入分类 (burp_mcp / playwright_mcp)，
        供 ModuleDef.tools 过滤使用。

        Returns:
            注册的工具数量
        """
        tools = await self.mcp.list_all_tools()
        for tool_info in tools:
            tool_def = self._mcp_to_tooldef(tool_info)
            registry.register([tool_def])

            # 闭包捕获 MCP 原生工具名
            def make_executor(name):
                async def executor(params: dict) -> str:
                    return await self.mcp.call_tool(name, params)
                return executor

            registry.set_executor(tool_info.name, make_executor(tool_info.name))

            # 按 server_name 归入分类
            category = _server_to_category(tool_info.server_name)
            if category:
                registry.add_to_category(category, tool_info.name)

        return len(tools)

    @staticmethod
    def _mcp_to_tooldef(tool_info) -> "ToolDef":
        """将 MCP 工具的 JSON Schema 转换为框架 ToolDef。

        MCP 返回的 input_schema 是标准 JSON Schema，
        我们从中提取 properties 和 required 构建 ToolParam 列表。
        """
        schema = tool_info.input_schema or {}
        properties = schema.get("properties", {})
        required_fields = set(schema.get("required", []))

        params = []
        for param_name, param_schema in properties.items():
            param_type = param_schema.get("type", "string")
            param_desc = param_schema.get("description", "")
            is_required = param_name in required_fields
            enum_values = param_schema.get("enum", None)

            params.append(ToolParam(
                name=param_name,
                type=param_type,
                description=param_desc,
                required=is_required,
                enum=enum_values,
            ))

        return ToolDef(
            name=tool_info.name,
            description=tool_info.description or f"MCP tool: {tool_info.name}",
            parameters=params,
        )


# ============================================================
# Tool 注册表
# ============================================================


class ToolRegistry:
    """工具注册表 — 管理工具定义和执行器的映射。

    用法:
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())
        # 动态注册 MCP 工具 (需要 MCPClientManager):
        await registry.register_mcp_tools(mcp_manager)
        # 添加自定义执行器:
        registry.set_executor("bash", my_custom_bash)
    """

    def __init__(self):
        self._defs: Dict[str, ToolDef] = {}
        self._executors: Dict[str, ToolExecutor] = {}
        self._category_map: Dict[str, List[str]] = {}

    def register(self, tools: List[ToolDef], executor_source: Any = None) -> None:
        """批量注册工具定义"""
        _std_names = {t.name for t in STANDARD_TOOLS}
        for t in tools:
            self._defs[t.name] = t
            # 标准工具自动归入 "bash" 分类
            if t.name in _std_names:
                self.add_to_category(CATEGORY_STANDARD, t.name)

        # 自动从 executor_source 绑定
        if executor_source is not None:
            for t in tools:
                fn = getattr(executor_source, t.name, None)
                if fn:
                    self._executors[t.name] = fn

    def add_to_category(self, category: str, tool_name: str) -> None:
        """将工具添加到指定分类（供 ModuleDef.tools 过滤使用）。"""
        if category not in self._category_map:
            self._category_map[category] = []
        if tool_name not in self._category_map[category]:
            self._category_map[category].append(tool_name)

    def resolve_categories(self, categories: tuple) -> List[str]:
        """将分类名列表解析为实际工具名列表。

        Args:
            categories: 分类名元组，如 ("bash", "burp_mcp", "playwright_mcp")

        Returns:
            去重后的工具名列表
        """
        result = []
        seen = set()
        for cat in categories:
            if cat == CATEGORY_STANDARD:
                names = STANDARD_TOOL_NAMES
            else:
                names = self._category_map.get(cat, [])
            for name in names:
                if name not in seen and name in self._defs:
                    seen.add(name)
                    result.append(name)
        return result

    async def register_mcp_tools(self, mcp_manager) -> int:
        """从 MCP 服务器动态发现并注册所有工具。

        使用 MCPToolAdapter 连接 MCPClientManager:
        - 调用 tools/list 发现工具
        - 转换为 ToolDef + 闭包 executor
        - 注册到本 registry

        Args:
            mcp_manager: MCPClientManager 实例 (已连接)

        Returns:
            注册的工具数量
        """
        adapter = MCPToolAdapter(mcp_manager)
        return await adapter.register_all(self)

    def set_executor(self, name: str, executor: ToolExecutor) -> None:
        """设置工具的执行器"""
        self._executors[name] = executor

    def get_def(self, name: str) -> Optional[ToolDef]:
        return self._defs.get(name)

    def get_executor(self, name: str) -> Optional[ToolExecutor]:
        return self._executors.get(name)

    def to_anthropic_schemas(self, names: Optional[List[str]] = None) -> List[dict]:
        """导出为 Anthropic API tools 参数格式"""
        targets = names or list(self._defs.keys())
        return [self._defs[n].to_anthropic_schema() for n in targets if n in self._defs]

    async def execute(self, name: str, params: dict, receipt_context: Optional[dict] = None) -> ToolResult:
        """执行工具并返回结果；带 workspace 上下文时异步写入工具调用收据。"""
        started_at = datetime.now()
        effective_context = dict(receipt_context or {})
        effective_params = params
        if receipt_context:
            from framework.execution_policy import ToolExecutionPolicy
            decision = ToolExecutionPolicy(receipt_context).validate(name, params)
            effective_context["policy"] = decision.as_receipt()
            effective_params = decision.params
            if not decision.allowed:
                result = ToolResult(
                    tool_use_id="", tool_name=name,
                    content=f"Tool policy blocked ({decision.code}): {decision.reason}",
                    is_error=True,
                )
                from framework.tool_receipts import record_tool_receipt
                record_tool_receipt(
                    effective_context, name, effective_params, result.content, True,
                    started_at, datetime.now(),
                )
                return result
        executor = self._executors.get(name)
        if executor is None:
            result = ToolResult(
                tool_use_id="",
                tool_name=name,
                content=f"Tool '{name}' has no executor registered",
                is_error=True,
            )
        else:
            try:
                content = await executor(effective_params)
                result = ToolResult(
                    tool_use_id="",
                    tool_name=name,
                    content=content,
                )
            except Exception as e:
                result = ToolResult(
                    tool_use_id="",
                    tool_name=name,
                    content=f"Tool execution error: {e}",
                    is_error=True,
                )

        if effective_context:
            artifact_context = dict(effective_context)
            if name == "write_file" and not result.is_error:
                artifact = self._workspace_artifact_ref(effective_context, effective_params.get("path"))
                if artifact:
                    artifact_context["artifact_refs"] = [artifact]
            from framework.tool_receipts import record_tool_receipt
            record_tool_receipt(
                artifact_context, name, effective_params, result.content, result.is_error,
                started_at, datetime.now(),
            )
        return result

    @staticmethod
    def _workspace_artifact_ref(context: dict, raw_path: object) -> str | None:
        if not context.get("workspace") or not isinstance(raw_path, str):
            return None
        try:
            workspace = Path(context["workspace"]).resolve()
            path = Path(raw_path).resolve()
            return path.relative_to(workspace).as_posix() if path.is_relative_to(workspace) else None
        except OSError:
            return None

    @property
    def tool_names(self) -> List[str]:
        return list(self._defs.keys())

    @property
    def tool_count(self) -> int:
        return len(self._defs)
