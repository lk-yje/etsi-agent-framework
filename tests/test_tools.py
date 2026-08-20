"""Tool 系统测试 — ToolDef, ToolRegistry, 多轮 AgentRunner"""

import tempfile
from pathlib import Path
import json
from types import SimpleNamespace
import pytest

from framework.agent_runner import AgentConfig, AgentRunner
from framework.telemetry import Telemetry
from framework.tools import (
    ToolDef, ToolParam, ToolResult, ToolRegistry,
    STANDARD_TOOLS, BuiltinExecutors,
    CATEGORY_STANDARD, CATEGORY_BURP_MCP, CATEGORY_PLAYWRIGHT,
)
from framework.audit_tools import (
    AUDIT_READONLY_CATEGORY,
    build_audit_readonly_registry,
)


class TestToolDef:
    """ToolDef → Anthropic schema 转换"""

    def test_basic_tool_schema(self):
        t = ToolDef(
            name="bash",
            description="Execute a shell command",
            parameters=[
                ToolParam("command", "string", "The command"),
            ],
        )
        schema = t.to_anthropic_schema()
        assert schema["name"] == "bash"
        assert schema["description"] == "Execute a shell command"
        assert "command" in schema["input_schema"]["properties"]
        assert "command" in schema["input_schema"]["required"]

    def test_tool_with_optional_params(self):
        t = ToolDef(
            name="search",
            description="Search",
            parameters=[
                ToolParam("query", "string", "Search query"),
                ToolParam("limit", "integer", "Max results", required=False),
            ],
        )
        schema = t.to_anthropic_schema()
        assert "query" in schema["input_schema"]["required"]
        assert "limit" not in schema["input_schema"]["required"]
        assert "limit" in schema["input_schema"]["properties"]

    def test_tool_with_enum(self):
        t = ToolDef(
            name="set_level",
            description="Set level",
            parameters=[
                ToolParam("level", "string", "Log level", enum=["debug", "info", "error"]),
            ],
        )
        schema = t.to_anthropic_schema()
        assert schema["input_schema"]["properties"]["level"]["enum"] == ["debug", "info", "error"]

    def test_tool_immutability(self):
        t = ToolDef(name="test", description="desc", parameters=[])
        with pytest.raises(Exception):
            t.name = "hacked"  # frozen dataclass


class TestToolRegistry:
    """ToolRegistry 注册与执行"""

    def test_register_standard_tools(self):
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())
        assert registry.tool_count >= 4
        assert "bash" in registry.tool_names
        assert "read_file" in registry.tool_names

    def test_to_anthropic_schemas(self):
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())
        schemas = registry.to_anthropic_schemas(["bash", "read_file"])
        assert len(schemas) == 2
        assert schemas[0]["name"] == "bash"

    def test_execute_unknown_tool(self):
        registry = ToolRegistry()
        result = await_asyncio(registry.execute("nonexistent", {}))
        assert result.is_error

    def test_execute_bash_builtin(self):
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())
        result = await_asyncio(registry.execute("bash", {"command": "echo hello"}))
        assert not result.is_error
        assert "hello" in result.content

    def test_execute_read_file(self):
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test content")
            path = f.name

        try:
            result = await_asyncio(registry.execute("read_file", {"path": path}))
            assert not result.is_error
            assert "test content" in result.content
        finally:
            Path(path).unlink()

    def test_execute_write_file(self):
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())

        with tempfile.TemporaryDirectory() as tmp:
            filepath = str(Path(tmp) / "output.txt")
            result = await_asyncio(registry.execute("write_file", {
                "path": filepath,
                "content": "hello world",
            }))
            assert not result.is_error
            assert Path(filepath).read_text() == "hello world"

    def test_custom_executor(self):
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())

        async def custom_bash(params):
            return "custom: " + params.get("command", "")

        registry.set_executor("bash", custom_bash)
        result = await_asyncio(registry.execute("bash", {"command": "test"}))
        assert "custom: test" in result.content

    def test_filtered_schemas(self):
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())
        schemas = registry.to_anthropic_schemas(["bash"])
        assert len(schemas) == 1
        assert schemas[0]["name"] == "bash"

    def test_standard_tools_auto_categorized(self):
        """注册标准工具时自动归入 'bash' 分类"""
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())
        names = registry.resolve_categories((CATEGORY_STANDARD,))
        assert set(names) == {"bash", "read_file", "write_file", "python_script"}

    def test_add_to_category(self):
        """手动添加工具到分类"""
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())
        # 添加 MCP 工具到 burp_mcp 分类
        tool = ToolDef(name="http_send_request", description="test", parameters=[])
        registry.register([tool])
        registry.add_to_category(CATEGORY_BURP_MCP, "http_send_request")
        names = registry.resolve_categories((CATEGORY_BURP_MCP,))
        assert names == ["http_send_request"]

    def test_resolve_categories_mixed(self):
        """混合分类解析: bash + burp_mcp"""
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())
        # 添加 burp 工具
        for name in ("http_send_request", "proxy_history_search"):
            t = ToolDef(name=name, description="test", parameters=[])
            registry.register([t])
            registry.add_to_category(CATEGORY_BURP_MCP, name)

        names = registry.resolve_categories((CATEGORY_STANDARD, CATEGORY_BURP_MCP))
        assert "bash" in names
        assert "read_file" in names
        assert "http_send_request" in names
        assert "proxy_history_search" in names
        # playwright 工具不应该出现
        assert "browser_navigate" not in names

    def test_resolve_categories_dedup(self):
        """分类解析去重"""
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())
        # 两次添加相同工具
        registry.add_to_category(CATEGORY_BURP_MCP, "bash")
        names = registry.resolve_categories((CATEGORY_STANDARD, CATEGORY_BURP_MCP))
        assert names.count("bash") == 1

    def test_resolve_categories_unknown(self):
        """未知分类返回空"""
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())
        names = registry.resolve_categories(("unknown_category",))
        assert names == []

    def test_resolve_categories_empty_tuple(self):
        """空分类元组返回空"""
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())
        names = registry.resolve_categories(())
        assert names == []

    def test_schemas_filtered_by_category(self):
        """to_anthropic_schemas 配合 resolve_categories 实现模块级过滤"""
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())
        # 模拟 M1 模块: bash + burp_mcp
        for name in ("http_send_request", "sitemap_query"):
            t = ToolDef(name=name, description="test", parameters=[])
            registry.register([t])
            registry.add_to_category(CATEGORY_BURP_MCP, name)
        # 模拟 playwright 工具 (不应出现在 M1 中)
        pw_tool = ToolDef(name="browser_navigate", description="test", parameters=[])
        registry.register([pw_tool])
        registry.add_to_category(CATEGORY_PLAYWRIGHT, "browser_navigate")

        # M1 只声明 bash + burp_mcp
        module_tools = (CATEGORY_STANDARD, CATEGORY_BURP_MCP)
        filtered = registry.resolve_categories(module_tools)
        schemas = registry.to_anthropic_schemas(filtered)
        schema_names = {s["name"] for s in schemas}

        assert "bash" in schema_names
        assert "http_send_request" in schema_names
        assert "browser_navigate" not in schema_names  # Playwright 被过滤


class TestToolResult:
    """ToolResult → Anthropic block 转换"""

    def test_basic_result(self):
        r = ToolResult(
            tool_use_id="tu_001",
            tool_name="bash",
            content="command output",
        )
        block = r.to_anthropic_block()
        assert block["type"] == "tool_result"
        assert block["tool_use_id"] == "tu_001"
        assert block["content"] == "command output"
        assert not block["is_error"]

    def test_error_result(self):
        r = ToolResult(
            tool_use_id="tu_002",
            tool_name="bash",
            content="command not found",
            is_error=True,
        )
        assert r.is_error


class TestStandardTools:
    """标准工具定义完整性"""

    def test_all_standard_tools_have_executors(self):
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())

        for name in registry.tool_names:
            executor = registry.get_executor(name)
            assert executor is not None, f"Tool '{name}' has no executor"

    def test_all_params_have_descriptions(self):
        for t in STANDARD_TOOLS:
            for p in t.parameters:
                assert p.description, f"{t.name}.{p.name} missing description"


class TestAuditReadonlyTools:
    """Audit Agent 只能读取本轮 task 明列的输入文件。"""

    def test_only_exposes_bounded_read_and_search(self, tmp_path):
        (tmp_path / "ixit.json").write_text('{"table": "7-UpdMech"}', encoding="utf-8")
        registry = build_audit_readonly_registry(tmp_path, ["ixit.json"])

        assert registry.resolve_categories((AUDIT_READONLY_CATEGORY,)) == [
            "read_audit_input", "search_audit_input",
        ]
        assert set(registry.tool_names) == {"read_audit_input", "search_audit_input"}
        assert "bash" not in registry.tool_names
        assert "write_file" not in registry.tool_names

    def test_reads_and_searches_allowed_input_only(self, tmp_path):
        (tmp_path / "ixit.json").write_text(
            '{"table": "7-UpdMech", "value": "auto update"}',
            encoding="utf-8",
        )
        (tmp_path / "secret.txt").write_text("not an audit input", encoding="utf-8")
        registry = build_audit_readonly_registry(tmp_path, ["ixit.json"])

        read = await_asyncio(registry.execute("read_audit_input", {"path": "ixit.json"}))
        search = await_asyncio(registry.execute("search_audit_input", {
            "path": "ixit.json", "query": "7-UpdMech",
        }))
        denied = await_asyncio(registry.execute("read_audit_input", {"path": "secret.txt"}))
        traversal = await_asyncio(registry.execute("read_audit_input", {"path": "../secret.txt"}))

        assert not read.is_error and "auto update" in read.content
        assert not search.is_error and "7-UpdMech" in search.content
        assert denied.is_error
        assert traversal.is_error


class TestAgentRunnerToolBudget:
    """工具预算耗尽后仍必须请求一次无工具的最终结构化输出。"""

    def test_tool_budget_forces_final_no_tool_turn(self, tmp_path):
        persona = tmp_path / "persona.md"
        persona.write_text("你是受控测试 Agent。", encoding="utf-8")

        class MockMessages:
            def __init__(self):
                self.calls = []

            async def create(self, **params):
                self.calls.append(params)
                if len(self.calls) == 1:
                    return SimpleNamespace(
                        content=[SimpleNamespace(
                            type="tool_use", id="tool-1", name="lookup", input={"key": "x"},
                        )],
                        usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                    )
                return SimpleNamespace(
                    content=[SimpleNamespace(type="text", text='{"verdict":"PASS"}')],
                    usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                )

        class MockClient:
            def __init__(self):
                self.messages = MockMessages()

        registry = ToolRegistry()
        registry.register([ToolDef(
            name="lookup", description="Read a bounded fixture", parameters=[
                ToolParam("key", "string", "Fixture key"),
            ],
        )])

        async def lookup(_params):
            return "fixture-result"

        registry.set_executor("lookup", lookup)
        client = MockClient()
        runner = AgentRunner(client, Telemetry(tmp_path / "logs"))
        config = AgentConfig(
            agent_id="budget-test",
            agent_type="work",
            persona_path=persona,
            max_tool_turns=1,
        )

        result = await_asyncio(runner.run(
            config,
            {"task": "读取 fixture 后输出 JSON", "workspace": str(tmp_path)},
            tools=registry,
            retry_on_api_error=False,
        ))

        assert result.raw_text == '{"verdict":"PASS"}'
        assert result.trace.tool_calls_count == 1
        assert len(client.messages.calls) == 2
        assert client.messages.calls[1]["tool_choice"] == {"type": "none"}
        assert "工具调用预算已用尽" in client.messages.calls[1]["messages"][-1]["content"]

    def test_textual_dsml_tool_call_recovers_without_tool_schema(self, tmp_path):
        """A provider's textual tool envelope must never be executed as a tool."""
        persona = tmp_path / "persona.md"
        persona.write_text("你是受控测试 Agent。", encoding="utf-8")

        class MockMessages:
            def __init__(self):
                self.calls = []

            async def create(self, **params):
                self.calls.append(params)
                if len(self.calls) == 1:
                    return SimpleNamespace(
                        content=[SimpleNamespace(
                            type="tool_use", id="tool-1", name="lookup", input={"key": "x"},
                        )],
                        usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                    )
                if len(self.calls) == 2:
                    return SimpleNamespace(
                        content=[SimpleNamespace(
                            type="text", text="<｜｜DSML｜｜tool_calls>ignored</｜｜DSML｜｜tool_calls>",
                        )],
                        usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                    )
                return SimpleNamespace(
                    content=[SimpleNamespace(type="text", text='{"verdict":"PASS"}')],
                    usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                )

        class MockClient:
            def __init__(self):
                self.messages = MockMessages()

        registry = ToolRegistry()
        registry.register([ToolDef(
            name="lookup", description="Read a bounded fixture", parameters=[
                ToolParam("key", "string", "Fixture key"),
            ],
        )])

        async def lookup(_params):
            return "fixture-result"

        registry.set_executor("lookup", lookup)
        client = MockClient()
        runner = AgentRunner(client, Telemetry(tmp_path / "logs"))
        config = AgentConfig(
            agent_id="dsml-budget-test", agent_type="work", persona_path=persona,
            max_tool_turns=1,
        )

        result = await_asyncio(runner.run(
            config,
            {"task": "读取 fixture 后输出 JSON", "workspace": str(tmp_path)},
            tools=registry,
            retry_on_api_error=False,
        ))

        assert result.raw_text == '{"verdict":"PASS"}'
        assert result.trace.tool_calls_count == 1
        assert len(client.messages.calls) == 3
        assert "tools" not in client.messages.calls[2]
        assert "tool_choice" not in client.messages.calls[2]


def await_asyncio(coro):
    """Helper to run async in sync tests"""
    import asyncio
    return asyncio.run(coro)
