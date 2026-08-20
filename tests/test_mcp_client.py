"""MCP 客户端测试 — MCPClientManager + MCPToolAdapter mock 测试。

不连接真实 MCP 服务器。通过 mock 验证:
- MCPClientManager 连接/断开生命周期
- 工具发现和缓存
- call_tool 路由到正确服务器
- 优雅降级（连接失败返回 False）
- MCPToolAdapter 转换 + 注册
"""

import asyncio
import pytest
from dataclasses import dataclass
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

from framework.mcp_client import MCPClientManager, MCPToolInfo
from framework.tools import MCPToolAdapter, ToolRegistry, STANDARD_TOOLS, BuiltinExecutors


# ============================================================
# Mock MCP SDK objects
# ============================================================


@dataclass
class MockMCPTool:
    """模拟 MCP SDK 返回的 Tool 对象"""
    name: str
    description: str = ""
    inputSchema: dict = None  # noqa: N815

    def __post_init__(self):
        if self.inputSchema is None:
            self.inputSchema = {"type": "object", "properties": {}, "required": []}


@dataclass
class MockToolsResult:
    """模拟 list_tools() 返回值"""
    tools: List[MockMCPTool]


@dataclass
class MockContentBlock:
    """模拟 MCP call_tool 返回的 ContentBlock"""
    text: str = ""


@dataclass
class MockCallResult:
    """模拟 call_tool() 返回值"""
    content: List[MockContentBlock]


# ============================================================
# MCPClientManager 测试
# ============================================================


class TestMCPClientManager:
    """MCPClientManager 生命周期和工具路由"""

    @pytest.fixture
    def manager(self):
        return MCPClientManager()

    def test_initial_state(self, manager):
        """初始状态: 全部未连接"""
        assert not manager.burp_connected
        assert not manager.playwright_connected
        status = manager.status()
        assert status["burp"]["connected"] is False
        assert status["playwright"]["connected"] is False
        assert status["total_tools"] == 0

    @pytest.mark.asyncio
    async def test_connect_burp_no_token_returns_false(self, manager):
        """无 token 时 connect_burp 返回 False（优雅降级）"""
        async with manager:
            result = await manager.connect_burp(token="")
            assert result is False
            assert not manager.burp_connected

    @pytest.mark.asyncio
    async def test_connect_burp_success(self, manager):
        """模拟 Burp MCP 连接成功"""
        async with manager:
            mock_tools = [
                MockMCPTool(name="http_send_request", description="Send HTTP request",
                            inputSchema={
                                "type": "object",
                                "properties": {
                                    "url": {"type": "string", "description": "Target URL"},
                                    "method": {"type": "string", "description": "HTTP method"},
                                },
                                "required": ["url"],
                            }),
                MockMCPTool(name="sitemap_get", description="Get sitemap"),
            ]

            # Patch the mcp module imports (they're imported inside the function)
            with patch("mcp.client.sse.sse_client") as mock_sse, \
                 patch("mcp.ClientSession") as mock_session_cls:
                # Setup mock streams
                mock_read = AsyncMock()
                mock_write = AsyncMock()
                mock_sse.return_value.__aenter__ = AsyncMock(return_value=(mock_read, mock_write))
                mock_sse.return_value.__aexit__ = AsyncMock(return_value=False)

                # Setup mock session
                mock_session = AsyncMock()
                mock_session.initialize = AsyncMock()
                mock_session.list_tools = AsyncMock(return_value=MockToolsResult(tools=mock_tools))
                mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

                result = await manager.connect_burp(token="test-token")
                assert result is True
                assert manager.burp_connected

                # 工具应被缓存
                tools = await manager.list_all_tools()
                assert len(tools) == 2
                assert tools[0].name == "http_send_request"
                assert tools[0].server_name == "burp"

    @pytest.mark.asyncio
    async def test_connect_burp_failure_returns_false(self, manager):
        """连接失败时返回 False（优雅降级）"""
        async with manager:
            with patch("mcp.client.sse.sse_client", side_effect=ConnectionError("refused")):
                result = await manager.connect_burp(token="test-token")
                assert result is False
                assert not manager.burp_connected

    @pytest.mark.asyncio
    async def test_call_tool_routes_to_correct_server(self, manager):
        """call_tool 路由到正确的 MCP 服务器"""
        async with manager:
            # 手动设置缓存和 session
            manager._tool_cache["http_send_request"] = MCPToolInfo(
                name="http_send_request", description="test",
                input_schema={}, server_name="burp",
            )
            manager._tool_cache["browser_navigate"] = MCPToolInfo(
                name="browser_navigate", description="test",
                input_schema={}, server_name="playwright",
            )

            mock_burp = AsyncMock()
            mock_burp.call_tool = AsyncMock(return_value=MockCallResult(
                content=[MockContentBlock(text="burp response")]
            ))
            mock_pw = AsyncMock()
            mock_pw.call_tool = AsyncMock(return_value=MockCallResult(
                content=[MockContentBlock(text="playwright response")]
            ))

            manager._burp_session = mock_burp
            manager._playwright_session = mock_pw
            manager._connected = {"burp": True, "playwright": True}

            # Burp 工具
            result = await manager.call_tool("http_send_request", {"url": "http://test"})
            assert result == "burp response"
            mock_burp.call_tool.assert_called_once_with("http_send_request", {"url": "http://test"})

            # Playwright 工具
            result = await manager.call_tool("browser_navigate", {"url": "http://test"})
            assert result == "playwright response"
            mock_pw.call_tool.assert_called_once_with("browser_navigate", {"url": "http://test"})

    @pytest.mark.asyncio
    async def test_call_tool_unknown_raises(self, manager):
        """调用未知工具抛 ValueError"""
        async with manager:
            with pytest.raises(ValueError, match="Unknown tool"):
                await manager.call_tool("nonexistent_tool", {})

    @pytest.mark.asyncio
    async def test_call_tool_disconnected_raises(self, manager):
        """服务器未连接时调用工具抛 ValueError"""
        async with manager:
            manager._tool_cache["test_tool"] = MCPToolInfo(
                name="test_tool", description="test",
                input_schema={}, server_name="burp",
            )
            # burp session is None
            with pytest.raises(ValueError, match="not connected"):
                await manager.call_tool("test_tool", {})

    @pytest.mark.asyncio
    async def test_status(self, manager):
        """status() 返回正确的连接状态和工具计数"""
        async with manager:
            manager._tool_cache["tool_a"] = MCPToolInfo(
                name="tool_a", description="", input_schema={}, server_name="burp")
            manager._tool_cache["tool_b"] = MCPToolInfo(
                name="tool_b", description="", input_schema={}, server_name="burp")
            manager._tool_cache["tool_c"] = MCPToolInfo(
                name="tool_c", description="", input_schema={}, server_name="playwright")
            manager._connected = {"burp": True, "playwright": True}

            status = manager.status()
            assert status["burp"]["connected"] is True
            assert status["burp"]["tool_count"] == 2
            assert status["playwright"]["connected"] is True
            assert status["playwright"]["tool_count"] == 1
            assert status["total_tools"] == 3

    @pytest.mark.asyncio
    async def test_context_manager_cleanup(self, manager):
        """退出 async context 时清理状态"""
        async with manager:
            manager._connected = {"burp": True, "playwright": True}
            manager._tool_cache["test"] = MCPToolInfo(
                name="test", description="", input_schema={}, server_name="burp")

        # 退出后应重置
        assert not manager.burp_connected
        assert not manager.playwright_connected
        assert len(manager._tool_cache) == 0

    def test_default_playwright_caps(self, manager):
        """默认 Playwright caps 包含 core,network,storage,testing"""
        caps = manager.DEFAULT_PLAYWRIGHT_CAPS
        assert "core" in caps
        assert "network" in caps
        assert "storage" in caps
        assert "testing" in caps

    @pytest.mark.asyncio
    async def test_connect_playwright_default_caps(self, manager):
        """connect_playwright() 默认使用 opt-in caps"""
        async with manager:
            mock_tools = [MockMCPTool(name="browser_navigate")]
            with patch("mcp.client.stdio.stdio_client") as mock_stdio, \
                 patch("mcp.ClientSession") as mock_session_cls:
                mock_read = AsyncMock()
                mock_write = AsyncMock()
                mock_stdio.return_value.__aenter__ = AsyncMock(
                    return_value=(mock_read, mock_write))
                mock_stdio.return_value.__aexit__ = AsyncMock(return_value=False)

                mock_session = AsyncMock()
                mock_session.initialize = AsyncMock()
                mock_session.list_tools = AsyncMock(
                    return_value=MockToolsResult(tools=mock_tools))
                mock_session_cls.return_value.__aenter__ = AsyncMock(
                    return_value=mock_session)
                mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

                await manager.connect_playwright()

                # 验证 stdio_client 被调用时包含 --caps 参数
                call_args = mock_stdio.call_args[0][0]
                args_list = call_args["args"]
                assert "--caps" in args_list
                caps_idx = args_list.index("--caps")
                caps_value = args_list[caps_idx + 1]
                assert "network" in caps_value
                assert "storage" in caps_value
                assert "testing" in caps_value


# ============================================================
# MCPToolAdapter 测试
# ============================================================


class TestMCPToolAdapter:
    """MCPToolAdapter — MCP 工具到 ToolRegistry 的适配"""

    @pytest.mark.asyncio
    async def test_register_all(self):
        """从 MCP 服务器发现并注册所有工具"""
        mock_manager = AsyncMock()
        mock_manager.list_all_tools = AsyncMock(return_value=[
            MCPToolInfo(
                name="http_send_request",
                description="Send HTTP request",
                input_schema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "method": {"type": "string", "description": "HTTP method"},
                    },
                    "required": ["url"],
                },
                server_name="burp",
            ),
            MCPToolInfo(
                name="browser_navigate",
                description="Navigate to URL",
                input_schema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL to navigate to"},
                    },
                    "required": ["url"],
                },
                server_name="playwright",
            ),
        ])
        mock_manager.call_tool = AsyncMock(return_value="tool result")

        adapter = MCPToolAdapter(mock_manager)
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())

        count = await adapter.register_all(registry)
        assert count == 2
        assert "http_send_request" in registry.tool_names
        assert "browser_navigate" in registry.tool_names

        # 验证 ToolDef 转换
        tool_def = registry.get_def("http_send_request")
        assert tool_def is not None
        assert tool_def.description == "Send HTTP request"
        param_names = [p.name for p in tool_def.parameters]
        assert "url" in param_names
        assert "method" in param_names

    @pytest.mark.asyncio
    async def test_mcp_to_tooldef_conversion(self):
        """MCPToolInfo → ToolDef 转换"""
        tool_info = MCPToolInfo(
            name="test_tool",
            description="A test tool",
            input_schema={
                "type": "object",
                "properties": {
                    "required_param": {"type": "string", "description": "Required"},
                    "optional_param": {"type": "integer", "description": "Optional"},
                    "enum_param": {"type": "string", "description": "Enum", "enum": ["a", "b"]},
                },
                "required": ["required_param"],
            },
            server_name="burp",
        )

        tool_def = MCPToolAdapter._mcp_to_tooldef(tool_info)
        assert tool_def.name == "test_tool"
        assert tool_def.description == "A test tool"

        params = {p.name: p for p in tool_def.parameters}
        assert params["required_param"].required is True
        assert params["optional_param"].required is False
        assert params["enum_param"].enum == ["a", "b"]

    @pytest.mark.asyncio
    async def test_executor_routes_to_mcp(self):
        """注册的工具执行器路由到 MCPClientManager.call_tool()"""
        mock_manager = AsyncMock()
        mock_manager.list_all_tools = AsyncMock(return_value=[
            MCPToolInfo(
                name="scan_port",
                description="Scan port",
                input_schema={"type": "object", "properties": {"port": {"type": "integer"}}, "required": ["port"]},
                server_name="burp",
            ),
        ])
        mock_manager.call_tool = AsyncMock(return_value="port 80 open")

        adapter = MCPToolAdapter(mock_manager)
        registry = ToolRegistry()
        await adapter.register_all(registry)

        # 通过 ToolRegistry.execute() 调用
        result = await registry.execute("scan_port", {"port": 80})
        assert not result.is_error
        assert result.content == "port 80 open"
        mock_manager.call_tool.assert_called_once_with("scan_port", {"port": 80})

    @pytest.mark.asyncio
    async def test_empty_mcp_tools(self):
        """MCP 服务器无工具时返回 0"""
        mock_manager = AsyncMock()
        mock_manager.list_all_tools = AsyncMock(return_value=[])

        adapter = MCPToolAdapter(mock_manager)
        registry = ToolRegistry()
        count = await adapter.register_all(registry)
        assert count == 0

    @pytest.mark.asyncio
    async def test_register_categorizes_by_server(self):
        """MCPToolAdapter 按 server_name 自动分类工具"""
        from framework.tools import CATEGORY_BURP_MCP, CATEGORY_PLAYWRIGHT
        mock_manager = AsyncMock()
        mock_manager.list_all_tools = AsyncMock(return_value=[
            MCPToolInfo(name="http_send_request", description="", input_schema={},
                        server_name="burp"),
            MCPToolInfo(name="proxy_history_search", description="", input_schema={},
                        server_name="burp"),
            MCPToolInfo(name="browser_navigate", description="", input_schema={},
                        server_name="playwright"),
        ])
        mock_manager.call_tool = AsyncMock(return_value="ok")

        adapter = MCPToolAdapter(mock_manager)
        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())
        count = await adapter.register_all(registry)
        assert count == 3

        # Burp 工具应归入 burp_mcp 分类
        burp_tools = registry.resolve_categories((CATEGORY_BURP_MCP,))
        assert "http_send_request" in burp_tools
        assert "proxy_history_search" in burp_tools
        assert "browser_navigate" not in burp_tools

        # Playwright 工具应归入 playwright_mcp 分类
        pw_tools = registry.resolve_categories((CATEGORY_PLAYWRIGHT,))
        assert "browser_navigate" in pw_tools
        assert "http_send_request" not in pw_tools

    @pytest.mark.asyncio
    async def test_register_mcp_tools_via_registry(self):
        """通过 ToolRegistry.register_mcp_tools() 注册"""
        mock_manager = AsyncMock()
        mock_manager.list_all_tools = AsyncMock(return_value=[
            MCPToolInfo(
                name="test_mcp_tool",
                description="test",
                input_schema={"type": "object", "properties": {}, "required": []},
                server_name="burp",
            ),
        ])
        mock_manager.call_tool = AsyncMock(return_value="ok")

        registry = ToolRegistry()
        registry.register(STANDARD_TOOLS, BuiltinExecutors())
        count = await registry.register_mcp_tools(mock_manager)
        assert count == 1
        assert "test_mcp_tool" in registry.tool_names
        # 标准工具也在
        assert "bash" in registry.tool_names
