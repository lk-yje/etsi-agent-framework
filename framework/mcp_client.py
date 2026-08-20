"""MCP 客户端管理器 — 管理 Burp MCP 和 Playwright MCP 服务器连接。

使用 Python MCP SDK (mcp>=2.0.0) 通过标准协议连接 MCP 服务器:
- BurpMCP-Ultra: SSE 连接 (http://127.0.0.1:9876/, Bearer Token)
- Playwright MCP: stdio 子进程 (npx @playwright/mcp@latest)

优雅降级: 连接失败返回 False，不抛异常。管线仅用标准工具继续运行。

用法:
    async with MCPClientManager() as manager:
        await manager.connect_burp(token="...")
        await manager.connect_playwright()
        tools = await manager.list_all_tools()
        result = await manager.call_tool("http_send_request", {"url": "...", "method": "GET"})
"""

import json
import logging
import os
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class MCPToolInfo:
    """MCP 工具元数据（从 MCP 服务器 tools/list 发现）。"""
    name: str           # MCP 原生名称 (e.g., "http_send_request")
    description: str    # 来自 MCP 服务器的描述
    input_schema: dict  # JSON Schema (来自 MCP 服务器)
    server_name: str    # "burp" | "playwright"


class MCPClientManager:
    """管理 MCP 服务器连接（管线生命周期内长连接）。

    支持两种传输:
    - SSE (Server-Sent Events): BurpMCP-Ultra 在端口 9876
    - stdio: Playwright MCP 作为子进程

    连接失败时优雅降级 — connect_*() 返回 False，call_tool() 对
    未连接服务器抛 ValueError。
    """

    # BurpMCP-Ultra 默认配置
    DEFAULT_BURP_HOST = "127.0.0.1"
    DEFAULT_BURP_PORT = 9876

    # Playwright MCP 默认配置
    DEFAULT_PLAYWRIGHT_CMD = "npx"
    DEFAULT_PLAYWRIGHT_ARGS = ["@playwright/mcp@latest"]
    # 默认开启 opt-in caps: network/storage/testing 解锁 ETSI 测试所需工具
    # (browser_network_requests, browser_storage_*, browser_test_*, 等)
    DEFAULT_PLAYWRIGHT_CAPS = ("core", "network", "storage", "testing")

    def __init__(self):
        self._exit_stack: Optional[AsyncExitStack] = None
        self._burp_session: Optional[Any] = None  # ClientSession
        self._playwright_session: Optional[Any] = None  # ClientSession
        self._tool_cache: Dict[str, MCPToolInfo] = {}
        self._connected: Dict[str, bool] = {"burp": False, "playwright": False}

    async def __aenter__(self):
        self._exit_stack = AsyncExitStack()
        await self._exit_stack.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._exit_stack:
            await self._exit_stack.__aexit__(exc_type, exc_val, exc_tb)
            self._exit_stack = None
        self._burp_session = None
        self._playwright_session = None
        self._tool_cache.clear()
        self._connected = {"burp": False, "playwright": False}

    # ---------------------------------------------------------------
    # BurpMCP-Ultra (SSE)
    # ---------------------------------------------------------------

    async def connect_burp(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        token: Optional[str] = None,
    ) -> bool:
        """连接 BurpMCP-Ultra 通过 SSE。

        Args:
            host: 默认 env BURP_MCP_HOST 或 127.0.0.1
            port: 默认 env BURP_MCP_PORT 或 9876
            token: 默认 env BURP_MCP_TOKEN

        Returns:
            True 连接成功, False 连接失败（优雅降级）
        """
        host = host or os.environ.get("BURP_MCP_HOST", self.DEFAULT_BURP_HOST)
        port = port or int(os.environ.get("BURP_MCP_PORT", str(self.DEFAULT_BURP_PORT)))
        token = token or os.environ.get("BURP_MCP_TOKEN", "")

        url = f"http://{host}:{port}/"  # 根路径，不是 /sse

        if not token:
            logger.warning(
                "Burp MCP token not set (BURP_MCP_TOKEN). "
                "Set it to the token shown in Burp Suite's MCP tab."
            )
            return False

        try:
            from mcp.client.sse import sse_client
            from mcp import ClientSession

            headers = {"Authorization": f"Bearer {token}"}

            # sse_client 返回 (read_stream, write_stream)
            ctx = sse_client(url=url, headers=headers)
            read_stream, write_stream = await self._exit_stack.enter_async_context(ctx)

            # 创建 ClientSession
            session_ctx = ClientSession(read_stream, write_stream)
            self._burp_session = await self._exit_stack.enter_async_context(session_ctx)

            # 初始化 MCP 会话
            await self._burp_session.initialize()

            # 预缓存工具列表
            tools_result = await self._burp_session.list_tools()
            for tool in tools_result.tools:
                self._tool_cache[tool.name] = MCPToolInfo(
                    name=tool.name,
                    description=getattr(tool, 'description', ''),
                    input_schema=getattr(tool, 'inputSchema', {}),
                    server_name="burp",
                )

            self._connected["burp"] = True
            logger.info(
                "Burp MCP connected: %d tools from %s",
                len(tools_result.tools), url,
            )
            return True

        except Exception as e:
            logger.warning("Burp MCP connection failed: %s", e)
            self._burp_session = None
            self._connected["burp"] = False
            return False

    # ---------------------------------------------------------------
    # Playwright MCP (stdio)
    # ---------------------------------------------------------------

    async def connect_playwright(
        self,
        headless: bool = True,
        browser: str = "chrome",
        caps: Optional[List[str]] = None,
    ) -> bool:
        """连接 Playwright MCP 通过 stdio 子进程。

        Args:
            headless: 无头模式 (默认 True)
            browser: 浏览器名称 (默认 "chrome")
            caps: capabilities 列表 (默认开启 core,network,storage,testing)。
                  传 [] 禁用所有 opt-in caps，传 None 使用默认值。

        Returns:
            True 连接成功, False 连接失败（优雅降级）
        """
        if caps is None:
            caps = list(self.DEFAULT_PLAYWRIGHT_CAPS)
        args = list(self.DEFAULT_PLAYWRIGHT_ARGS)
        if headless:
            args.append("--headless")
        if browser:
            args.extend(["--browser", browser])
        if caps:
            args.extend(["--caps", ",".join(caps)])

        try:
            from mcp.client.stdio import stdio_client
            from mcp import ClientSession

            server_params = {
                "command": self.DEFAULT_PLAYWRIGHT_CMD,
                "args": args,
            }

            # stdio_client 返回 (read_stream, write_stream)
            ctx = stdio_client(server_params)
            read_stream, write_stream = await self._exit_stack.enter_async_context(ctx)

            # 创建 ClientSession
            session_ctx = ClientSession(read_stream, write_stream)
            self._playwright_session = await self._exit_stack.enter_async_context(session_ctx)

            # 初始化 MCP 会话
            await self._playwright_session.initialize()

            # 预缓存工具列表
            tools_result = await self._playwright_session.list_tools()
            for tool in tools_result.tools:
                self._tool_cache[tool.name] = MCPToolInfo(
                    name=tool.name,
                    description=getattr(tool, 'description', ''),
                    input_schema=getattr(tool, 'inputSchema', {}),
                    server_name="playwright",
                )

            self._connected["playwright"] = True
            logger.info(
                "Playwright MCP connected: %d tools",
                len(tools_result.tools),
            )
            return True

        except Exception as e:
            logger.warning("Playwright MCP connection failed: %s", e)
            self._playwright_session = None
            self._connected["playwright"] = False
            return False

    # ---------------------------------------------------------------
    # Tool execution
    # ---------------------------------------------------------------

    async def call_tool(self, tool_name: str, arguments: dict) -> str:
        """在正确的 MCP 服务器上执行工具。

        通过 _tool_cache 查找 tool_name 所属服务器，路由到对应 session。

        Args:
            tool_name: MCP 原生工具名 (e.g., "http_send_request")
            arguments: 工具参数

        Returns:
            工具返回的文本内容

        Raises:
            ValueError: 工具未找到或服务器未连接
        """
        tool_info = self._tool_cache.get(tool_name)
        if tool_info is None:
            raise ValueError(
                f"Unknown tool '{tool_name}'. "
                f"Available: {list(self._tool_cache.keys())[:10]}..."
            )

        session = self._get_session(tool_info.server_name)
        if session is None:
            raise ValueError(
                f"MCP server '{tool_info.server_name}' is not connected. "
                f"Call connect_{tool_info.server_name}() first."
            )

        result = await session.call_tool(tool_name, arguments)

        # 提取文本内容 — result.content 是 ContentBlock 列表
        text_parts = []
        for block in result.content:
            if hasattr(block, 'text'):
                text_parts.append(block.text)
            else:
                text_parts.append(str(block))

        return "\n".join(text_parts)

    def _get_session(self, server_name: str):
        """获取指定服务器的 session。"""
        if server_name == "burp":
            return self._burp_session
        elif server_name == "playwright":
            return self._playwright_session
        return None

    # ---------------------------------------------------------------
    # Tool discovery
    # ---------------------------------------------------------------

    async def list_all_tools(self) -> List[MCPToolInfo]:
        """返回所有已连接服务器的工具列表。"""
        return list(self._tool_cache.values())

    def get_tool(self, name: str) -> Optional[MCPToolInfo]:
        """获取单个工具信息。"""
        return self._tool_cache.get(name)

    # ---------------------------------------------------------------
    # Status
    # ---------------------------------------------------------------

    @property
    def burp_connected(self) -> bool:
        return self._connected["burp"]

    @property
    def playwright_connected(self) -> bool:
        return self._connected["playwright"]

    def status(self) -> dict:
        """返回连接状态和工具计数。"""
        burp_tools = sum(1 for t in self._tool_cache.values() if t.server_name == "burp")
        pw_tools = sum(1 for t in self._tool_cache.values() if t.server_name == "playwright")
        return {
            "burp": {
                "connected": self._connected["burp"],
                "tool_count": burp_tools,
            },
            "playwright": {
                "connected": self._connected["playwright"],
                "tool_count": pw_tools,
            },
            "total_tools": len(self._tool_cache),
        }
