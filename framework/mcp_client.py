"""MCP 客户端管理器 — 管理 Burp MCP 和 Playwright MCP 服务器连接。

使用 Python MCP SDK (mcp>=2.0.0) 通过标准协议连接 MCP 服务器:
- BurpMCP-Ultra: SSE 连接 (http://127.0.0.1:9876/, Bearer Token)
- Playwright MCP: stdio 子进程 (npx @playwright/mcp@latest)

优雅降级: 连接失败返回 False，不抛异常。管线仅用标准工具继续运行。

用法:
    async with MCPClientManager() as manager:
        await manager.connect_burp()
        await manager.connect_playwright()
        tools = await manager.list_all_tools()
        result = await manager.call_tool("http_send_request", {"url": "...", "method": "GET"})
"""

import json
import logging
import os
import shutil
import asyncio
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class PlaywrightMCPUnavailable(RuntimeError):
    """Raised when the required local Playwright MCP transport is not ready."""


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
    # SSE 在 Burp 扩展重载或本机网络短暂切换后可能连续断开一次；为只读
    # 调用保留两次独立重连机会，超过该次数才由上层进入可见的故障处理。
    MAX_BURP_RECONNECT_ATTEMPTS = 2

    # Playwright MCP is a pinned project runtime.  Never use npx/latest or a
    # cache fallback on the stdio transport: Windows .cmd wrappers can emit
    # AutoRun text before JSON-RPC is initialized.
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    PLAYWRIGHT_RUNTIME = PROJECT_ROOT / "tools" / "playwright-mcp"

    def __init__(self, workspace: Path | None = None):
        self.workspace = Path(workspace).resolve() if workspace else None
        self._exit_stack: Optional[AsyncExitStack] = None
        self._burp_session: Optional[Any] = None  # ClientSession
        self._playwright_session: Optional[Any] = None  # ClientSession
        self._tool_cache: Dict[str, MCPToolInfo] = {}
        self._connected: Dict[str, bool] = {"burp": False, "playwright": False}
        self._playwright_error: Optional[str] = None
        self._burp_host: Optional[str] = None
        self._burp_port: Optional[int] = None
        self._burp_reconnect_lock = asyncio.Lock()

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
    ) -> bool:
        """连接 BurpMCP-Ultra 通过 SSE。

        Args:
            host: 默认 env BURP_MCP_HOST 或 127.0.0.1
            port: 默认 env BURP_MCP_PORT 或 9876

        Returns:
            True 连接成功, False 连接失败（优雅降级）
        """
        host = host or os.environ.get("BURP_MCP_HOST", self.DEFAULT_BURP_HOST)
        port = port or int(os.environ.get("BURP_MCP_PORT", str(self.DEFAULT_BURP_PORT)))
        self._burp_host, self._burp_port = host, port
        # 当前 BurpMCP-Ultra 服务以 legacy SSE 握手工作：GET / 返回 endpoint
        # 事件并给出回传 URL。以实际运行服务为准，不假设源码注释中的 /sse 路由。
        url = f"http://{host}:{port}/"

        try:
            from mcp.client.sse import sse_client
            from mcp import ClientSession

            # sse_client 返回 (read_stream, write_stream)
            ctx = sse_client(url=url)
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
            self._record_burp_diagnostic("connect_ok", tool_count=len(tools_result.tools), endpoint=url)
            logger.info(
                "Burp MCP connected: %d tools from %s",
                len(tools_result.tools), url,
            )
            return True

        except Exception as e:
            logger.warning("Burp MCP connection failed: %s", e)
            self._burp_session = None
            self._connected["burp"] = False
            self._record_burp_diagnostic("connect_failed", error=e, endpoint=url)
            return False

    # ---------------------------------------------------------------
    # Playwright MCP (stdio)
    # ---------------------------------------------------------------

    async def connect_playwright(
        self,
        headless: bool = True,
        browser: str = "msedge",
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
        try:
            node, cli = self._resolve_playwright_runtime()
        except PlaywrightMCPUnavailable as exc:
            self._playwright_error = str(exc)
            logger.error("Playwright MCP blocked: %s", exc)
            return False

        args = [str(cli)]
        if headless:
            args.append("--headless")
        if browser:
            args.extend(["--browser", browser])
        if caps:
            args.extend(["--caps", ",".join(caps)])
        args.append("--isolated")
        if self.workspace:
            output_dir = self.workspace / "playwright"
            args.extend(["--output-dir", str(output_dir)])
            dut_host = self._workspace_dut_host()
            if dut_host:
                args.extend(["--allowed-hosts", dut_host])

        try:
            from mcp.client.stdio import stdio_client
            from mcp import ClientSession, StdioServerParameters

            server_params = StdioServerParameters(
                command=node,
                args=args,
                cwd=str(self.PLAYWRIGHT_RUNTIME),
            )

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
            self._playwright_error = None
            logger.info(
                "Playwright MCP connected: %d tools",
                len(tools_result.tools),
            )
            return True

        except Exception as e:
            self._playwright_error = f"Playwright MCP 握手失败: {e}"
            logger.warning("%s", self._playwright_error)
            self._playwright_session = None
            self._connected["playwright"] = False
            return False

    def _resolve_playwright_runtime(self) -> tuple[str, Path]:
        node = os.environ.get("PLAYWRIGHT_NODE_BINARY") or shutil.which("node")
        cli = Path(os.environ.get(
            "PLAYWRIGHT_MCP_CLI",
            self.PLAYWRIGHT_RUNTIME / "node_modules" / "@playwright" / "mcp" / "cli.js",
        )).resolve()
        if not node:
            raise PlaywrightMCPUnavailable("未找到 node 可执行文件")
        if not cli.is_file():
            raise PlaywrightMCPUnavailable(
                f"未安装固定的 Playwright MCP runtime: {cli}；请运行 npm ci"
            )
        return node, cli

    def _workspace_dut_host(self) -> str | None:
        if not self.workspace:
            return None
        try:
            config = json.loads((self.workspace / "run_config.json").read_text(encoding="utf-8"))
            value = config.get("dut_ip")
            return value.strip() if isinstance(value, str) and value.strip() else None
        except (OSError, ValueError, json.JSONDecodeError):
            return None

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

        try:
            result = await session.call_tool(tool_name, arguments)
        except Exception as exc:
            if tool_info.server_name != "burp" or not self._is_burp_transport_error(exc):
                raise
            self._connected["burp"] = False
            self._record_burp_diagnostic("transport_lost", tool=tool_name, error=exc)
            logger.warning("Burp MCP transport closed during %s; reconnecting up to %d times", tool_name, self.MAX_BURP_RECONNECT_ATTEMPTS)
            safe_to_replay = self._burp_tool_safe_to_retry(tool_name, arguments)
            last_error: BaseException = exc
            for reconnect_attempt in range(1, self.MAX_BURP_RECONNECT_ATTEMPTS + 1):
                self._record_burp_diagnostic(
                    "reconnect_attempt", tool=tool_name, attempt=reconnect_attempt,
                )
                if not await self._reconnect_burp_once():
                    continue
                if not safe_to_replay:
                    # 连接已恢复，但不重放可能已经在 Burp 端执行过的变更/请求。
                    # Agent 会收到原始异常并可在下一轮基于恢复后的连接继续。
                    self._record_burp_diagnostic("reconnect_ready_no_replay", tool=tool_name)
                    raise exc
                try:
                    # 对只读工具只重放当前调用；若仍是传输关闭，进入第二次重连。
                    result = await self._burp_session.call_tool(tool_name, arguments)
                    self._record_burp_diagnostic("retry_ok", tool=tool_name, attempt=reconnect_attempt)
                    break
                except Exception as retry_exc:
                    if not self._is_burp_transport_error(retry_exc):
                        raise
                    last_error = retry_exc
                    self._connected["burp"] = False
                    self._record_burp_diagnostic(
                        "retry_transport_lost", tool=tool_name,
                        attempt=reconnect_attempt, error=retry_exc,
                    )
            else:
                self._record_burp_diagnostic("reconnect_exhausted", tool=tool_name, error=last_error)
                raise last_error

        # 提取文本内容 — result.content 是 ContentBlock 列表
        text_parts = []
        for block in result.content:
            if hasattr(block, 'text'):
                text_parts.append(block.text)
            else:
                text_parts.append(str(block))

        return "\n".join(text_parts)

    @staticmethod
    def _is_burp_transport_error(exc: BaseException) -> bool:
        """只识别会话/传输断开；业务工具报错不得被误判为可重试。"""
        text = f"{type(exc).__name__}: {exc}".lower()
        signals = (
            "connection closed", "closedresource", "endofstream", "broken pipe",
            "connection reset", "server disconnected", "connecterror", "readerror",
        )
        return any(signal in text for signal in signals)

    @staticmethod
    def _burp_tool_safe_to_retry(tool_name: str, arguments: dict) -> bool:
        """判断重放是否无副作用；不能证明安全时一律不重放。"""
        normalized = tool_name.lower()
        if normalized.startswith(("get_", "list_", "find_", "search_")):
            return True
        if normalized in {"burp_version", "proxy_history", "sitemap_get", "site_map_get"}:
            return True
        if normalized == "http_send_request":
            return str(arguments.get("method", "GET")).upper() in {"GET", "HEAD", "OPTIONS"}
        return False

    async def _reconnect_burp_once(self) -> bool:
        """串行化重连，防止并发 Work Agent 同时新建多条 SSE 会话。"""
        async with self._burp_reconnect_lock:
            if self._connected["burp"] and self._burp_session is not None:
                return True
            for name, info in list(self._tool_cache.items()):
                if info.server_name == "burp":
                    del self._tool_cache[name]
            self._burp_session = None
            ok = await self.connect_burp(self._burp_host, self._burp_port)
            self._record_burp_diagnostic("reconnect_ok" if ok else "reconnect_failed")
            return ok

    def _record_burp_diagnostic(
        self,
        event: str,
        *,
        tool: str | None = None,
        error: BaseException | None = None,
        **details: Any,
    ) -> None:
        """记录不含请求参数/凭据的 MCP 生命周期证据，供下一次定位中断。"""
        payload = {"event": event, "tool": tool, **details}
        if error is not None:
            payload["error_type"] = type(error).__name__
            payload["error"] = str(error)[:500]
        logger.info("Burp MCP diagnostic: %s", payload)
        if not self.workspace:
            return
        try:
            from datetime import datetime, timezone
            payload["at"] = datetime.now(timezone.utc).isoformat()
            path = self.workspace / "mcp_diagnostics.jsonl"
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except OSError as write_error:
            logger.warning("Cannot write Burp MCP diagnostics: %s", write_error)

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

    @property
    def playwright_error(self) -> str | None:
        return self._playwright_error

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
