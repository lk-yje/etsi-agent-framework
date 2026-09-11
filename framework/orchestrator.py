"""Agent 编排器 — 管线 + AgentRunner + FileBus + ToolRegistry 的协调层。

薄层：从 Registry 动态解析管线类，组装组件，启动管线。
完全不依赖具体管线实现 — 通过 PipelineDef.pipeline_class 动态导入。

MCP 集成 (v0.3):
- 接收 MCPClientManager 实例（已连接或 None）
- 在管线启动前通过 MCPToolAdapter 动态注册 MCP 工具
- 连接失败时优雅降级：管线仅用标准工具继续运行
"""

import asyncio
import importlib
import logging
from pathlib import Path
from typing import Any, Optional

from contracts.pipeline import PipelineSnapshot
from framework.agent_runner import AgentRunner
from framework.file_bus import FileBus
from framework.telemetry import Telemetry
from framework.registry import AgentRegistry
from framework.tools import ToolRegistry, STANDARD_TOOLS, BuiltinExecutors
from framework.retry import RetryPolicy, RetryConfig
from framework.path_resolver import PathResolver
from framework.ixit_tools import build_ixit_readonly_registry

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """编排器 — 组装全部组件，启动管线。

    完全通用：不包含任何 ETSI 或业务逻辑。
    管线类通过 PipelineDef.pipeline_class 动态解析。

    用法:
        async with MCPClientManager() as mcp:
            await mcp.connect_burp(token="...")
            orchestrator = AgentOrchestrator(workspace, registry, api_client,
                                              mcp_manager=mcp)
            result = await orchestrator.run_pipeline("etsi-ts103701")
    """

    def __init__(
        self,
        workspace: Path,
        registry: AgentRegistry,
        api_client: Any,
        retry_config: RetryConfig | None = None,
        path_resolver: PathResolver | None = None,
        non_interactive: bool = False,
        mcp_manager: Optional[Any] = None,
        control_mode: str = "terminal",
    ):
        self.workspace = Path(workspace)
        self.registry = registry
        self.bus = FileBus(workspace)
        self.telemetry = Telemetry(workspace / "logs")
        self.path_resolver = path_resolver or PathResolver()
        self.non_interactive = non_interactive
        self.control_mode = control_mode
        self.mcp_manager = mcp_manager

        # 带重试策略的 AgentRunner
        retry = RetryPolicy(retry_config or RetryConfig())
        self.runner = AgentRunner(api_client, self.telemetry, retry_policy=retry)

        # 初始化 Tool 注册表 — 标准内置工具
        self.tool_registry = ToolRegistry()
        self.tool_registry.register(STANDARD_TOOLS, BuiltinExecutors())
        # 概念性 phase 只需要读取当前 workspace 的 ICS/IXIT；不复用
        # bash/write_file/python_script 这个过宽的标准工具类别。
        build_ixit_readonly_registry(self.tool_registry, self.workspace)
        # MCP 工具在 run_pipeline() 中异步注册（需要 MCP 服务器已连接）

    async def _connect_mcp_tools(self) -> int:
        """在管线启动前连接 MCP 服务器并动态注册工具。

        优雅降级：连接失败返回 0，管线仅用标准工具继续运行。

        Returns:
            注册的 MCP 工具数量
        """
        if self.mcp_manager is None:
            logger.info("No MCP manager provided — using standard tools only")
            return 0

        try:
            count = await self.tool_registry.register_mcp_tools(self.mcp_manager)
            logger.info("Registered %d MCP tools", count)
            return count
        except Exception as e:
            logger.warning("MCP tool registration failed: %s — continuing with standard tools", e)
            return 0

    async def run_pipeline(self, pipeline_name: str, run_plan=None) -> PipelineSnapshot:
        """运行指定管线到完成。

        动态解析管线类 → 注册 MCP 工具 → 实例化 → 驱动到完成。
        """
        pipe_def = self.registry.get_pipeline(pipeline_name)
        if pipe_def is None:
            available = self.registry.list_pipelines()
            raise ValueError(
                f"管线 '{pipeline_name}' 未注册。可用管线: {available}"
            )

        # 在管线启动前注册 MCP 工具（优雅降级）
        mcp_tool_count = await self._connect_mcp_tools()

        # 动态导入管线类
        pipeline_cls = self._resolve_pipeline_class(pipe_def.pipeline_class)

        pipeline = pipeline_cls(
            workspace=self.workspace,
            registry=self.registry,
            runner=self.runner,
            bus=self.bus,
            telemetry=self.telemetry,
            pipe_def=pipe_def,
            tool_registry=self.tool_registry,
            path_resolver=self.path_resolver,
            non_interactive=self.non_interactive,
            mcp_manager=self.mcp_manager,
            control_mode=self.control_mode,
            run_plan=run_plan,
        )

        pipeline_id = pipeline._state.pipeline_id if pipeline._state else "?"
        self.telemetry.log_pipeline_start(pipeline_id, pipeline_name)

        start = asyncio.get_event_loop().time()
        result = await pipeline.run()
        duration = asyncio.get_event_loop().time() - start

        self.telemetry.log_pipeline_complete(
            result.pipeline_id,
            total_agents=0,
            total_duration_s=duration,
        )

        return result

    @staticmethod
    def _resolve_pipeline_class(class_path: str):
        """从完全限定路径动态导入管线类。

        Args:
            class_path: 如 "pipelines.etsi.pipeline.ETSIPipeline"

        Returns:
            Pipeline 子类

        Raises:
            ImportError: 如果类无法加载
        """
        if not class_path:
            raise ImportError(
                "PipelineDef.pipeline_class 为空，无法解析管线类。"
                "请在 PipelineDef 中设置 pipeline_class 字段。"
            )

        parts = class_path.rsplit(".", 1)
        if len(parts) != 2:
            raise ImportError(f"无效的 pipeline_class: {class_path}")

        module_path, class_name = parts
        try:
            module = importlib.import_module(module_path)
        except ImportError as e:
            raise ImportError(
                f"无法导入管线模块 '{module_path}': {e}"
            ) from e

        pipeline_cls = getattr(module, class_name, None)
        if pipeline_cls is None:
            raise ImportError(
                f"模块 '{module_path}' 中找不到类 '{class_name}'"
            )

        return pipeline_cls
