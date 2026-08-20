"""Framework — ETSI Agent Framework 基础设施。

组件:
  AgentRunner   — 独立 API 调用 + 多轮 tool-use 循环
  FileBus       — Agent 间文件通信 (原子读写/令牌/轮询)
  Pipeline      — 状态机引擎 (Stage + StageTransition)
  GateChecker   — L1 确定性校验 + L2 AI 审计 + Phase 闸门
  ToolRegistry  — 工具定义 + MCP 动态发现
  MCPClientManager — MCP 服务器连接管理 (SSE + stdio)
  AgentRegistry — 管线注册 + 隔离验证
  Workspace     — 工作区管理
  PathResolver  — 工具路径映射
  Telemetry     — 结构化日志/token 统计
  Retry         — 指数退避 + 熔断
"""

from framework.agent_runner import (
    AgentConfig,
    AgentRunner,
    PromptCompiler,
    IsolationViolation,
)
from framework.file_bus import FileBus
from framework.pipeline import Pipeline, Stage, StageTransition
from framework.gate_checker import (
    GateChecker,
    GateResult,
    L1StructuralGate,
    L2AuditGate,
    PhaseGate,
)
from framework.registry import AgentRegistry, RegistryViolation
from framework.retry import RetryPolicy, RetryConfig, RetryExhausted, CircuitBreakerOpen
from framework.tools import (
    ToolDef,
    ToolParam,
    ToolResult,
    ToolRegistry,
    BuiltinExecutors,
    STANDARD_TOOLS,
    MCPToolAdapter,
    CATEGORY_STANDARD,
    CATEGORY_BURP_MCP,
    CATEGORY_PLAYWRIGHT,
)
from framework.mcp_client import MCPClientManager, MCPToolInfo

try:
    from framework.context_pool import ContextPool, Scope, ProviderSpec
    _HAS_CONTEXT_POOL = True
except ImportError:
    ContextPool = None  # type: ignore
    Scope = None  # type: ignore
    ProviderSpec = None  # type: ignore
    _HAS_CONTEXT_POOL = False

try:
    from framework.phase_engine import PhaseExecutionEngine, PhaseDefinitionLoader, PhaseDef
    _HAS_PHASE_ENGINE = True
except ImportError:
    PhaseExecutionEngine = None  # type: ignore
    PhaseDefinitionLoader = None  # type: ignore
    PhaseDef = None  # type: ignore
    _HAS_PHASE_ENGINE = False

try:
    from framework.orchestrator import AgentOrchestrator
    _HAS_ORCHESTRATOR = True
except ImportError:
    AgentOrchestrator = None  # type: ignore
    _HAS_ORCHESTRATOR = False

try:
    from framework.telemetry import Telemetry
    _HAS_TELEMETRY = True
except ImportError:
    Telemetry = None  # type: ignore
    _HAS_TELEMETRY = False

__all__ = [
    # agent runner
    "AgentConfig",
    "AgentRunner",
    "PromptCompiler",
    "IsolationViolation",
    # file bus
    "FileBus",
    # pipeline
    "Pipeline",
    "Stage",
    "StageTransition",
    # gates
    "GateChecker",
    "GateResult",
    "L1StructuralGate",
    "L2AuditGate",
    "PhaseGate",
    # registry
    "AgentRegistry",
    "RegistryViolation",
    # retry
    "RetryPolicy",
    "RetryConfig",
    "RetryExhausted",
    "CircuitBreakerOpen",
    # tools
    "ToolDef",
    "ToolParam",
    "ToolResult",
    "ToolRegistry",
    "BuiltinExecutors",
    "STANDARD_TOOLS",
    "MCPToolAdapter",
    # MCP
    "MCPClientManager",
    "MCPToolInfo",
    # context pool
    "ContextPool",
    "Scope",
    "ProviderSpec",
    # phase engine
    "PhaseExecutionEngine",
    "PhaseDefinitionLoader",
    "PhaseDef",
    # orchestrator
    "AgentOrchestrator",
    # telemetry
    "Telemetry",
]
