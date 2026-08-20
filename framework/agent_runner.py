"""Agent Runner — 物理隔离的核心实现 + 多轮 Tool-Use 循环。

每个 Agent 是一次独立的 API 调用会话。
支持:
- 单轮模式: tools=None → 一次调用，直接返回文本
- 多轮 Tool-Use 模式: tools=ToolRegistry → API ↔ tool 交替，最多 max_turns 轮
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Tuple, List, Optional, Any
import asyncio
import json
import os
from datetime import datetime

from contracts.agent_result import AgentResult, AgentTrace, TokenUsage
from framework.retry import RetryPolicy, RetryConfig, RetryExhausted, CircuitBreakerOpen


def _default_max_tokens() -> int:
    """Allow private compatible gateways to cap a request without code edits."""
    try:
        return max(1, int(os.environ.get("ANTHROPIC_MAX_TOKENS", "32000")))
    except ValueError:
        return 32000


# ============================================================
# AgentConfig — 不可变 Agent 配置
# ============================================================

@dataclass(frozen=True)
class AgentConfig:
    """每个 Agent 实例的不可变配置。

    隔离保证核心: frozen=True 确保创建后不可修改。
    """
    agent_id: str
    agent_type: str  # "work" | "audit"

    persona_path: Path
    knowledge_paths: Tuple[Path, ...] = ()
    tool_manifest: Tuple[str, ...] = ()
    forbidden_patterns: Tuple[str, ...] = ()

    model: str = "claude-sonnet-5"
    max_tokens: int = field(default_factory=_default_max_tokens)
    temperature: float = 0.1
    max_tool_turns: int = 30  # 最多 tool-use 轮数

    def __post_init__(self):
        assert self.persona_path.exists(), f"Persona 文件不存在: {self.persona_path}"
        for kp in self.knowledge_paths:
            assert kp.exists(), f"知识库文件不存在: {kp}"


# ============================================================
# IsolationViolation
# ============================================================

class IsolationViolation(Exception):
    """编译时隔离违规"""

    def __init__(self, agent_id: str, pattern: str, source_file: str):
        self.agent_id = agent_id
        self.pattern = pattern
        self.source_file = source_file
        super().__init__(
            f"\n{'='*60}\n"
            f" 隔离违规: Agent '{agent_id}' 的 prompt 包含禁止模式\n"
            f" 模式: '{pattern}'\n"
            f" 来源: {source_file}\n"
            f" 这会导致 Goodhart's Law 污染 — 拒绝创建此 Agent。\n"
            f"{'='*60}"
        )


# ============================================================
# PromptCompiler
# ============================================================

class PromptCompiler:
    """Agent system prompt 编译器 + 隔离检查"""

    DEFAULT_FORBIDDEN: Tuple[str, ...] = (
        "审计 Agent",
        "审计 agent",
        "etsi-report-auditor",
        "Harness 违规",
        "Harness违规",
        "audit-checklist",
        "common-errors",
        "evidence-standards",
        "audit-result",
        "审计结果",
        "审计备忘录",
        "retryInstruction",
    )

    @classmethod
    def compile(cls, config: AgentConfig, task_context: dict) -> str:
        if config.agent_type == "work":
            cls._enforce_isolation(config)

        parts: List[str] = []

        persona = config.persona_path.read_text(encoding="utf-8")
        parts.append(persona)

        for kp in config.knowledge_paths:
            content = kp.read_text(encoding="utf-8")
            parts.append(f"\n---\n## 参考: {kp.stem}\n{content}")

        if config.tool_manifest:
            parts.append(f"\n## 可用工具\n{', '.join(config.tool_manifest)}")

        # 默认兼容原有 Work/Audit Agent：task 同时存在于 system 与 user
        # message。受控的按条款执行面可关闭 system 侧副本，避免把同一份
        # recipe/skill excerpt 在每次重试中重复计入上下文 token。
        if task_context.get("include_task_in_system", True):
            parts.append(f"\n---\n## 当前任务\n{task_context['task']}")
            parts.append(f"\n### 工作区\n{task_context['workspace']}")

        if task_context.get("inputs"):
            parts.append("\n### 输入文件")
            for inp in task_context["inputs"]:
                parts.append(f"- {inp}")

        # 上下文池数据 (Phase 引擎注入)
        pool_data = task_context.get("pool_data")
        if pool_data and isinstance(pool_data, dict):
            parts.append("\n### 上下文池数据")
            for key, value in pool_data.items():
                if isinstance(value, (dict, list)):
                    val_str = json.dumps(value, ensure_ascii=False, indent=None)
                else:
                    val_str = str(value)
                if len(val_str) > 2000:
                    val_str = val_str[:2000] + "...(truncated)"
                parts.append(f"- **{key}**: {val_str}")

        if task_context.get("output_schema"):
            parts.append(f"\n## 输出格式要求\n{task_context['output_schema']}")

        return "\n".join(parts)

    @classmethod
    def _enforce_isolation(cls, config: AgentConfig) -> None:
        all_content = config.persona_path.read_text(encoding="utf-8")
        for kp in config.knowledge_paths:
            all_content += "\n" + kp.read_text(encoding="utf-8")

        all_forbidden = set(cls.DEFAULT_FORBIDDEN) | set(config.forbidden_patterns)

        for pattern in all_forbidden:
            if pattern.lower() in all_content.lower():
                source = cls._find_source(pattern, config)
                raise IsolationViolation(config.agent_id, pattern, source)

    @classmethod
    def _find_source(cls, pattern: str, config: AgentConfig) -> str:
        for kp in [config.persona_path] + list(config.knowledge_paths):
            content = kp.read_text(encoding="utf-8")
            if pattern.lower() in content.lower():
                return str(kp)
        return "unknown"


# ============================================================
# AgentRunner — 多轮 Tool-Use 循环
# ============================================================

class AgentRunner:
    """Agent 运行器。

    单轮模式 (tools=None):
        response = await runner.run(config, task_ctx)
        → 一次 API 调用，返回文本

    多轮 Tool-Use 模式 (tools=ToolRegistry):
        response = await runner.run(config, task_ctx, tools=registry)
        → API ↔ tool 交替，最多 max_tool_turns 轮
    """

    def __init__(
        self,
        api_client: Any,
        telemetry: "Telemetry",  # noqa: F821
        retry_policy: Optional[RetryPolicy] = None,
    ):
        self.api = api_client
        self.telemetry = telemetry
        self.retry = retry_policy or RetryPolicy(RetryConfig())

    async def run(
        self,
        config: AgentConfig,
        task_context: dict,
        tools: Optional[Any] = None,  # Optional[ToolRegistry]
        output_schema: Optional[type] = None,
        retry_on_api_error: bool = True,
    ) -> AgentResult:
        """启动 Agent 调用。

        tools=None → 单轮模式
        tools=ToolRegistry → 多轮 Tool-Use 模式
        retry_on_api_error → 对单次 API 调用启用重试策略
        """
        trace_id = self.telemetry.start_trace(
            agent_id=config.agent_id,
            agent_type=config.agent_type,
        )
        started_at = datetime.now()
        total_input_tokens = 0
        total_output_tokens = 0
        all_tools_used: List[str] = []
        total_tool_calls = 0

        try:
            system_prompt = PromptCompiler.compile(config, task_context)

            messages: List[dict] = [
                {"role": "user", "content": task_context["task"]}
            ]

            # 将 ToolRegistry 转为 Anthropic schema (按 module 过滤)
            tool_schemas: Optional[List[dict]] = None
            tool_registry = None
            if tools is not None:
                try:
                    from framework.tools import ToolRegistry
                    if isinstance(tools, ToolRegistry):
                        tool_registry = tools
                        # 按 ModuleDef.tools 过滤: 只暴露该模块声明的工具分类
                        if config.tool_manifest:
                            filtered_names = tools.resolve_categories(config.tool_manifest)
                            tool_schemas = tools.to_anthropic_schemas(filtered_names)
                        else:
                            tool_schemas = tools.to_anthropic_schemas()
                except ImportError:
                    pass

            # ── 多轮 Tool-Use 循环 ──
            final_text: Optional[str] = None
            turn = 0
            max_turns = config.max_tool_turns if tool_schemas else 1

            while turn < max_turns:
                turn += 1

                api_params: dict = {
                    "model": config.model,
                    "max_tokens": config.max_tokens,
                    "temperature": config.temperature,
                    "system": system_prompt,
                    "messages": messages,
                }

                if tool_schemas:
                    api_params["tools"] = tool_schemas

                # DeepSeek's Anthropic-compatible API enables thinking by
                # default.  A bounded audit request may otherwise consume its
                # output budget in reasoning before emitting its JSON result.
                # Keep provider-neutral defaults; opt in only when a private
                # runtime explicitly sets enabled/disabled.
                thinking_mode = os.environ.get("ANTHROPIC_THINKING_MODE", "").lower()
                if thinking_mode in {"enabled", "disabled"}:
                    api_params["thinking"] = {"type": thinking_mode}

                # 单次 API 调用（含重试）
                response = await self._call_api_with_retry(
                    api_params, config.agent_id, retry_on_api_error
                )

                # 累计 token
                if hasattr(response, "usage"):
                    total_input_tokens += getattr(response.usage, "input_tokens", 0)
                    total_output_tokens += getattr(response.usage, "output_tokens", 0)

                # 检查 content
                if not hasattr(response, "content") or not response.content:
                    final_text = ""
                    break

                # 分离 text 和 tool_use blocks
                text_blocks = []
                tool_use_blocks = []

                for block in response.content:
                    block_type = getattr(block, "type", "text")
                    if block_type == "tool_use":
                        tool_use_blocks.append(block)
                    elif block_type == "text":
                        text_blocks.append(getattr(block, "text", ""))

                # 无 tool_use → 最终响应
                if not tool_use_blocks:
                    final_text = "\n".join(text_blocks)
                    break

                # 有 tool_use → 执行工具
                if tool_registry is None:
                    final_text = (
                        "[Tool use requested but no ToolRegistry available: "
                        f"{[getattr(b, 'name', '?') for b in tool_use_blocks]}]"
                    )
                    break

                # 将 assistant 响应加入 messages
                messages.append({
                    "role": "assistant",
                    "content": [
                        self._serialize_content_block(b)
                        for b in response.content
                    ],
                })

                # 执行所有 tool_use
                tool_results_content = []
                for tb in tool_use_blocks:
                    tool_name = getattr(tb, "name", "unknown")
                    tool_id = getattr(tb, "id", "")
                    tool_input = getattr(tb, "input", {})

                    all_tools_used.append(tool_name)
                    total_tool_calls += 1

                    receipt_context = {
                        "workspace": task_context.get("workspace"),
                        "agent_id": config.agent_id,
                        "agent_type": config.agent_type,
                        "module_id": task_context.get("module_id"),
                        "phase_id": task_context.get("phase_id"),
                        "clause_ids": task_context.get("clause_ids", []),
                        "attempt": task_context.get("attempt"),
                    }
                    result = await tool_registry.execute(tool_name, tool_input, receipt_context)
                    result.tool_use_id = tool_id

                    tool_results_content.append({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": result.content,
                        "is_error": result.is_error,
                    })

                messages.append({
                    "role": "user",
                    "content": tool_results_content,
                })

            # Tool budget is a guardrail, not a valid output boundary. Without
            # one final no-tool turn, an Agent that just read all required
            # inputs can end with raw_text=None and strand valid evidence.
            if final_text is None and tool_schemas:
                messages.append({
                    "role": "user",
                    "content": (
                        "工具调用预算已用尽。不得再调用工具；仅依据此前已返回的工具结果，"
                        "现在输出当前任务要求的最终 JSON 对象，不要附加解释。"
                    ),
                })
                api_params = {
                    "model": config.model,
                    "max_tokens": config.max_tokens,
                    "temperature": config.temperature,
                    "system": system_prompt,
                    "messages": messages,
                    "tools": tool_schemas,
                    "tool_choice": {"type": "none"},
                }
                thinking_mode = os.environ.get("ANTHROPIC_THINKING_MODE", "").lower()
                if thinking_mode in {"enabled", "disabled"}:
                    api_params["thinking"] = {"type": thinking_mode}
                response = await self._call_api_with_retry(
                    api_params, config.agent_id, retry_on_api_error
                )
                if hasattr(response, "usage"):
                    total_input_tokens += getattr(response.usage, "input_tokens", 0)
                    total_output_tokens += getattr(response.usage, "output_tokens", 0)
                final_text = "\n".join(
                    getattr(block, "text", "")
                    for block in getattr(response, "content", [])
                    if getattr(block, "type", "") == "text"
                )

                # Some Anthropic-compatible gateways (observed with
                # DeepSeek's DSML dialect) can return a *textual* tool-call
                # envelope even when tool_choice=none.  It is not executable
                # and is not a valid evidence/audit response.  Ask once more
                # with no tool schema at all; never interpret or execute the
                # textual envelope as a tool call.
                if self._is_textual_tool_protocol(final_text):
                    messages.append({
                        "role": "assistant",
                        "content": [
                            self._serialize_content_block(block)
                            for block in getattr(response, "content", [])
                        ],
                    })
                    messages.append({
                        "role": "user",
                        "content": (
                            "上一条是无效的工具调用文本，工具现已完全不可用。"
                            "不要调用任何工具；只输出当前任务要求的最终 JSON 对象，"
                            "不要附加解释或代码围栏。"
                        ),
                    })
                    recovery_params = {
                        "model": config.model,
                        "max_tokens": config.max_tokens,
                        "temperature": config.temperature,
                        "system": system_prompt,
                        "messages": messages,
                    }
                    if thinking_mode in {"enabled", "disabled"}:
                        recovery_params["thinking"] = {"type": thinking_mode}
                    response = await self._call_api_with_retry(
                        recovery_params, config.agent_id, retry_on_api_error
                    )
                    if hasattr(response, "usage"):
                        total_input_tokens += getattr(response.usage, "input_tokens", 0)
                        total_output_tokens += getattr(response.usage, "output_tokens", 0)
                    final_text = "\n".join(
                        getattr(block, "text", "")
                        for block in getattr(response, "content", [])
                        if getattr(block, "type", "") == "text"
                    )

            # ── 构建结果 ──
            output: Optional[dict] = None
            raw_text: Optional[str] = final_text

            # 尝试解析结构化输出
            if final_text and output_schema:
                try:
                    import json
                    text = final_text
                    if "```json" in text:
                        text = text.split("```json")[1].split("```")[0]
                    elif "```" in text:
                        text = text.split("```")[1].split("```")[0]
                    parsed = json.loads(text.strip())
                    output = output_schema(**parsed).model_dump()
                except Exception:
                    pass  # 解析失败，保留 raw_text

            duration_ms = int((datetime.now() - started_at).total_seconds() * 1000)

            trace = AgentTrace(
                trace_id=trace_id,
                agent_id=config.agent_id,
                agent_type=config.agent_type,
                started_at=started_at,
                ended_at=datetime.now(),
                duration_ms=duration_ms,
                model=config.model,
                token_usage=TokenUsage(
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                ),
                tool_calls_count=total_tool_calls,
                tools_used=list(set(all_tools_used)),
                outcome="success",
                output_file_path=task_context.get("output_file"),
            )

            result = AgentResult(trace=trace, output=output, raw_text=raw_text)
            self.telemetry.end_trace(trace_id, result)
            return result

        except IsolationViolation:
            raise

        except (RetryExhausted, CircuitBreakerOpen) as e:
            trace = AgentTrace(
                trace_id=trace_id,
                agent_id=config.agent_id,
                agent_type=config.agent_type,
                started_at=started_at,
                ended_at=datetime.now(),
                outcome="api_error",
                error_message=str(e),
            )
            self.telemetry.end_trace(trace_id, AgentResult(trace=trace))
            raise

        except Exception as e:
            trace = AgentTrace(
                trace_id=trace_id,
                agent_id=config.agent_id,
                agent_type=config.agent_type,
                started_at=started_at,
                ended_at=datetime.now(),
                outcome="api_error",
                error_message=str(e),
            )
            self.telemetry.end_trace(trace_id, AgentResult(trace=trace))
            raise

    async def _call_api_with_retry(
        self,
        api_params: dict,
        agent_id: str,
        retry_on_api_error: bool,
    ):
        """单次 API 调用，可选重试。"""
        if not retry_on_api_error:
            return await self.api.messages.create(**api_params)

        return await self.retry.execute(
            lambda: self.api.messages.create(**api_params),
            agent_id=agent_id,
        )

    @staticmethod
    def _serialize_content_block(block) -> dict:
        """Serialize an Anthropic content block to a dict for messages history."""
        block_type = getattr(block, "type", "text")
        if block_type == "text":
            return {"type": "text", "text": getattr(block, "text", "")}
        elif block_type == "thinking":
            # Anthropic-compatible gateways may emit a thinking block before
            # tool_use.  It must be returned unchanged on the next turn; a
            # generic {"type": "thinking"} loses the required payload.
            serialized = {
                "type": "thinking",
                "thinking": getattr(block, "thinking", ""),
            }
            signature = getattr(block, "signature", None)
            if signature:
                serialized["signature"] = signature
            return serialized
        elif block_type == "tool_use":
            return {
                "type": "tool_use",
                "id": getattr(block, "id", ""),
                "name": getattr(block, "name", ""),
                "input": getattr(block, "input", {}),
            }
        else:
            # Fallback: generic attribute extraction
            result = {"type": block_type}
            for attr in ("text", "id", "name", "input"):
                if hasattr(block, attr):
                    result[attr] = getattr(block, attr)
            return result

    @staticmethod
    def _is_textual_tool_protocol(text: str | None) -> bool:
        """Identify a provider's textual tool envelope without executing it."""
        if not text:
            return False
        lowered = text.lower()
        return "dsml" in lowered and "tool_calls" in lowered
