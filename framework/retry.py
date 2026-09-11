"""重试策略 — 指数退避 + 熔断器。

用于 Agent API 调用失败时的自动重试。
"""

import asyncio
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional


class CircuitState(Enum):
    CLOSED = "closed"          # 正常，允许调用
    OPEN = "open"              # 熔断，拒绝调用
    HALF_OPEN = "half_open"    # 半开，允许一次探测调用


@dataclass
class RetryConfig:
    """重试策略配置"""
    max_retries: int = 3
    base_delay_seconds: float = 2.0
    max_delay_seconds: float = 60.0
    backoff_multiplier: float = 2.0
    jitter: bool = True       # 是否加随机抖动

    # 熔断器
    circuit_breaker: bool = True
    failure_threshold: int = 5       # 连续失败 N 次 → 熔断
    recovery_timeout_seconds: float = 60.0  # 熔断后 N 秒进入半开


class RetryExhausted(Exception):
    """重试次数耗尽"""

    def __init__(self, agent_id: str, attempts: int, last_error: Exception):
        self.agent_id = agent_id
        self.attempts = attempts
        self.last_error = last_error
        super().__init__(
            f"Agent '{agent_id}': 重试 {attempts} 次后仍失败。最后错误: {last_error}"
        )


class CircuitBreakerOpen(Exception):
    """熔断器打开，拒绝调用"""

    def __init__(self, agent_id: str):
        super().__init__(f"Agent '{agent_id}': 熔断器打开，拒绝调用")


class RetryPolicy:
    """指数退避重试 + 熔断器。

    用法:
        policy = RetryPolicy(RetryConfig(max_retries=3))
        result = await policy.execute(
            lambda: runner.run(config, task),
            agent_id=config.agent_id,
        )
    """

    def __init__(self, config: RetryConfig = RetryConfig()):
        self.config = config
        self._failure_counts: Dict[str, int] = {}
        self._circuit_state: Dict[str, CircuitState] = {}
        self._circuit_opened_at: Dict[str, float] = {}
        self._last_errors: Dict[str, Exception] = {}

    async def execute(self, fn, agent_id: str):
        """执行 fn，失败时按配置重试。熔断器打开时直接拒绝。"""
        # 熔断器检查
        if self.config.circuit_breaker and self._get_circuit_state(agent_id) == CircuitState.OPEN:
            raise CircuitBreakerOpen(agent_id)

        last_error: Optional[Exception] = None

        for attempt in range(self.config.max_retries + 1):  # 1 首次 + N 重试
            try:
                result = await fn()
                # 成功 → 重置失败计数
                self._on_success(agent_id)
                return result
            except Exception as e:
                last_error = e
                self._last_errors[agent_id] = e
                self._on_failure(agent_id)

                if attempt < self.config.max_retries:
                    delay = self._compute_delay(attempt)
                    await asyncio.sleep(delay)

        raise RetryExhausted(agent_id, self.config.max_retries + 1, last_error)

    def _compute_delay(self, attempt: int) -> float:
        """计算退避延迟"""
        delay = min(
            self.config.base_delay_seconds * (self.config.backoff_multiplier ** attempt),
            self.config.max_delay_seconds,
        )
        if self.config.jitter:
            delay *= random.uniform(0.5, 1.5)
        return delay

    def _on_failure(self, agent_id: str) -> None:
        """记录一次失败，检查是否触发熔断"""
        self._failure_counts[agent_id] = self._failure_counts.get(agent_id, 0) + 1
        if self._failure_counts[agent_id] >= self.config.failure_threshold:
            self._circuit_state[agent_id] = CircuitState.OPEN
            self._circuit_opened_at[agent_id] = asyncio.get_event_loop().time()

    def _on_success(self, agent_id: str) -> None:
        """成功后重置该 agent 的失败计数和熔断状态"""
        self._failure_counts.pop(agent_id, None)
        self._circuit_state.pop(agent_id, None)
        self._circuit_opened_at.pop(agent_id, None)

    def last_error(self, agent_id: str) -> Exception | None:
        """该 agent 最近一次失败的原始异常（熔断打开时可用来判定错误类别）。"""
        return self._last_errors.get(agent_id)

    def _get_circuit_state(self, agent_id: str) -> CircuitState:
        """获取当前熔断状态（含半开自动恢复逻辑）"""
        state = self._circuit_state.get(agent_id, CircuitState.CLOSED)
        if state == CircuitState.OPEN:
            opened_at = self._circuit_opened_at.get(agent_id, 0)
            if asyncio.get_event_loop().time() - opened_at > self.config.recovery_timeout_seconds:
                self._circuit_state[agent_id] = CircuitState.HALF_OPEN
                return CircuitState.HALF_OPEN
        return state

    def reset(self, agent_id: str) -> None:
        """手动重置某 agent 的重试/熔断状态"""
        self._failure_counts.pop(agent_id, None)
        self._circuit_state.pop(agent_id, None)
        self._circuit_opened_at.pop(agent_id, None)
        self._last_errors.pop(agent_id, None)
