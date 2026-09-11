"""Agent 运行结果合约 — AgentResult, AgentTrace, TokenUsage"""

from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Optional


class TokenUsage(BaseModel):
    """Token 用量统计"""
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class AgentTrace(BaseModel):
    """Agent 执行完整 trace — 每次 API 调用一条"""
    trace_id: str
    agent_id: str
    agent_type: str = Field(description="work | audit")
    started_at: datetime = Field(default_factory=datetime.now)
    ended_at: Optional[datetime] = None
    duration_ms: int = 0
    model: str = "unknown"
    token_usage: Optional[TokenUsage] = None
    tool_calls_count: int = 0
    tools_used: List[str] = Field(default_factory=list)
    outcome: str = Field(default="pending", description="success | validation_error | api_error | timeout | isolation_violation")
    error_message: Optional[str] = None
    output_file_path: Optional[str] = None


class AgentResult(BaseModel):
    """Agent 运行完整结果"""
    trace: AgentTrace
    output: Optional[dict] = None
    raw_text: Optional[str] = None

    @property
    def is_success(self) -> bool:
        return self.trace.outcome == "success"
