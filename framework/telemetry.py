"""遥测系统 — 结构化日志、Trace、Token 统计。

三层遥测:
- Trace: 每次 Agent API 调用
- Stage: 每个管线阶段
- Pipeline Run: 整次运行

零外部依赖 — 使用标准库 logging + JSON 文件。
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from contracts.agent_result import AgentResult

logger = logging.getLogger("agent_framework")


class Telemetry:
    """遥测系统。

    提供:
    - 结构化日志 (JSON lines 写入日志文件)
    - Trace ID 贯穿 Agent → Stage → Pipeline 三层追踪
    - Token 用量累计
    - 每次 API 调用的完整审计日志（trace_{id}.json）
    """

    def __init__(self, log_dir: Path):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._active_traces: Dict[str, dict] = {}
        self._pipeline_token_total: int = 0
        # JSONL 事件流 — 实时状态的事件源（前端/后端 tail 用）
        self._events_path = self.log_dir / "events.jsonl"

    # ===== JSONL 事件流 =====

    def _emit(self, kind: str, **fields) -> None:
        """追加一行 JSON 事件到 events.jsonl。

        单进程单写者（管线在独立子进程运行），append + flush 即可保证顺序。
        事件行统一: {ts, type, ...fields}
        """
        try:
            line = json.dumps(
                {"ts": datetime.now().isoformat(timespec="seconds"), "type": kind, **fields},
                ensure_ascii=False, default=str,
            )
            with open(self._events_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
        except Exception:
            pass  # 事件流写失败不影响管线

    # ===== Trace 管理 =====

    def start_trace(self, agent_id: str, agent_type: str) -> str:
        """开始一次 Agent 调用的 trace，返回 trace_id"""
        ts = datetime.now().strftime("%H%M%S%f")[:12]
        trace_id = f"{agent_id}_{ts}"

        self._active_traces[trace_id] = {
            "trace_id": trace_id,
            "agent_id": agent_id,
            "agent_type": agent_type,
            "started_at": datetime.now().isoformat(),
        }
        self._emit(
            "agent_start", trace_id=trace_id, agent_id=agent_id, agent_type=agent_type,
        )
        logger.info("agent_trace_started trace_id=%s agent_id=%s", trace_id, agent_id)
        return trace_id

    def end_trace(
        self,
        trace_id: str,
        result: Optional[AgentResult],
        error: Optional[str] = None,
    ) -> None:
        """结束一次 Agent 调用的 trace"""
        trace = self._active_traces.pop(trace_id, {})
        trace["ended_at"] = datetime.now().isoformat()

        if error:
            trace["outcome"] = "error"
            trace["error"] = error
        elif result:
            trace["outcome"] = result.trace.outcome
            trace["duration_ms"] = result.trace.duration_ms
            trace["model"] = result.trace.model
            if result.trace.token_usage:
                trace["token_usage"] = result.trace.token_usage.model_dump()
                self._pipeline_token_total += result.trace.token_usage.total_tokens
            trace["tool_calls_count"] = result.trace.tool_calls_count
            trace["tools_used"] = result.trace.tools_used
            trace["output_file"] = result.trace.output_file_path

        # 写入结构化 trace 日志（JSON 格式，方便后续导入 ELK/Loki）
        log_file = self.log_dir / f"trace_{trace_id}.json"
        log_file.write_text(json.dumps(trace, indent=2, ensure_ascii=False, default=str))

        self._emit(
            "agent_end",
            trace_id=trace_id,
            agent_id=trace.get("agent_id", ""),
            agent_type=trace.get("agent_type", ""),
            outcome=trace.get("outcome", "unknown"),
            duration_ms=trace.get("duration_ms", 0),
            model=trace.get("model", ""),
            tool_calls_count=trace.get("tool_calls_count", 0),
            tools_used=trace.get("tools_used", []),
            output_file=trace.get("output_file", ""),
            error=trace.get("error", None),
            token_usage=trace.get("token_usage"),
        )

        logger.info("agent_trace_ended trace_id=%s outcome=%s", trace_id, trace.get("outcome", "unknown"))

    # ===== 阶段事件 =====

    def log_stage_event(self, pipeline_id: str, stage: str, event: str, **details) -> None:
        """记录阶段级事件"""
        self._emit("stage_event", pipeline_id=pipeline_id, stage=stage, event=event, details=details)
        logger.info(
            "stage_event pipeline=%s stage=%s event=%s %s",
            pipeline_id, stage, event,
            " ".join(f"{k}={v}" for k, v in details.items()),
        )

    def log_stage_start(self, pipeline_id: str, stage: str) -> None:
        self.log_stage_event(pipeline_id, stage, "started")

    def log_stage_complete(self, pipeline_id: str, stage: str, duration_s: float) -> None:
        self.log_stage_event(pipeline_id, stage, "completed", duration_s=duration_s)

    def log_stage_failed(self, pipeline_id: str, stage: str, error: str) -> None:
        self.log_stage_event(pipeline_id, stage, "failed", error=error)

    # ===== 管线级统计 =====

    def log_pipeline_start(self, pipeline_id: str, pipeline_name: str) -> None:
        self._emit("pipeline_start", pipeline_id=pipeline_id, pipeline_name=pipeline_name)
        logger.info("pipeline_started pipeline=%s name=%s", pipeline_id, pipeline_name)

    def log_pipeline_complete(self, pipeline_id: str, total_agents: int, total_duration_s: float) -> None:
        self._emit(
            "pipeline_end", pipeline_id=pipeline_id,
            total_agents=total_agents, duration_s=round(total_duration_s, 1),
            total_tokens=self._pipeline_token_total,
        )
        logger.info(
            "pipeline_completed pipeline=%s agents=%d tokens=%d duration=%.1fs",
            pipeline_id, total_agents, self._pipeline_token_total, total_duration_s,
        )

    @property
    def total_tokens(self) -> int:
        return self._pipeline_token_total

    @property
    def active_trace_count(self) -> int:
        return len(self._active_traces)
