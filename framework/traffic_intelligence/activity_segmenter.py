"""无人工步骤标签的自动流量活动窗口。"""

from __future__ import annotations

import hashlib
import statistics
from dataclasses import dataclass, field

from contracts.traffic_intelligence import (
    ActivityKind,
    AutomaticActivityWindow,
    ObservedFrame,
)


def _is_initial_syn(flags: str | None) -> bool:
    if not flags:
        return False
    try:
        value = int(flags.split(",", 1)[0], 0)
        return bool(value & 0x02) and not bool(value & 0x10)
    except ValueError:
        normalized = flags.casefold()
        return "syn" in normalized and "ack" not in normalized


@dataclass
class _WindowAccumulator:
    start: float
    end: float
    frame_count: int = 0
    total_bytes: int = 0
    max_frame_length: int = 0
    flow_ids: set[str] = field(default_factory=set)
    syn_flow_ids: set[str] = field(default_factory=set)
    timestamps: list[float] = field(default_factory=list)

    def add(self, frame: ObservedFrame) -> None:
        self.end = max(self.end, frame.timestamp_epoch)
        self.frame_count += 1
        self.total_bytes += frame.frame_length
        self.max_frame_length = max(self.max_frame_length, frame.frame_length)
        self.timestamps.append(frame.timestamp_epoch)
        if frame.flow_id:
            self.flow_ids.add(frame.flow_id)
            if _is_initial_syn(frame.tcp_flags):
                self.syn_flow_ids.add(frame.flow_id)


class AutomaticActivitySegmenter:
    """按静默间隔流式分段，只输出可解释的自动标签。"""

    def __init__(self, *, idle_gap_seconds: float = 2.0) -> None:
        if idle_gap_seconds <= 0:
            raise ValueError("idle_gap_seconds 必须大于 0")
        self.idle_gap_seconds = float(idle_gap_seconds)
        self.capture_start: float | None = None
        self.current: _WindowAccumulator | None = None
        self.windows: list[AutomaticActivityWindow] = []

    def add(self, frame: ObservedFrame) -> None:
        if self.capture_start is None:
            self.capture_start = frame.timestamp_epoch
        if (
            self.current is not None
            and frame.timestamp_epoch - self.current.end > self.idle_gap_seconds
        ):
            self._finish_current()
        if self.current is None:
            self.current = _WindowAccumulator(frame.timestamp_epoch, frame.timestamp_epoch)
        self.current.add(frame)

    @staticmethod
    def _classify(window: _WindowAccumulator) -> tuple[ActivityKind, float, list[str]]:
        duration = max(0.0, window.end - window.start)
        if len(window.syn_flow_ids) >= 3 and duration <= 10.0:
            return (
                ActivityKind.RECONNECT,
                0.8,
                [f"10 秒内观察到 {len(window.syn_flow_ids)} 个含初始 SYN 的 Flow"],
            )

        intervals = [
            right - left
            for left, right in zip(window.timestamps, window.timestamps[1:])
            if right > left
        ]
        if (
            len(window.flow_ids) == 1
            and window.frame_count >= 4
            and window.max_frame_length <= 512
            and len(intervals) >= 3
        ):
            mean_interval = statistics.fmean(intervals)
            variation = statistics.pstdev(intervals) / mean_interval if mean_interval else 1.0
            if mean_interval >= 0.2 and variation <= 0.15:
                return (
                    ActivityKind.HEARTBEAT,
                    0.82,
                    [
                        f"单 Flow 小包呈稳定周期，均值 {mean_interval:.3f}s",
                        f"间隔变异系数 {variation:.3f}",
                    ],
                )

        if window.total_bytes >= 64 * 1024 or window.frame_count >= 100:
            return (
                ActivityKind.TRANSFER,
                0.85,
                [f"窗口内 {window.frame_count} 帧、{window.total_bytes} bytes"],
            )
        rate = window.frame_count / max(duration, 0.001)
        if window.frame_count >= 10 and (duration <= 2.0 or rate >= 20.0):
            return (
                ActivityKind.FLOW_BURST,
                0.8,
                [f"窗口帧率约 {rate:.2f} frames/s"],
            )
        return (
            ActivityKind.UNATTRIBUTED_ACTIVITY,
            0.35,
            ["没有人工步骤标签，现有时序特征不足以归因具体业务操作"],
        )

    def _finish_current(self) -> None:
        if self.current is None or self.capture_start is None:
            return
        current = self.current
        kind, confidence, observations = self._classify(current)
        flow_ids = sorted(current.flow_ids)
        material = "\0".join((
            f"{current.start:.6f}",
            f"{current.end:.6f}",
            str(current.frame_count),
            *flow_ids,
        ))
        window_id = f"activity-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"
        self.windows.append(AutomaticActivityWindow(
            window_id=window_id,
            start_offset_ms=max(0.0, (current.start - self.capture_start) * 1000),
            end_offset_ms=max(0.0, (current.end - self.capture_start) * 1000),
            flow_ids=flow_ids,
            kind=kind,
            confidence=confidence,
            observations=observations,
        ))
        self.current = None

    def finish(self) -> list[AutomaticActivityWindow]:
        self._finish_current()
        return list(self.windows)


__all__ = ["AutomaticActivitySegmenter"]
