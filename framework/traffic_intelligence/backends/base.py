"""Direct Tshark 与 EasyTshark Batch Worker 的共同接口。"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class BackendError(RuntimeError):
    """分析后端失败的基类。"""


class BackendUnavailableError(BackendError):
    """后端二进制或依赖不可用。"""


class BackendExecutionError(BackendError):
    """后端已启动但未产生有效 staging 数据。"""


@dataclass(frozen=True)
class BackendRequest:
    workspace: Path
    capture_path: Path
    output_dir: Path
    tshark_path: str
    dut_addresses: tuple[str, ...] = ()
    timeout_seconds: int = 1800
    options: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds 必须大于 0")
        workspace = self.workspace.resolve()
        capture_path = self.capture_path.resolve()
        output_dir = self.output_dir.resolve(strict=False)
        if not capture_path.is_relative_to(workspace):
            raise ValueError("capture_path 必须位于当前 workspace")
        if not output_dir.is_relative_to(workspace):
            raise ValueError("output_dir 必须位于当前 workspace")
        if not capture_path.is_file():
            raise FileNotFoundError(capture_path)
        object.__setattr__(self, "workspace", workspace)
        object.__setattr__(self, "capture_path", capture_path)
        object.__setattr__(self, "output_dir", output_dir)


@dataclass(frozen=True)
class BackendResult:
    backend_name: str
    backend_version: str
    tshark_version: str
    frame_index_path: Path
    flow_index_path: Path
    non_session_observations_path: Path | None = None
    payload_profiles_path: Path | None = None
    frame_count: int = 0
    flow_count: int = 0
    warnings: tuple[str, ...] = ()
    metrics: dict[str, int | float | str] = field(default_factory=dict)


class AnalysisBackend(ABC):
    name: str

    @abstractmethod
    def availability(self) -> tuple[bool, str]:
        """返回 (是否可用, 版本或不可用原因)。"""

    @abstractmethod
    def analyze(self, request: BackendRequest) -> BackendResult:
        """把 PCAP 转换为标准 staging 索引。"""
