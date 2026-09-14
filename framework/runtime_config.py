"""Deployment-level runtime configuration and path boundaries."""

from __future__ import annotations

import os
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RuntimeSettings:
    """Configuration owned by the server deployment, not by browser requests."""

    project_root: Path
    auto_test_root: Path
    path_mapping_path: Path | None
    firmware_roots: tuple[Path, ...] = ()
    input_roots: tuple[Path, ...] = ()
    traffic_analyzer_backend: str = "auto"
    traffic_payload_policy: str = "metadata_only"
    traffic_max_stream_sample_bytes: int = 4096
    traffic_easytshark_timeout_seconds: int = 1800
    traffic_easytshark_path: str | None = None

    @classmethod
    def from_env(cls, project_root: Path) -> RuntimeSettings:
        project_root = Path(project_root).resolve()
        default_runs = Path("D:/Auto-TEST") if os.name == "nt" else project_root / "runs"
        auto_test_root = Path(os.environ.get("AUTO_TEST_ROOT", str(default_runs))).resolve()
        raw_mapping = os.environ.get("PATH_MAPPING", "").strip()
        path_mapping = Path(raw_mapping).resolve() if raw_mapping else None
        firmware_roots: list[Path] = []
        raw_roots = os.environ.get("FIRMWARE_ROOTS", "").strip()
        if raw_roots:
            firmware_roots.extend(Path(value).resolve() for value in raw_roots.split(os.pathsep) if value.strip())

        # 只读取部署者显式指定的私有 PATH_MAPPING；绝不回退读取仓库内的映射表。
        # 这样浏览器侧本地固件引用可以沿用工作机自己的 DIR.FIRMWARE 配置。
        if path_mapping and path_mapping.is_file():
            try:
                mapping_data = json.loads(path_mapping.read_text(encoding="utf-8"))
                firmware_dir = mapping_data.get("paths", {}).get("DIR.FIRMWARE", {})
                configured = firmware_dir.get("windows") if os.name == "nt" else firmware_dir.get("linux")
                if configured:
                    firmware_roots.append(Path(configured).resolve())
            except (OSError, ValueError, json.JSONDecodeError):
                pass
        unique_roots = tuple(dict.fromkeys(firmware_roots))
        input_roots: list[Path] = []
        raw_input_roots = os.environ.get("INPUT_ROOTS", "").strip()
        if raw_input_roots:
            input_roots.extend(Path(value).resolve() for value in raw_input_roots.split(os.pathsep) if value.strip())
        if path_mapping and path_mapping.is_file():
            try:
                mapping_data = json.loads(path_mapping.read_text(encoding="utf-8"))
                for logical_name in ("DIR.IXIT", "DIR.INPUT", "DIR.INPUTS"):
                    configured_dir = mapping_data.get("paths", {}).get(logical_name, {})
                    configured = configured_dir.get("windows") if os.name == "nt" else configured_dir.get("linux")
                    if configured:
                        input_roots.append(Path(configured).resolve())
            except (OSError, ValueError, json.JSONDecodeError):
                pass
        unique_input_roots = tuple(dict.fromkeys(input_roots))
        from framework.traffic_intelligence.pipeline import TrafficIntelligenceSettings

        traffic = TrafficIntelligenceSettings.from_environment()
        return cls(
            project_root=project_root,
            auto_test_root=auto_test_root,
            path_mapping_path=path_mapping,
            firmware_roots=unique_roots,
            input_roots=unique_input_roots,
            traffic_analyzer_backend=traffic.backend,
            traffic_payload_policy=traffic.payload_policy,
            traffic_max_stream_sample_bytes=traffic.max_stream_sample_bytes,
            traffic_easytshark_timeout_seconds=traffic.timeout_seconds,
            traffic_easytshark_path=traffic.easytshark_path,
        )

    def resolve_workspace(self, value: str | Path, *, create: bool = False) -> Path:
        """Resolve a workspace.

        相对路径仍固定在 ``AUTO_TEST_ROOT``；Windows 的绝对路径允许用户从
        非 C: 数据盘显式选择。C: 保持禁止，避免本机控制台被用作系统盘浏览器。
        """
        raw = str(value).strip()
        if not raw:
            raise ValueError("workspace 不能为空")

        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = self.auto_test_root / candidate
        target = candidate.resolve()
        root = self.auto_test_root.resolve()

        if not target.is_relative_to(root):
            if os.name != "nt" or target.drive.upper() == "C:":
                raise ValueError("workspace 必须位于 AUTO_TEST_ROOT 内，或为非 C: 的绝对本地路径")
        if create:
            target.mkdir(parents=True, exist_ok=True)
        return target

    def public_summary(self) -> dict:
        """Return non-secret deployment information safe for the local UI."""
        mapping = self.path_mapping_path
        return {
            "auto_test_root": str(self.auto_test_root),
            "path_mapping": {
                "configured": mapping is not None,
                "exists": bool(mapping and mapping.is_file()),
                "source": "environment" if mapping else "system_path",
                "path": str(mapping) if mapping else None,
            },
            "firmware_roots": [
                {"path": str(root), "exists": root.is_dir()}
                for root in self.firmware_roots
            ],
            "input_roots": [
                {"path": str(root), "exists": root.is_dir()}
                for root in self.input_roots
            ],
            "traffic_intelligence": {
                "requested_backend": self.traffic_analyzer_backend,
                "payload_policy": self.traffic_payload_policy,
                "max_stream_sample_bytes": self.traffic_max_stream_sample_bytes,
                "easytshark_configured": bool(self.traffic_easytshark_path),
            },
        }
