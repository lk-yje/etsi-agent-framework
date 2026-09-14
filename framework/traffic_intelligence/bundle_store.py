"""Traffic Intelligence Bundle 的隔离写入、原子发布和完整性读取。"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, TypeVar

from pydantic import BaseModel

from contracts.traffic_intelligence import BundleArtifact, TrafficCaptureManifest


class BundleError(RuntimeError):
    """Bundle 操作失败。"""


class BundleIntegrityError(BundleError):
    """Bundle、artifact 或原始 PCAP 完整性校验失败。"""


ModelT = TypeVar("ModelT", bound=BaseModel)


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative_path(value: str | Path) -> Path:
    raw = str(value).strip()
    normalized = raw.replace("\\", "/")
    posix = PurePosixPath(normalized)
    windows = PureWindowsPath(raw)
    if (
        not raw
        or normalized.startswith("/")
        or windows.is_absolute()
        or windows.drive
        or ".." in posix.parts
        or any(part in {"", "."} for part in posix.parts)
    ):
        raise ValueError("Bundle 文件必须使用安全相对路径")
    return Path(*posix.parts)


def _ensure_within(root: Path, candidate: Path) -> Path:
    resolved_root = root.resolve()
    resolved_candidate = candidate.resolve(strict=False)
    if not resolved_candidate.is_relative_to(resolved_root):
        raise ValueError(f"路径越出工作区: {candidate}")
    return resolved_candidate


def _json_compatible(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_compatible(item) for item in value]
    return value


def _media_type(path: Path) -> str:
    if path.suffix == ".jsonl":
        return "application/x-ndjson"
    if path.suffix == ".json":
        return "application/json"
    if path.suffix in {".txt", ".log"}:
        return "text/plain"
    return "application/octet-stream"


class TrafficIntelligenceBundleWriter:
    """在 workspace 内构建临时 Bundle，校验后一次性发布。"""

    def __init__(
        self,
        workspace: Path,
        manifest: TrafficCaptureManifest,
        *,
        capture_path: Path | None = None,
        output_name: str = "traffic-intelligence",
    ) -> None:
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        output_relative = _safe_relative_path(output_name)
        if len(output_relative.parts) != 1:
            raise ValueError("output_name 只能是工作区下的一个目录名")
        self.output_dir = _ensure_within(self.workspace, self.workspace / output_relative)
        selected_capture = Path(capture_path) if capture_path else Path("capture.pcap")
        if not selected_capture.is_absolute():
            selected_capture = self.workspace / selected_capture
        self.capture_path = _ensure_within(self.workspace, selected_capture)
        if not self.capture_path.is_file():
            raise FileNotFoundError(self.capture_path)
        if self.capture_path.stat().st_size != manifest.capture_size:
            raise BundleIntegrityError("manifest capture_size 与输入 PCAP 不一致")
        if sha256_file(self.capture_path) != manifest.capture_sha256:
            raise BundleIntegrityError("manifest capture_sha256 与输入 PCAP 不一致")

        self.manifest = manifest.model_copy(deep=True, update={"complete": False})
        self.staging_dir = _ensure_within(
            self.workspace,
            self.workspace / f".{output_relative.name}.staging-{uuid.uuid4().hex}",
        )
        self.staging_dir.mkdir(parents=False, exist_ok=False)
        self._artifacts: dict[str, BundleArtifact] = {}
        self._committed = False

    def _target(self, relative_path: str | Path) -> tuple[Path, str]:
        relative = _safe_relative_path(relative_path)
        logical = PurePosixPath(*relative.parts).as_posix()
        if logical == "manifest.json":
            raise ValueError("manifest.json 由 BundleWriter 在 commit 时生成")
        target = _ensure_within(self.staging_dir, self.staging_dir / relative)
        return target, logical

    @staticmethod
    def _atomic_write_text(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)

    def _record_artifact(self, path: Path, logical_path: str) -> BundleArtifact:
        artifact = BundleArtifact(
            path=logical_path,
            sha256=sha256_file(path),
            size=path.stat().st_size,
            media_type=_media_type(path),
        )
        self._artifacts[logical_path] = artifact
        return artifact

    def write_json(self, relative_path: str | Path, value: Any) -> BundleArtifact:
        target, logical = self._target(relative_path)
        serialized = json.dumps(
            _json_compatible(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
        self._atomic_write_text(target, serialized)
        return self._record_artifact(target, logical)

    def write_jsonl(
        self,
        relative_path: str | Path,
        rows: Iterable[Any],
    ) -> BundleArtifact:
        target, logical = self._target(relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(
                    _json_compatible(row),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ))
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(target)
        return self._record_artifact(target, logical)

    def register_existing(self, relative_path: str | Path) -> BundleArtifact:
        """登记已由受控 backend 写入 staging 的文件，不复制大型索引。"""
        target, logical = self._target(relative_path)
        if target.is_symlink() or not target.is_file():
            raise BundleError(f"无法登记不存在或为符号链接的 artifact: {logical}")
        return self._record_artifact(target, logical)

    def update_manifest(self, **updates: Any) -> TrafficCaptureManifest:
        """在提交前更新后端、时间和警告等运行事实，并重新执行合约校验。"""
        if self._committed:
            raise BundleError("已提交的 manifest 不可修改")
        values = self.manifest.model_dump()
        values.update(updates)
        values["complete"] = False
        values["analysis_finished_at"] = None
        values["artifacts"] = []
        self.manifest = TrafficCaptureManifest.model_validate(values)
        return self.manifest

    def commit(self) -> Path:
        if self._committed:
            raise BundleError("BundleWriter 已经提交")
        if sha256_file(self.capture_path) != self.manifest.capture_sha256:
            raise BundleIntegrityError("分析期间输入 PCAP 发生变化")
        if self.capture_path.stat().st_size != self.manifest.capture_size:
            raise BundleIntegrityError("分析期间输入 PCAP 大小发生变化")

        completed = self.manifest.model_copy(update={
            "analysis_finished_at": datetime.now(timezone.utc),
            "complete": True,
            "artifacts": [self._artifacts[key] for key in sorted(self._artifacts)],
        })
        manifest_path = self.staging_dir / "manifest.json"
        self._atomic_write_text(
            manifest_path,
            completed.model_dump_json(indent=2) + "\n",
        )

        backup = _ensure_within(
            self.workspace,
            self.workspace / f".{self.output_dir.name}.backup-{uuid.uuid4().hex}",
        )
        had_previous = self.output_dir.exists()
        if had_previous:
            if self.output_dir.is_symlink():
                raise BundleError("拒绝替换符号链接形式的 Bundle 目录")
            self.output_dir.replace(backup)
        try:
            self.staging_dir.replace(self.output_dir)
        except Exception:
            if had_previous and backup.exists() and not self.output_dir.exists():
                backup.replace(self.output_dir)
            raise
        if backup.exists():
            if backup.is_symlink():
                backup.unlink()
            else:
                shutil.rmtree(backup)
        self.manifest = completed
        self._committed = True
        return self.output_dir

    def abort(self) -> None:
        if self._committed or not self.staging_dir.exists():
            return
        if self.staging_dir.is_symlink():
            self.staging_dir.unlink()
        else:
            shutil.rmtree(self.staging_dir)

    def __enter__(self) -> "TrafficIntelligenceBundleWriter":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if exc is not None or not self._committed:
            self.abort()


class TrafficIntelligenceBundleStore:
    """读取前强制校验 manifest、artifact 和可选的原始 PCAP。"""

    def __init__(self, workspace: Path, *, output_name: str = "traffic-intelligence") -> None:
        self.workspace = Path(workspace).resolve()
        output_relative = _safe_relative_path(output_name)
        if len(output_relative.parts) != 1:
            raise ValueError("output_name 只能是工作区下的一个目录名")
        self.bundle_dir = _ensure_within(self.workspace, self.workspace / output_relative)
        self._manifest: TrafficCaptureManifest | None = None

    def load_manifest(
        self,
        *,
        verify_artifacts: bool = True,
        capture_path: Path | None = None,
    ) -> TrafficCaptureManifest:
        manifest_path = _ensure_within(self.bundle_dir, self.bundle_dir / "manifest.json")
        try:
            manifest = TrafficCaptureManifest.model_validate_json(
                manifest_path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            raise BundleIntegrityError(f"manifest 无法读取或校验: {exc}") from exc
        if not manifest.complete:
            raise BundleIntegrityError("Bundle 尚未完整提交")
        if verify_artifacts:
            self._verify_artifacts(manifest)
        if capture_path is not None:
            capture = Path(capture_path)
            if not capture.is_absolute():
                capture = self.workspace / capture
            capture = _ensure_within(self.workspace, capture)
            if not capture.is_file():
                raise BundleIntegrityError("原始 PCAP 不存在")
            if capture.stat().st_size != manifest.capture_size:
                raise BundleIntegrityError("原始 PCAP 大小与 manifest 不一致")
            if sha256_file(capture) != manifest.capture_sha256:
                raise BundleIntegrityError("原始 PCAP 哈希与 manifest 不一致")
        self._manifest = manifest
        return manifest

    def _verify_artifacts(self, manifest: TrafficCaptureManifest) -> None:
        seen: set[str] = set()
        for artifact in manifest.artifacts:
            if artifact.path in seen:
                raise BundleIntegrityError(f"manifest 包含重复 artifact: {artifact.path}")
            seen.add(artifact.path)
            relative = _safe_relative_path(artifact.path)
            path = _ensure_within(self.bundle_dir, self.bundle_dir / relative)
            if not path.is_file():
                raise BundleIntegrityError(f"artifact 不存在: {artifact.path}")
            if path.stat().st_size != artifact.size:
                raise BundleIntegrityError(f"artifact 大小不一致: {artifact.path}")
            if sha256_file(path) != artifact.sha256:
                raise BundleIntegrityError(f"artifact 哈希不一致: {artifact.path}")

        actual: set[str] = set()
        for path in self.bundle_dir.rglob("*"):
            if path.is_symlink():
                raise BundleIntegrityError("Bundle 中不允许符号链接")
            if path.is_file():
                actual.add(path.relative_to(self.bundle_dir).as_posix())
        unexpected = actual - seen - {"manifest.json"}
        if unexpected:
            raise BundleIntegrityError(
                "Bundle 包含未在 manifest 声明的文件: " + ", ".join(sorted(unexpected))
            )

    def _read_target(self, relative_path: str | Path) -> Path:
        if self._manifest is None:
            self.load_manifest()
        relative = _safe_relative_path(relative_path)
        target = _ensure_within(self.bundle_dir, self.bundle_dir / relative)
        declared = {artifact.path for artifact in self._manifest.artifacts}
        logical = PurePosixPath(*relative.parts).as_posix()
        if logical != "manifest.json" and logical not in declared:
            raise BundleIntegrityError(f"文件未在 manifest 中声明: {logical}")
        return target

    def read_json(self, relative_path: str | Path, *, max_bytes: int = 10 * 1024 * 1024) -> Any:
        target = self._read_target(relative_path)
        if target.stat().st_size > max_bytes:
            raise BundleError(f"文件超过读取上限 {max_bytes} bytes")
        try:
            return json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BundleIntegrityError(f"JSON 无法读取: {relative_path}") from exc

    def read_model(self, relative_path: str | Path, model: type[ModelT]) -> ModelT:
        return model.model_validate(self.read_json(relative_path))

    def iter_jsonl(
        self,
        relative_path: str | Path,
        *,
        max_line_bytes: int = 1024 * 1024,
    ) -> Iterator[dict[str, Any]]:
        target = self._read_target(relative_path)
        try:
            with target.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if len(line.encode("utf-8")) > max_line_bytes:
                        raise BundleIntegrityError(
                            f"JSONL 第 {line_number} 行超过限制: {relative_path}"
                        )
                    if not line.strip():
                        continue
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise BundleIntegrityError(
                            f"JSONL 第 {line_number} 行不是对象: {relative_path}"
                        )
                    yield value
        except json.JSONDecodeError as exc:
            raise BundleIntegrityError(f"JSONL 内容损坏: {relative_path}") from exc
