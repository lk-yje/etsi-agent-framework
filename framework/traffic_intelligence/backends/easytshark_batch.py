"""未来 EasyTshark fork 的无界面 Batch CLI 适配器。"""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from pathlib import Path

from pydantic import BaseModel, ValidationError

from contracts.traffic_intelligence import ObservedFlow, ObservedFrame, ObservedProtocolRecord
from framework.traffic_intelligence.backends.base import (
    AnalysisBackend,
    BackendExecutionError,
    BackendRequest,
    BackendResult,
)


def _creation_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


class EasyTsharkBatchBackend(AnalysisBackend):
    """只接受约定的离线命令参数，不连接 EasyTshark 现有 HTTP/Tauri 服务。"""

    name = "easytshark_batch"

    def __init__(self, executable: str) -> None:
        self.executable = executable

    def availability(self) -> tuple[bool, str]:
        try:
            result = subprocess.run(
                [self.executable, "--version"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                shell=False,
                creationflags=_creation_flags(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"{type(exc).__name__}: {exc}"
        output = (result.stdout or result.stderr).strip()
        if result.returncode != 0:
            return False, output[:500] or f"exit {result.returncode}"
        return True, next((line.strip() for line in output.splitlines() if line.strip()), "unknown")

    def analyze(self, request: BackendRequest) -> BackendResult:
        request.output_dir.mkdir(parents=True, exist_ok=True)
        if request.output_dir.is_symlink():
            raise BackendExecutionError("拒绝写入符号链接形式的 backend output_dir")
        available, version = self.availability()
        if not available:
            raise BackendExecutionError(version)

        stdout_path = request.output_dir / f".worker-{uuid.uuid4().hex}.stdout"
        stderr_path = request.output_dir / f".worker-{uuid.uuid4().hex}.stderr"
        command = [
            self.executable,
            "--input",
            str(request.capture_path),
            "--output",
            str(request.output_dir),
            "--tshark",
            request.tshark_path,
            "--format",
            "jsonl",
            "--no-network",
            "--no-raw-payload",
        ]
        try:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                try:
                    process = subprocess.Popen(
                        command,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout,
                        stderr=stderr,
                        shell=False,
                        creationflags=_creation_flags(),
                    )
                    process.wait(timeout=request.timeout_seconds)
                except subprocess.TimeoutExpired as exc:
                    process.kill()
                    process.wait(timeout=10)
                    raise BackendExecutionError(
                        f"EasyTshark Worker 超过 {request.timeout_seconds} 秒未完成"
                    ) from exc
                except OSError as exc:
                    raise BackendExecutionError(f"无法启动 EasyTshark Worker: {exc}") from exc
            if process.returncode != 0:
                details = stderr_path.read_text(encoding="utf-8", errors="replace")[:2000]
                raise BackendExecutionError(
                    f"EasyTshark Worker 返回 {process.returncode}: {details or 'no stderr'}"
                )
            return self._validate_output(request.output_dir, version)
        finally:
            stdout_path.unlink(missing_ok=True)
            stderr_path.unlink(missing_ok=True)

    @staticmethod
    def _validate_jsonl(path: Path, model: type[BaseModel]) -> int:
        if path.is_symlink() or not path.is_file():
            raise BackendExecutionError(f"Worker 缺少输出: {path.name}")
        count = 0
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    if len(line.encode("utf-8")) > 1024 * 1024:
                        raise BackendExecutionError(
                            f"{path.name} 第 {line_number} 行超过 1 MiB"
                        )
                    model.model_validate_json(line)
                    count += 1
        except (OSError, ValidationError, ValueError) as exc:
            raise BackendExecutionError(f"Worker 输出校验失败 {path.name}: {exc}") from exc
        return count

    def _validate_output(self, output_dir: Path, detected_version: str) -> BackendResult:
        manifest_path = output_dir / "manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BackendExecutionError("Worker manifest.json 无法读取") from exc
        if manifest.get("complete") is not True:
            raise BackendExecutionError("Worker manifest 未标记 complete=true")

        frames_path = output_dir / "frames.jsonl"
        flows_path = output_dir / "flows.jsonl"
        observations_path = output_dir / "non-session-observations.jsonl"
        frame_count = self._validate_jsonl(frames_path, ObservedFrame)
        flow_count = self._validate_jsonl(flows_path, ObservedFlow)
        if observations_path.exists():
            self._validate_jsonl(observations_path, ObservedProtocolRecord)
        else:
            observations_path.write_text("", encoding="utf-8")

        return BackendResult(
            backend_name=self.name,
            backend_version=str(manifest.get("backend_version") or detected_version),
            tshark_version=str(manifest.get("tshark_version") or "unknown"),
            frame_index_path=frames_path,
            flow_index_path=flows_path,
            non_session_observations_path=observations_path,
            frame_count=frame_count,
            flow_count=flow_count,
            warnings=tuple(str(item) for item in manifest.get("warnings", [])),
            metrics={"frame_count": frame_count, "flow_count": flow_count},
        )
