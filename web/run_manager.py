"""Web Pipeline 运行生命周期服务。

不接管服务重启前的 PID，也不提供强杀；RunManager 只保存可验证的
注册信息、构建 argv/env、启动当前进程以及把 Pipeline 快照收敛为 run 状态。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable


PROC_KEY = "proc"
ACTIVE_STATUSES = {"created", "running", "waiting_user", "stopping", "cancellation_requested", "orphaned"}
TERMINAL_PIPELINE_STATES = {"done", "needs_review", "failed", "cancelled"}

# 子进程不继承任意环境变量。此列表涵盖 Windows 启动、Python、私有映射、
# 常见 Anthropic 配置和网络证书/代理；Burp 覆盖值由 build_env 显式注入。
ENV_ALLOWLIST = {
    "APPDATA", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL",
    "COMSPEC", "HTTPS_PROXY", "HTTP_PROXY", "LOCALAPPDATA", "NO_PROXY", "PATH", "PATH_MAPPING",
    "PATHEXT", "PROGRAMDATA", "PYTHONHOME", "PYTHONPATH", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE",
    "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE", "VIRTUAL_ENV", "WINDIR",
}


class RunManager:
    def __init__(self, registry_path: Path):
        self.registry_path = Path(registry_path)
        self.runs: dict[str, dict[str, Any]] = {}

    def use_registry_path(self, path: Path) -> None:
        """测试或部署切换 registry 位置时保持同一内存注册表。"""
        self.registry_path = Path(path)

    def load(self) -> None:
        if not self.registry_path.exists():
            return
        try:
            payload = json.loads(self.registry_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                return
            for run_id, meta in payload.items():
                if isinstance(meta, dict):
                    meta.pop(PROC_KEY, None)
                    self.runs[run_id] = meta
        except (OSError, json.JSONDecodeError):
            return

    def save(self) -> None:
        serializable = {
            run_id: {key: value for key, value in meta.items() if key != PROC_KEY}
            for run_id, meta in self.runs.items()
        }
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.registry_path.with_suffix(self.registry_path.suffix + ".tmp")
        tmp.write_text(json.dumps(serializable, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.registry_path)

    @staticmethod
    def build_command(*, workspace: Path, pipeline: str, mock: bool, no_playwright: bool) -> list[str]:
        command = [
            sys.executable, "run_pipeline.py", "run", "--workspace", str(workspace),
            "--pipeline", pipeline, "--control-mode", "web", "--non-interactive",
        ]
        if mock:
            command.append("--mock")
        if no_playwright:
            command.append("--no-playwright")
        return command

    @staticmethod
    def build_env(*, burp_token: str | None, burp_host: str | None, burp_port: int | None) -> dict[str, str]:
        env = {key: value for key, value in os.environ.items() if key.upper() in ENV_ALLOWLIST}
        if burp_token:
            env["BURP_MCP_TOKEN"] = burp_token
        if burp_host:
            env["BURP_MCP_HOST"] = burp_host
        if burp_port:
            env["BURP_MCP_PORT"] = str(burp_port)
        return env

    @staticmethod
    def start(*, command: list[str], project_root: Path, workspace: Path,
              env: dict[str, str], popen_factory: Callable[..., Any]) -> Any:
        log_dir = workspace / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        stdout_log = open(log_dir / "web_run_stdout.log", "a", encoding="utf-8", errors="replace")
        try:
            return popen_factory(
                command, cwd=str(project_root), stdout=stdout_log, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, start_new_session=True, env=env,
            )
        finally:
            # Popen 已复制 OS handle；父进程不持有日志文件，避免长期句柄泄漏。
            stdout_log.close()

    @staticmethod
    def terminal_status(state: dict | None) -> str:
        return {
            "done": "succeeded", "needs_review": "needs_review",
            "failed": "failed", "cancelled": "cancelled",
        }.get((state or {}).get("current_state"), "failed")

    @classmethod
    def reconcile(cls, meta: dict, *, read_state: Callable[[Path], dict | None],
                  pid_may_be_running: Callable[[object], bool]) -> tuple[bool, bool]:
        """返回 (可能仍在运行, 是否 orphaned)；从不重新接管旧 PID。"""
        proc = meta.get(PROC_KEY)
        if proc is not None:
            return_code = proc.poll()
            if return_code is None:
                if meta.get("status") not in {"stopping", "cancellation_requested"}:
                    meta["status"] = "running"
                return True, False
            meta["exit_code"] = return_code
            meta["status"] = cls.terminal_status(read_state(Path(meta["workspace"]) / "pipeline_state.json"))
            return False, False
        if meta.get("pid") and pid_may_be_running(meta["pid"]):
            meta["status"] = "orphaned"
            return True, True
        meta["status"] = cls.terminal_status(read_state(Path(meta["workspace"]) / "pipeline_state.json"))
        return False, False
