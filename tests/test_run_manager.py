import json
import pytest

from web.run_manager import PROC_KEY, RunManager


def test_run_manager_builds_web_command_and_allowlisted_env(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "kept-for-local-run")
    monkeypatch.setenv("PATH_MAPPING", str(tmp_path / "local-mapping.json"))
    monkeypatch.setenv("UNRELATED_PARENT_SECRET", "must-not-leak")

    command = RunManager.build_command(
        workspace=tmp_path, pipeline="etsi-ts103701", mock=True, no_playwright=False,
    )
    env = RunManager.build_env(burp_host="127.0.0.1", burp_port=7777)

    assert command[:3] == [command[0], "run_pipeline.py", "run"]
    assert "--control-mode" in command and command[command.index("--control-mode") + 1] == "web"
    assert "--mock" in command and "--no-playwright" not in command
    assert env["ANTHROPIC_API_KEY"] == "kept-for-local-run"
    assert env["PATH_MAPPING"].endswith("local-mapping.json")
    assert "BURP_MCP_TOKEN" not in env
    assert "UNRELATED_PARENT_SECRET" not in env


def test_run_manager_rejects_playwright_downgrade(tmp_path):
    with pytest.raises(ValueError, match="禁止 --no-playwright"):
        RunManager.build_command(
            workspace=tmp_path, pipeline="etsi-ts103701", mock=False, no_playwright=True,
        )


def test_run_manager_persists_without_process_and_reconciles_safely(tmp_path):
    registry = tmp_path / "runs.json"
    manager = RunManager(registry)
    manager.runs["old"] = {"workspace": str(tmp_path), "status": "running", "pid": 1234, PROC_KEY: object()}
    manager.save()

    raw = json.loads(registry.read_text(encoding="utf-8"))
    assert PROC_KEY not in raw["old"]

    restarted = RunManager(registry)
    restarted.load()
    running, orphaned = RunManager.reconcile(
        restarted.runs["old"], read_state=lambda _path: None, pid_may_be_running=lambda _pid: True,
    )

    assert running is True and orphaned is True
    assert restarted.runs["old"]["status"] == "orphaned"


def test_run_manager_uses_pipeline_terminal_state_for_managed_process(tmp_path):
    class FinishedProcess:
        def poll(self):
            return 2

    meta = {"workspace": str(tmp_path), "status": "running", PROC_KEY: FinishedProcess()}
    running, orphaned = RunManager.reconcile(
        meta, read_state=lambda _path: {"current_state": "needs_review"}, pid_may_be_running=lambda _pid: False,
    )

    assert (running, orphaned) == (False, False)
    assert meta["exit_code"] == 2
    assert meta["status"] == "needs_review"
