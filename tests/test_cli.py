"""CLI process-outcome contract tests."""

import json
import sys

import pytest

import run_pipeline


def _argv_for(command: str) -> list[str]:
    if command == "run":
        return ["run_pipeline.py", "run", "--workspace", "test-workspace"]
    return ["run_pipeline.py", "workspace-status", "--path", "."]


def test_structured_error_exits_nonzero(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", _argv_for("workspace-status"))
    monkeypatch.setattr(
        run_pipeline,
        "_dispatch",
        lambda args: {"status": "error", "error": "expected failure"},
    )

    with pytest.raises(SystemExit) as exc:
        run_pipeline.main()

    assert exc.value.code == 1
    assert json.loads(capsys.readouterr().out)["status"] == "error"


def test_run_not_done_exits_nonzero(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", _argv_for("run"))
    monkeypatch.setattr(
        run_pipeline,
        "_dispatch",
        lambda args: {"status": "ok", "final_state": "failed"},
    )

    with pytest.raises(SystemExit) as exc:
        run_pipeline.main()

    assert exc.value.code == 1
    assert json.loads(capsys.readouterr().out)["final_state"] == "failed"


def test_successful_command_returns_normally(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", _argv_for("workspace-status"))
    monkeypatch.setattr(run_pipeline, "_dispatch", lambda args: {"status": "ok"})

    assert run_pipeline.main() is None
    assert json.loads(capsys.readouterr().out)["status"] == "ok"
