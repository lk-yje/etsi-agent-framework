import json
from pathlib import Path

from fastapi.testclient import TestClient

from framework.reporting import write_report_bundle
from framework.runtime_config import RuntimeSettings
from framework.traffic_state import TrafficStateStore
from web import server


def _configure_runtime(tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "runs"
    root.mkdir()
    mapping = tmp_path / "mapping.json"
    mapping.write_text('{"paths": {}}', encoding="utf-8")
    monkeypatch.setattr(
        server,
        "RUNTIME_SETTINGS",
        RuntimeSettings(tmp_path, root, mapping),
    )
    monkeypatch.setattr(server, "RUNS_FILE", tmp_path / "runs-registry.json")
    return root


def test_frontend_serves_persisted_traffic_checklist_controls():
    """Traffic 操作项必须有可访问的完成控件和留痕字段，而不只是视觉列表。"""
    response = TestClient(server.app).get("/")

    assert response.status_code == 200
    assert 'data-item-toggle="' in response.text
    assert 'data-note-item="' in response.text
    assert 'data-evidence-item="' in response.text
    assert 'data-save-item="' in response.text
    assert 'class="clause-toggle"' in response.text
    assert 'aria-expanded="false"' in response.text
    assert 'id="btnPickWorkspace"' in response.text
    assert 'placeholder="例如 D:\\ETSI\\runs\\case-001"' in response.text
    assert 'id="btnPickIxit"' in response.text
    assert 'id="btnPickFirmwareOld"' in response.text
    assert 'id="btnPickFirmwareTampered"' in response.text
    assert "'/api/input-file-picker'" in response.text
    assert 'id="inpToken"' not in response.text
    assert "inpIxitFile').files" not in response.text
    assert 'id="toolCoverage"' in response.text
    assert "按条款“应调用工具”分类" in response.text
    assert 'class="coverage-tool"' in response.text


def test_terminal_run_marks_unclosed_agent_trace_as_terminated():
    agents = server._derive_agents(
        [{"type": "agent_start", "agent_id": "work_M5_phase_B_v1", "agent_type": "work", "ts": "2026-08-25T00:00:03"}],
        run_terminal=True,
    )

    assert agents[0]["running"] is False
    assert agents[0]["outcome"] == "terminated"


def test_tool_coverage_uses_receipt_and_marks_missing_calls(tmp_path):
    ws = tmp_path / "case"
    (ws / "tool-receipts").mkdir(parents=True)
    (ws / "tool-receipts" / "one.json").write_text(json.dumps({
        "tool": {"name": "mcp__burp__proxy_history", "executable_hint": "mcp__burp__proxy_history"},
        "clause_ids": ["5.13-1"], "result": {"is_error": False},
    }), encoding="utf-8")

    coverage = server._read_tool_coverage(ws)
    burp_row = next(row for row in coverage["Burp MCP"] if row["clause"] == "5.13-1")

    assert burp_row["state"] == "已调用"
    assert burp_row["actual"][0]["source"] == "receipt"
    assert burp_row["actual"][0]["index"] == "tool-receipts/one.json"


def test_burp_recipe_subtools_do_not_fall_into_other_tools(tmp_path):
    coverage = server._read_tool_coverage(tmp_path)

    assert any(row["clause"] == "5.5-5" for row in coverage["Burp MCP"])
    assert not any(row["clause"] == "5.5-5" for row in coverage.get("其他工具", []))


def test_audit_queue_explains_l1_block_without_claiming_audit(tmp_path):
    ws = tmp_path / "case"
    ws.mkdir()
    (ws / "l1_errors_pre-M1-evidence.json").write_text("{}", encoding="utf-8")
    queue = server._derive_audit_queue_state("M1", ws, [], None, None)

    assert queue["state"] == "blocked_l1"
    assert "Audit 未入队" in queue["reason"]


def test_cancel_timeline_treats_forced_failure_as_terminal(tmp_path):
    ws = tmp_path / "case"
    (ws / "tokens").mkdir(parents=True)
    (ws / "tokens" / ".cancel_requested").touch()

    cancellation = server._derive_cancellation(
        ws, {"status": "failed"}, {"history": []}, {"current_state": "failed"},
    )

    assert cancellation["terminal"] is True
    assert cancellation["steps"][-1]["state"] == "done"


def test_web_api_does_not_enable_wildcard_cors():
    response = TestClient(server.app).get(
        "/api/health", headers={"Origin": "https://untrusted.example"},
    )

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_environment_endpoint_is_offline_and_secret_free(tmp_path, monkeypatch):
    _configure_runtime(tmp_path, monkeypatch)
    monkeypatch.setenv("BURP_MCP_TOKEN", "must-not-appear")

    response = TestClient(server.app).get("/api/environment")

    assert response.status_code == 200
    assert response.json()["dut"]["reachability"] == "not_checked"
    assert "must-not-appear" not in response.text


def test_input_file_picker_requires_a_non_c_path_mapping_root(tmp_path, monkeypatch):
    _configure_runtime(tmp_path, monkeypatch)

    response = TestClient(server.app).post("/api/input-file-picker", json={"kind": "ixit"})

    assert response.status_code == 409
    assert "PATH_MAPPING" in response.json()["detail"]


def test_preflight_snapshot_is_written_inside_workspace(tmp_path, monkeypatch):
    root = _configure_runtime(tmp_path, monkeypatch)
    workspace = root / "case-001"
    workspace.mkdir()

    response = TestClient(server.app).post(
        "/api/preflight",
        json={"workspace": "case-001", "dut_ip": "10.0.0.8", "include_versions": False},
    )

    assert response.status_code == 200
    snapshot = workspace / "environment_snapshot.json"
    assert snapshot.is_file()
    assert json.loads(snapshot.read_text(encoding="utf-8"))["dut"]["reachability"] == "not_checked"


def test_run_plan_preview_expands_functional_dependencies():
    response = TestClient(server.app).post(
        "/api/run-plan", json={"profile": "functional-module", "modules": ["M3"]},
    )
    assert response.status_code == 200
    plan = response.json()["plan"]
    assert plan["certificationClaim"] is False
    assert plan["selectedModules"] == ["M2", "M3"]


def test_m0_audit_resume_requires_a_terminal_m0_audit_snapshot(tmp_path, monkeypatch):
    root = _configure_runtime(tmp_path, monkeypatch)
    workspace = root / "case-resume"
    (workspace / "logs").mkdir(parents=True)
    (workspace / "pipeline_state.json").write_text(json.dumps({
        "current_state": "cancelled", "stage_statuses": {"m0_audit": "failed"},
    }), encoding="utf-8")
    server._runs.clear()
    server._runs["old"] = {"run_id": "old", "workspace": str(workspace), "status": "cancelled", "pipeline": "etsi-ts103701"}
    class FakeProcess: pid = 123
    monkeypatch.setattr(server.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())
    response = TestClient(server.app).post("/api/runs/old/resume-m0-audit")
    assert response.status_code == 201
    assert response.json()["resumes_run_id"] == "old"


def test_m1m5_resume_restarts_managed_run_from_traffic_snapshot(tmp_path, monkeypatch):
    root = _configure_runtime(tmp_path, monkeypatch)
    workspace = root / "case-m1-resume"
    (workspace / "logs").mkdir(parents=True)
    (workspace / "pipeline_state.json").write_text(json.dumps({
        "current_state": "failed", "stage_statuses": {"m1_m5": "failed"},
    }), encoding="utf-8")
    server._runs.clear()
    server._runs["old-m1"] = {"run_id": "old-m1", "workspace": str(workspace), "status": "failed", "pipeline": "etsi-ts103701"}
    class FakeProcess: pid = 456
    monkeypatch.setattr(server.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())
    response = TestClient(server.app).post("/api/runs/old-m1/resume-m1m5")
    assert response.status_code == 201
    assert response.json()["resumes_run_id"] == "old-m1"


def test_firmware_reference_uses_workspace_role_and_manifest(tmp_path, monkeypatch):
    root = _configure_runtime(tmp_path, monkeypatch)
    workspace = root / "case-firmware"
    workspace.mkdir()
    firmware_root = tmp_path / "firmware-library"
    firmware_root.mkdir()
    firmware = firmware_root / "old.bin"
    firmware.write_bytes(b"old-image")
    monkeypatch.setattr(
        server, "RUNTIME_SETTINGS",
        RuntimeSettings(tmp_path, root, tmp_path / "mapping.json", (firmware_root,)),
    )
    response = TestClient(server.app).post(
        "/api/workspaces/case-firmware/inputs/firmware/old/reference",
        json={"path": str(firmware)},
    )

    assert response.status_code == 201
    assert not (workspace / "inputs/firmware").exists()
    assert response.json()["manifest"]["inputs"]["firmware"]["old"]["source_path"] == str(firmware.resolve())
    assert response.json()["manifest"]["inputs"]["firmware"]["old"]["sha256"]


def test_run_status_exposes_actual_safe_stop_timeline(tmp_path, monkeypatch):
    root = _configure_runtime(tmp_path, monkeypatch)
    workspace = root / "case-safe-stop"
    workspace.mkdir()
    (workspace / "tokens").mkdir()
    (workspace / "tokens/.cancel_requested").touch()
    (workspace / "pipeline_state.json").write_text(json.dumps({"current_state": "traffic"}), encoding="utf-8")
    store = TrafficStateStore(workspace)
    store.initialize(checklist_version="test", checklist=[], dut_ip="10.0.0.8", capture_pcap=workspace / "capture.pcap", control_mode="web")
    store.transition("STOPPING", "cleanup_started")
    store.transition("RESTORING_PROXY", "burp_restore_started")

    class FakeProcess:
        def poll(self):
            return None

    run_id = "safe-stop-test"
    server._runs[run_id] = {"run_id": run_id, "workspace": str(workspace), "status": "cancellation_requested", "proc": FakeProcess()}
    response = TestClient(server.app).get(f"/api/runs/{run_id}")

    assert response.status_code == 200
    steps = {step["key"]: step for step in response.json()["cancellation"]["steps"]}
    assert steps["requested"]["state"] == "done"
    assert steps["traffic_cleanup"]["state"] == "done"
    assert steps["proxy_restore"]["state"] == "done"
    assert steps["pipeline_terminal"]["state"] == "current"
    server._runs.pop(run_id, None)


def test_start_run_rejects_workspace_outside_allowed_root(tmp_path, monkeypatch):
    _configure_runtime(tmp_path, monkeypatch)

    response = TestClient(server.app).post(
        "/api/runs",
        json={"workspace": str(tmp_path / "outside")},
    )

    assert response.status_code == 400
    assert "AUTO_TEST_ROOT" in response.json()["detail"]


def test_workspace_create_and_ixit_local_reference(tmp_path, monkeypatch):
    root = _configure_runtime(tmp_path, monkeypatch)
    input_root = tmp_path / "input-library"
    input_root.mkdir()
    source = input_root / "device.json"
    source.write_text(json.dumps({"meta": {}, "ics": [], "ixit_tables": {}}), encoding="utf-8")
    monkeypatch.setattr(server, "RUNTIME_SETTINGS", RuntimeSettings(tmp_path, root, tmp_path / "mapping.json", (), (input_root,)))
    client = TestClient(server.app)

    created = client.post("/api/workspaces", json={"name": "case-001"})
    assert created.status_code == 201

    referenced = client.post(
        "/api/workspaces/case-001/inputs/ixit/reference", json={"path": str(source)},
    )
    assert referenced.status_code == 201
    assert referenced.json()["manifest"]["inputs"]["ixit"]["source_sha256"]

    different = input_root / "other.json"
    different.write_text(json.dumps({"meta": {"model": "other"}, "ics": [], "ixit_tables": {}}), encoding="utf-8")
    conflict = client.post(
        "/api/workspaces/case-001/inputs/ixit/reference", json={"path": str(different)},
    )
    assert conflict.status_code == 409


def test_start_run_uses_burp_endpoint_env_and_preserves_ixit(tmp_path, monkeypatch):
    root = _configure_runtime(tmp_path, monkeypatch)
    workspace = root / "case-002"
    workspace.mkdir()
    original = json.dumps({"meta": {}, "ics": [], "ixit_tables": {}}).encode()
    (workspace / "ixit.json").write_bytes(original)
    captured = {}

    class FakeProcess:
        def __init__(self, cmd, **kwargs):
            captured["cmd"] = cmd
            captured["env"] = kwargs["env"]

        def poll(self):
            return None

    monkeypatch.setattr(server.subprocess, "Popen", FakeProcess)
    monkeypatch.setattr(server, "analyze_dut_target", lambda *_args, **_kwargs: {
        "url": "http://10.0.0.8/", "host": "10.0.0.8", "port": 80,
        "reachability": "reachable", "reason": None,
    })

    response = TestClient(server.app).post(
        "/api/runs",
        json={
            "workspace": "case-002",
            "dut_ip": "10.0.0.8",
            "burp_host": "127.0.0.1",
            "burp_port": 9876,
            "mock": True,
        },
    )

    assert response.status_code == 201
    assert captured["env"]["BURP_MCP_HOST"] == "127.0.0.1"
    assert captured["env"]["BURP_MCP_PORT"] == "9876"
    assert "BURP_MCP_TOKEN" not in captured["env"]
    assert (workspace / "ixit.json").read_bytes() == original
    run_config = json.loads((workspace / "run_config.json").read_text(encoding="utf-8"))
    assert run_config["dut_ip"] == "http://10.0.0.8/"
    assert run_config["dut_host"] == "10.0.0.8"
    assert run_config["dut_port"] == 80

    server._runs.pop(response.json()["run_id"], None)
    server._save_runs()


def test_server_restart_marks_unknown_live_pid_as_orphaned(tmp_path, monkeypatch):
    root = _configure_runtime(tmp_path, monkeypatch)
    workspace = root / "case-stop"
    workspace.mkdir()
    client = TestClient(server.app)

    orphan_id = "orphan-stop"
    server._runs[orphan_id] = {"run_id": orphan_id, "workspace": str(workspace), "status": "running", "pid": 9876}
    monkeypatch.setattr(server, "_pid_may_be_running", lambda _pid: True)
    status = client.get(f"/api/runs/{orphan_id}")
    assert status.status_code == 200
    assert status.json()["status"] == "orphaned"
    assert status.json()["process"]["managed"] is False
    server._runs.pop(orphan_id, None)


def test_forget_terminal_run_preserves_workspace_and_rejects_active_run(tmp_path, monkeypatch):
    root = _configure_runtime(tmp_path, monkeypatch)
    workspace = root / "case-forget"
    workspace.mkdir()
    marker = workspace / "evidence.txt"
    marker.write_text("keep", encoding="utf-8")
    client = TestClient(server.app)
    server._runs["terminal"] = {"run_id": "terminal", "workspace": str(workspace), "status": "succeeded"}

    forgotten = client.delete("/api/runs/terminal")
    assert forgotten.status_code == 200
    assert marker.read_text(encoding="utf-8") == "keep"
    assert "terminal" not in server._runs

    server._runs["active"] = {"run_id": "active", "workspace": str(workspace), "status": "running", "pid": 7}
    monkeypatch.setattr(server, "_pid_may_be_running", lambda _pid: True)
    assert client.delete("/api/runs/active").status_code == 409
    server._runs.pop("active", None)


def test_start_run_rejects_second_active_run_for_same_workspace(tmp_path, monkeypatch):
    root = _configure_runtime(tmp_path, monkeypatch)
    workspace = root / "case-active"
    workspace.mkdir()
    run_id = "already-active"
    server._runs[run_id] = {"run_id": run_id, "workspace": str(workspace), "status": "running"}

    response = TestClient(server.app).post("/api/runs", json={"workspace": "case-active"})

    assert response.status_code == 409
    assert "已有活动" in response.json()["detail"]
    server._runs.pop(run_id, None)


def test_evidence_download_exports_selected_clause_package(tmp_path, monkeypatch):
    root = _configure_runtime(tmp_path, monkeypatch)
    workspace = root / "case-evidence"
    (workspace / "evidence").mkdir(parents=True)
    (workspace / "evidence" / "pre-M1-evidence.json").write_text(json.dumps({
        "meta": {"moduleId": "M1"},
        "clauses": [{
            "clause_id": "5.6-1", "verdict": "PASS", "reason": "test",
            "evidence": [{"type": "nmap", "path": "nmap_tcp.txt", "level": "L1"}],
            "ixit_references": ["15-Intf"],
        }],
    }), encoding="utf-8")
    (workspace / "nmap_tcp.txt").write_text("80/tcp open http\n", encoding="utf-8")
    (workspace / "ixit.json").write_text(json.dumps({"meta": {}, "ixit_tables": {"15-Intf": {"rows": []}}}), encoding="utf-8")
    write_report_bundle(workspace)
    run_id = "evidence-download"
    server._runs[run_id] = {"run_id": run_id, "workspace": str(workspace), "status": "done"}

    report = TestClient(server.app).get(f"/api/runs/{run_id}/report")
    assert report.status_code == 200
    assert report.json()["clauses"][0]["evidence_package"]["package"] == "evidence-packages/5.6/5.6-1"
    assert any(name.endswith(".html") for name in report.json()["report_files"])
    assert report.json()["report_artifacts"]

    artifact = TestClient(server.app).get(f"/api/runs/{run_id}/artifacts/module-evidence-M1")
    assert artifact.status_code == 200
    assert '"moduleId": "M1"' in artifact.json()["content"]
    assert TestClient(server.app).get(f"/api/runs/{run_id}/file?path=ixit.json").status_code == 404

    response = TestClient(server.app).get(
        f"/api/runs/{run_id}/evidence-download", params={"scope": "clause", "value": "5.6-1"}
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/zip")
    assert "evidence_clauses_5.6-1.zip" not in response.headers.get("content-disposition", "")
    assert "evidence_clause_5.6-1.zip" in response.headers.get("content-disposition", "")
    server._runs.pop(run_id, None)
