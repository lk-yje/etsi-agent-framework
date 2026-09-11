import asyncio
import json

from framework.tools import BuiltinExecutors, STANDARD_TOOLS, ToolDef, ToolRegistry


def test_tool_registry_writes_redacted_receipt_with_clause_context(tmp_path):
    registry = ToolRegistry()
    registry.register([ToolDef(name="probe", description="test", parameters=[])])

    async def probe(_params):
        return "Authorization: Bearer response-secret\nscan complete"

    registry.set_executor("probe", probe)
    result = asyncio.run(registry.execute(
        "probe",
        {"url": "https://127.0.0.1", "api_token": "request-secret", "command": "curl -H 'Authorization: Bearer cmd-secret'"},
        {
            "workspace": str(tmp_path), "agent_id": "work_M1_phase_A_v1",
            "agent_type": "work", "module_id": "M1", "phase_id": "phase_A",
            "clause_ids": ["5.6-1", "5.6-2"], "attempt": 2,
        },
    ))

    assert result.is_error is False
    receipts = list((tmp_path / "tool-receipts").glob("*.json"))
    assert len(receipts) == 1
    receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert receipt["module_id"] == "M1"
    assert receipt["phase_id"] == "phase_A"
    assert receipt["clause_ids"] == ["5.6-1", "5.6-2"]
    assert receipt["attempt"] == 2
    assert receipt["tool"]["params_preview"]["api_token"] == "[REDACTED]"
    assert "request-secret" not in receipts[0].read_text(encoding="utf-8")
    assert "response-secret" not in receipts[0].read_text(encoding="utf-8")
    assert "cmd-secret" not in receipts[0].read_text(encoding="utf-8")


def test_tool_registry_receipt_captures_unavailable_tool_as_error(tmp_path):
    registry = ToolRegistry()
    result = asyncio.run(registry.execute(
        "missing", {}, {"workspace": str(tmp_path), "clause_ids": ["5.6-1"]}
    ))

    assert result.is_error is True
    receipt = json.loads(next((tmp_path / "tool-receipts").glob("*.json")).read_text(encoding="utf-8"))
    assert receipt["result"]["is_error"] is True
    assert receipt["tool"]["name"] == "missing"


def test_execution_policy_confines_workspace_and_records_denial(tmp_path):
    workspace = tmp_path / "case"
    workspace.mkdir()
    (workspace / "ixit.json").write_text('{"ok": true}', encoding="utf-8")
    (workspace / "run_config.json").write_text('{"dut_ip": "10.0.0.8"}', encoding="utf-8")
    context = {"workspace": str(workspace), "clause_ids": ["5.6-1"]}
    registry = ToolRegistry()
    registry.register(STANDARD_TOOLS, BuiltinExecutors())

    read = asyncio.run(registry.execute("read_file", {"path": "ixit.json"}, context))
    escaped = asyncio.run(registry.execute("read_file", {"path": "../outside.txt"}, context))

    assert read.is_error is False
    assert '"ok": true' in read.content
    assert escaped.is_error is True
    # 按内容挑被拒绝的回执, 不依赖文件名排序 (Windows 时钟粒度下同 tick 时序不可靠)
    receipt = next(
        json.loads(path.read_text(encoding="utf-8"))
        for path in (workspace / "tool-receipts").glob("*.json")
        if json.loads(path.read_text(encoding="utf-8"))["policy"]["allowed"] is False
    )
    assert receipt["policy"]["code"] == "workspace_path_outside"


def test_execution_policy_allows_only_declared_dut_and_blocks_dangerous_python(tmp_path):
    workspace = tmp_path / "case"
    workspace.mkdir()
    (workspace / "run_config.json").write_text('{"dut_ip": "10.0.0.8"}', encoding="utf-8")
    (workspace / "environment_snapshot.json").write_text(
        '{"tools": {"nmap": {"version": "Nmap version 7.94"}}}', encoding="utf-8"
    )
    context = {"workspace": str(workspace), "clause_ids": ["5.6-1"]}
    registry = ToolRegistry()
    registry.register([ToolDef(name="bash", description="test", parameters=[])])
    calls = []

    async def bash(params):
        calls.append(params["command"])
        return "ok"

    registry.set_executor("bash", bash)
    allowed = asyncio.run(registry.execute("bash", {"command": "nmap -Pn 10.0.0.8"}, context))
    denied = asyncio.run(registry.execute("bash", {"command": "nmap -Pn 10.0.0.9"}, context))

    assert allowed.is_error is False
    assert denied.is_error is True
    assert calls == ["nmap -Pn 10.0.0.8"]
    nmap_receipt = next(
        json.loads(path.read_text(encoding="utf-8"))
        for path in (workspace / "tool-receipts").glob("*.json")
        if json.loads(path.read_text(encoding="utf-8"))["tool"]["params_preview"].get("command") == "nmap -Pn 10.0.0.8"
    )
    assert nmap_receipt["tool"]["executable_hint"] == "nmap"
    assert nmap_receipt["tool"]["environment_version"] == "Nmap version 7.94"

    registry.register([ToolDef(name="python_script", description="test", parameters=[])])
    blocked_python = asyncio.run(registry.execute("python_script", {"script": "import os; os.system('whoami')"}, context))
    assert blocked_python.is_error is True


def test_write_file_receipt_links_workspace_artifact(tmp_path):
    """成功写入的工作区文件要成为可复核的 receipt artifact 引用。"""
    workspace = tmp_path / "case"
    workspace.mkdir()
    context = {"workspace": str(workspace), "clause_ids": ["5.6-1"]}
    registry = ToolRegistry()
    registry.register(STANDARD_TOOLS, BuiltinExecutors())

    result = asyncio.run(registry.execute(
        "write_file", {"path": "artifacts/nmap_tcp.txt", "content": "scan output"}, context,
    ))

    assert result.is_error is False
    assert (workspace / "artifacts" / "nmap_tcp.txt").read_text(encoding="utf-8") == "scan output"
    receipt = next(
        json.loads(path.read_text(encoding="utf-8"))
        for path in (workspace / "tool-receipts").glob("*.json")
        if json.loads(path.read_text(encoding="utf-8"))["tool"]["name"] == "write_file"
    )
    assert receipt["artifact_refs"] == ["artifacts/nmap_tcp.txt"]
