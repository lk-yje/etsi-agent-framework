import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

from framework import reporting
from framework.reporting import build_report_data, create_evidence_zip, materialize_clause_pcap_slice, write_report_bundle


def _make_workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "case"
    (workspace / "evidence").mkdir(parents=True)
    fixture = Path(__file__).parent / "fixtures" / "sample_evidence.json"
    (workspace / "evidence" / "pre-M1-evidence.json").write_text(
        fixture.read_text(encoding="utf-8"), encoding="utf-8"
    )
    # Phase 文件是中间产物，报告与证据包均不得将其重复纳入。
    (workspace / "evidence" / "pre-M1-phase_A-evidence.json").write_text(
        fixture.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (workspace / "nmap_tcp.txt").write_text("80/tcp open http\n", encoding="utf-8")
    (workspace / "banner_http.txt").write_text("Server: nginx\n", encoding="utf-8")
    (workspace / "ixit.json").write_text(json.dumps({
        "meta": {"dut_identification": {"sample": {"model": "TestCam"}}},
        "ixit_tables": {
            "15-Intf": {"rows": [{"port": 80}]},
            "16-CodeMin": {"statement": "no debug banner"},
            "13-SoftServ": {"rows": [{"service": "http"}]},
        },
    }), encoding="utf-8")
    (workspace / "pipeline_state.json").write_text(
        json.dumps({"started_at": "2026-08-19T10:00:00", "current_state": "report"}),
        encoding="utf-8",
    )
    return workspace


def test_report_bundle_keeps_evidence_type_aware_and_shared_sources(tmp_path):
    workspace = _make_workspace(tmp_path)
    receipts = workspace / "tool-receipts"
    receipts.mkdir()
    (receipts / "phase-a.json").write_text(json.dumps({
        "tool": {"name": "bash"}, "module_id": "M1", "phase_id": "phase_A",
        "clause_ids": ["5.6-1", "5.6-2"], "result": {"is_error": False},
    }), encoding="utf-8")

    report = build_report_data(workspace)
    bundle = write_report_bundle(workspace, report)

    assert report["total_clauses"] == 3
    assert report["tool_receipt_count"] == 1
    assert (workspace / bundle["report_data"]).is_file()
    assert (workspace / bundle["markdown"]).is_file()
    assert (workspace / bundle["html"]).is_file()
    assert (workspace / "evidence-packages" / "5.6" / "5.6-1" / "clause.json").is_file()

    package_561 = json.loads((workspace / "evidence-packages" / "5.6" / "5.6-1" / "clause.json").read_text(encoding="utf-8"))
    package_562 = json.loads((workspace / "evidence-packages" / "5.6" / "5.6-2" / "clause.json").read_text(encoding="utf-8"))
    package_565 = json.loads((workspace / "evidence-packages" / "5.6" / "5.6-5" / "clause.json").read_text(encoding="utf-8"))

    # 5.6-1/5.6-5 共同引用同一个 nmap 原件；5.6-2 是 curl 原件；
    # IXIT 只抽取引用表，均不伪造 PCAP 或其他不存在的文件。
    nmap_561 = next(item for item in package_561["evidence_records"] if item.get("source") == "nmap_tcp.txt")
    nmap_565 = next(item for item in package_565["evidence_records"] if item.get("source") == "nmap_tcp.txt")
    curl_562 = next(item for item in package_562["evidence_records"] if item.get("source") == "banner_http.txt")
    assert nmap_561["sha256"] == nmap_565["sha256"]
    assert nmap_561["status"] in {"hardlink", "copy"}
    assert curl_562["status"] in {"hardlink", "copy"}
    assert any(item["kind"] == "ixit_excerpt" for item in package_561["evidence_records"])
    receipt = next(item for item in package_561["evidence_records"] if item["kind"] == "tool_receipt")
    assert receipt["scope"] == "phase"
    assert receipt["clause_ids"] == ["5.6-1", "5.6-2"]
    assert next(item for item in package_561["evidence_records"] if item["kind"] == "pcap_slice")["status"] == "no_capture"

    markdown = (workspace / bundle["markdown"]).read_text(encoding="utf-8")
    assert "任务编号：HCTL-20260819" in markdown
    assert "## 2. 阶段 3.1 流量采集取证" not in markdown
    assert "## 5. 逐条款检测结果" in markdown
    assert "evidence-packages/5.6/5.6-1" in markdown
    assert "以环境快照和各条款 evidence receipt 为准" in markdown


def test_evidence_zip_supports_clause_group_and_all_scopes(tmp_path):
    workspace = _make_workspace(tmp_path)
    write_report_bundle(workspace)

    clause_zip = create_evidence_zip(workspace, "clause", "5.6-1")
    group_zip = create_evidence_zip(workspace, "group", "5.6")
    all_zip = create_evidence_zip(workspace, "all")

    with zipfile.ZipFile(clause_zip) as archive:
        assert "evidence-packages/5.6/5.6-1/clause.json" in archive.namelist()
        assert "evidence-packages/5.6/5.6-2/clause.json" not in archive.namelist()
    with zipfile.ZipFile(group_zip) as archive:
        assert "evidence-packages/5.6/5.6-2/clause.json" in archive.namelist()
    with zipfile.ZipFile(all_zip) as archive:
        assert "evidence-packages/manifest.json" in archive.namelist()


def test_pcap_is_sliced_only_when_analysis_has_explicit_frame_indexes(tmp_path, monkeypatch):
    workspace = _make_workspace(tmp_path)
    (workspace / "capture.pcap").write_bytes(b"pcap-placeholder")
    analysis = workspace / "pcap_analysis"
    analysis.mkdir()
    (analysis / "_index.json").write_text(json.dumps({"queries": {
        "tls_561": {"clause": "5.6-1", "file": "tls_561.json"},
    }}), encoding="utf-8")
    (analysis / "tls_561.json").write_text(json.dumps({
        "command_fields": ["frame.number", "tls.version"],
        "result": {"data": [[12, "0x0304"], [18, "0x0304"]]},
    }), encoding="utf-8")
    write_report_bundle(workspace)

    class FakeResolver:
        def get_tool_path(self, name):
            return "C:/tools/tshark.exe" if name == "tshark" else None

    captured = {}

    def fake_run(command, **_kwargs):
        captured["command"] = command
        Path(command[-1]).write_bytes(b"derived-pcap")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(reporting, "PathResolver", FakeResolver)
    monkeypatch.setattr(reporting.subprocess, "run", fake_run)
    outcome = materialize_clause_pcap_slice(workspace, "5.6-1")

    assert outcome["status"] == "generated"
    assert "frame.number == 12" in captured["command"][4]
    assert (workspace / "evidence-packages" / "5.6" / "5.6-1" / "evidence" / "pcap_slice.pcapng").is_file()
