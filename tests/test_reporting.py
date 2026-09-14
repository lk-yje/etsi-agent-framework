import json
import zipfile
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from framework import reporting
from framework.reporting import build_report_data, create_evidence_zip, materialize_clause_pcap_slice, write_report_bundle
from contracts.traffic_intelligence import TrafficCaptureManifest
from framework.traffic_intelligence.bundle_store import TrafficIntelligenceBundleWriter


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


def test_report_includes_verified_traffic_intelligence_without_payload_or_step_labels(tmp_path):
    workspace = _make_workspace(tmp_path)
    capture = b"fixture"
    (workspace / "capture.pcap").write_bytes(capture)
    manifest = TrafficCaptureManifest(
        capture_sha256=hashlib.sha256(capture).hexdigest(),
        capture_size=len(capture),
        capture_format="pcap",
        analysis_backend="direct_tshark",
        analysis_started_at=datetime.now(timezone.utc),
    )
    mismatch = {
        "alignment_id": "alignment-test",
        "declaration_id": "decl-test",
        "flow_ids": ["flow-test"],
        "overall": "MISMATCH",
        "dimensions": {"port": "MISMATCH", "encryption": "MATCH"},
        "reason": "port differs",
        "frame_refs": [7],
        "confidence": 0.95,
    }
    with TrafficIntelligenceBundleWriter(workspace, manifest) as writer:
        writer.write_json("inventory.json", {
            "flow_count": 1,
            "endpoint_count": 2,
            "unknown_cluster_count": 0,
            "declaration_count": 1,
            "alignment_counts": {"MISMATCH": 1},
        })
        writer.write_json("summary-for-ai.json", {
            "encryption_counts": {"STANDARD_ENCRYPTION_CONFIRMED": 1},
        })
        writer.write_json("declaration-alignments.json", [mismatch])
        writer.write_json("unknown-protocol-clusters.json", [])
        writer.write_json("automatic-activity-windows.json", [])
        writer.write_json("dns-correlations.json", [])
        writer.commit()
    (workspace / "traffic_state.json").write_text(json.dumps({
        "status": "COMPLETE",
        "operation_mode": "continuous_unlabelled",
        "attempt_id": "traffic-test",
        "capture_pcap": "capture.pcap",
        "checklist": [],
    }), encoding="utf-8")

    report = build_report_data(workspace)
    bundle = write_report_bundle(workspace, report)
    markdown = (workspace / bundle["markdown"]).read_text(encoding="utf-8")
    archived_html = (workspace / bundle["html"]).read_text(encoding="utf-8")

    assert report["traffic_intelligence"]["status"] == "complete"
    assert report["traffic_intelligence"]["mismatches"][0]["flow_ids"] == ["flow-test"]
    assert report["traffic_intelligence"]["payload_included"] is False
    assert "Traffic Intelligence 结构化分析" in markdown
    assert "continuous_unlabelled" in markdown
    assert "操作项" not in markdown
    assert "flow-test" in archived_html
    assert "Payload" not in archived_html


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


def test_pcap_slice_prefers_verified_structured_traffic_refs_over_legacy_index(tmp_path):
    workspace = _make_workspace(tmp_path)
    capture = b"pcap-placeholder"
    (workspace / "capture.pcap").write_bytes(capture)

    evidence_path = workspace / "evidence" / "pre-M1-evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["clauses"][0]["evidence"].append({
        "type": "traffic_intelligence",
        "path": None,
        "level": "L1",
        "description": "Traffic Intelligence Flow flow-primary 的代表帧已核验",
        "flowIds": ["flow-primary"],
        "frameNumbers": [8],
    })
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    analysis = workspace / "pcap_analysis"
    analysis.mkdir()
    (analysis / "_index.json").write_text(json.dumps({"queries": {
        "legacy_561": {"clause": "5.6-1", "file": "legacy_561.json"},
    }}), encoding="utf-8")
    (analysis / "legacy_561.json").write_text(json.dumps({
        "command_fields": ["frame.number"], "result": {"data": [[99]]},
    }), encoding="utf-8")

    manifest = TrafficCaptureManifest(
        capture_sha256=hashlib.sha256(capture).hexdigest(),
        capture_size=len(capture),
        capture_format="pcap",
        analysis_backend="direct_tshark",
        analysis_started_at=datetime.now(timezone.utc),
    )
    with TrafficIntelligenceBundleWriter(workspace, manifest) as writer:
        writer.write_json("inventory.json", {})
        writer.write_json("summary-for-ai.json", {})
        writer.write_json("declaration-alignments.json", [])
        writer.write_json("unknown-protocol-clusters.json", [])
        writer.write_json("automatic-activity-windows.json", [])
        writer.write_json("dns-correlations.json", [])
        writer.write_jsonl("flows.jsonl", [{
            "flow_id": "flow-primary", "frame_refs": [7, 8],
        }])
        writer.write_jsonl("frames.jsonl", [
            {"frame_number": 7, "flow_id": "flow-primary"},
            {"frame_number": 8, "flow_id": "flow-primary"},
        ])
        writer.commit()

    write_report_bundle(workspace)
    evidence_dir = workspace / "evidence-packages" / "5.6" / "5.6-1" / "evidence"
    request = json.loads((evidence_dir / "pcap_slice_request.json").read_text(encoding="utf-8"))
    refs = json.loads((evidence_dir / "traffic_intelligence_refs.json").read_text(encoding="utf-8"))

    assert request["status"] == "ready_for_tshark_slice"
    assert request["reference_source"] == "traffic_intelligence"
    assert request["flow_ids"] == ["flow-primary"]
    assert request["frame_numbers"] == [7, 8]
    assert 99 not in request["frame_numbers"]
    assert refs["status"] == "ready"
    assert refs["payload_included"] is False


def test_traffic_intelligence_slice_rejects_capture_changed_after_report(tmp_path, monkeypatch):
    workspace = _make_workspace(tmp_path)
    capture = b"original-capture"
    capture_path = workspace / "inputs" / "capture.pcap"
    capture_path.parent.mkdir()
    capture_path.write_bytes(capture)
    evidence_path = workspace / "evidence" / "pre-M1-evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["clauses"][0]["evidence"].append({
        "type": "traffic_intelligence",
        "level": "L1",
        "description": "Traffic Intelligence Flow 已绑定原始抓包哈希和帧引用",
        "flowIds": ["flow-bound"],
    })
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    manifest = TrafficCaptureManifest(
        capture_sha256=hashlib.sha256(capture).hexdigest(),
        capture_size=len(capture),
        capture_format="pcap",
        capture_artifact="inputs/capture.pcap",
        analysis_backend="direct_tshark",
        analysis_started_at=datetime.now(timezone.utc),
    )
    with TrafficIntelligenceBundleWriter(
        workspace, manifest, capture_path=capture_path
    ) as writer:
        writer.write_json("inventory.json", {})
        writer.write_json("summary-for-ai.json", {})
        writer.write_json("declaration-alignments.json", [])
        writer.write_json("unknown-protocol-clusters.json", [])
        writer.write_json("automatic-activity-windows.json", [])
        writer.write_json("dns-correlations.json", [])
        writer.write_jsonl("flows.jsonl", [{
            "flow_id": "flow-bound", "frame_refs": [7],
        }])
        writer.commit()
    write_report_bundle(workspace)

    request_path = (
        workspace / "evidence-packages" / "5.6" / "5.6-1" /
        "evidence" / "pcap_slice_request.json"
    )
    request = json.loads(request_path.read_text(encoding="utf-8"))
    assert request["source_pcap"] == "inputs/capture.pcap"
    capture_path.write_bytes(b"changed-capture")

    def unexpected_run(*_args, **_kwargs):
        raise AssertionError("capture hash 不一致时不得调用 tshark")

    monkeypatch.setattr(reporting.subprocess, "run", unexpected_run)
    outcome = materialize_clause_pcap_slice(workspace, "5.6-1")

    assert outcome["status"] == "capture_hash_mismatch"
    assert not (
        workspace / "evidence-packages" / "5.6" / "5.6-1" / "evidence" / "pcap_slice.pcapng"
    ).exists()
