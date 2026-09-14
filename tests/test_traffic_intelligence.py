"""Traffic Intelligence 合约、稳定 ID 和 Bundle 完整性测试。"""

from __future__ import annotations

import hashlib
import csv
import json
import asyncio
import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from contracts.traffic_intelligence import (
    AlignmentStatus,
    DeclarationAlignment,
    EncryptionAssessment,
    EncryptionClassification,
    FlowDirection,
    ObservedFlow,
    ObservedFrame,
    ProtocolBasis,
    ProtocolBasisType,
    ProtocolCandidate,
    ProtocolCandidateStatus,
    TrafficCaptureManifest,
    TrafficDeclaration,
    TrafficDeclarationSource,
)
from framework.traffic_intelligence.bundle_store import (
    BundleIntegrityError,
    TrafficIntelligenceBundleStore,
    TrafficIntelligenceBundleWriter,
)
from framework.traffic_intelligence.backends.base import (
    AnalysisBackend,
    BackendExecutionError,
    BackendRequest,
    BackendResult,
)
from framework.traffic_intelligence.backend_benchmark import (
    compare_snapshots,
    evaluate_candidate,
    run_backend_benchmark,
)
from framework.traffic_intelligence.backends.direct_tshark import DirectTsharkBackend
from framework.traffic_intelligence.backends.easytshark_batch import EasyTsharkBatchBackend
from framework.traffic_intelligence.backends import easytshark_batch as easytshark_module
from framework.traffic_intelligence.pipeline import (
    TrafficIntelligencePipeline,
    TrafficIntelligenceSettings,
)
from framework.traffic_intelligence.agent_tools import (
    TRAFFIC_INTELLIGENCE_CATEGORY,
    build_traffic_intelligence_registry,
)
from framework.execution_policy import ToolExecutionPolicy
from framework.tools import ToolRegistry
from framework.traffic_intelligence.payload_profiler import IncrementalPayloadProfiler
from framework.traffic_intelligence.encryption_classifier import classify_encryption
from framework.traffic_intelligence.declaration_extractor import (
    extract_traffic_declarations,
)
from framework.traffic_intelligence.declaration_matcher import align_traffic_declarations
from framework.traffic_intelligence.decode_as import DecodeAsError, DecodeAsRunner
from framework.traffic_intelligence.activity_segmenter import AutomaticActivitySegmenter
from framework.traffic_intelligence.dns_correlator import DnsCorrelationIndex
from framework.traffic_intelligence.protocol_profiler import build_unknown_protocol_clusters
from framework.traffic_intelligence.flow_ids import (
    canonical_flow_key,
    stable_flow_id,
    stable_unknown_cluster_id,
)


def _manifest(capture: bytes, *, backend: str = "direct_tshark") -> TrafficCaptureManifest:
    return TrafficCaptureManifest(
        capture_sha256=hashlib.sha256(capture).hexdigest(),
        capture_size=len(capture),
        capture_format="pcap",
        dut_addresses=["192.0.2.10"],
        requested_backend="auto",
        analysis_backend=backend,
        backend_version="test",
        tshark_version="test",
        analysis_started_at=datetime.now(timezone.utc),
    )


def test_synthetic_pcap_fixture_matches_payload_free_golden_contract():
    fixture_root = Path(__file__).parent / "fixtures" / "traffic_intelligence"
    capture = bytes.fromhex(
        (fixture_root / "minimal_tcp_handshake.pcap.hex").read_text(encoding="ascii")
    )
    expected = json.loads(
        (fixture_root / "minimal_tcp_handshake.expected.json").read_text(encoding="utf-8")
    )

    magic, major, minor, _zone, _sigfigs, _snaplen, linktype = struct.unpack(
        "<IHHIIII", capture[:24]
    )
    assert (magic, major, minor, linktype) == (0xA1B2C3D4, 2, 4, expected["linktype"])
    assert hashlib.sha256(capture).hexdigest() == expected["capture_sha256"]

    rows = []
    offset = 24
    while offset < len(capture):
        seconds, microseconds, included_length, original_length = struct.unpack(
            "<IIII", capture[offset:offset + 16]
        )
        packet = capture[offset + 16:offset + 16 + included_length]
        assert len(packet) == included_length == original_length
        ip_header = packet[14:34]
        tcp_header = packet[34:54]
        rows.append({
            "frame_number": len(rows) + 1,
            "timestamp_epoch": seconds + microseconds / 1_000_000,
            "src_ip": ".".join(str(value) for value in ip_header[12:16]),
            "src_port": struct.unpack("!H", tcp_header[:2])[0],
            "dst_ip": ".".join(str(value) for value in ip_header[16:20]),
            "dst_port": struct.unpack("!H", tcp_header[2:4])[0],
            "tcp_flags": tcp_header[13],
        })
        offset += 16 + included_length

    assert rows == expected["packets"]
    assert expected["flow"]["frame_count"] == len(rows)
    assert expected["flow"]["payload_bytes"] == 0


class _BenchmarkBackend(AnalysisBackend):
    def __init__(self, name: str, frame_numbers: list[int], flow_ids: list[str]) -> None:
        self.name = name
        self._frame_numbers = frame_numbers
        self._flow_ids = flow_ids

    def availability(self) -> tuple[bool, str]:
        return True, "fixture"

    def analyze(self, request: BackendRequest) -> BackendResult:
        request.output_dir.mkdir(parents=True, exist_ok=True)
        frames = request.output_dir / "frames.jsonl"
        flows = request.output_dir / "flows.jsonl"
        observations = request.output_dir / "non-session-observations.jsonl"
        frames.write_text("".join(json.dumps({"frame_number": value, "protocol_stack": ["eth", "ip"]}) + "\n" for value in self._frame_numbers), encoding="utf-8")
        flows.write_text("".join(json.dumps({"flow_id": value}) + "\n" for value in self._flow_ids), encoding="utf-8")
        observations.write_text("", encoding="utf-8")
        return BackendResult(self.name, "fixture", "fixture", frames, flows, observations, frame_count=len(self._frame_numbers), flow_count=len(self._flow_ids))


def test_backend_benchmark_compares_coverage_without_exposing_indexes(tmp_path):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"synthetic")
    report_path, report = run_backend_benchmark(
        workspace=tmp_path,
        capture_path=capture,
        tshark_path="fixture-tshark",
        baseline=_BenchmarkBackend("direct_tshark", [1, 2], ["flow-a", "flow-b"]),
        candidate=_BenchmarkBackend("easytshark_batch", [1], ["flow-a"]),
    )
    assert report_path.is_file()
    assert report["comparison"]["frame_coverage_vs_baseline"] == 0.5
    assert report["comparison"]["flow_coverage_vs_baseline"] == 0.5
    assert report["decision"]["status"] == "REJECT"
    assert "frame_numbers" not in report["baseline"]
    assert "flow_ids" not in report["candidate"]
    assert report["safety"]["raw_payload_in_report"] is False


def test_backend_benchmark_decision_never_promotes_candidate_automatically():
    decision = evaluate_candidate({
        "frame_coverage_vs_baseline": 1.0,
        "flow_coverage_vs_baseline": 1.0,
        "protocol_field_retention_vs_baseline": 1.0,
    })
    assert decision["status"] == "REVIEW_REQUIRED"
    assert decision["automatic_selection_changed"] is False


def test_flow_id_is_bidirectional_and_stream_sensitive():
    forward = stable_flow_id("tcp", "192.0.2.10", 51000, "198.51.100.8", 443, stream_id=7)
    reverse = stable_flow_id("TCP", "198.51.100.8", 443, "192.0.2.10", 51000, stream_id=7)
    other_stream = stable_flow_id(
        "TCP", "192.0.2.10", 51000, "198.51.100.8", 443, stream_id=8
    )

    assert forward == reverse
    assert forward != other_stream
    assert canonical_flow_key(
        "tcp", "192.0.2.10", 51000, "198.51.100.8", 443, stream_id=7
    ) == canonical_flow_key(
        "tcp", "198.51.100.8", 443, "192.0.2.10", 51000, stream_id=7
    )


def test_unknown_cluster_id_is_order_independent_and_rejects_payload_bytes():
    left = stable_unknown_cluster_id("tcp", {"entropy_bucket": 7, "ports": [443, 8443]})
    right = stable_unknown_cluster_id("TCP", {"ports": [443, 8443], "entropy_bucket": 7})

    assert left == right
    with pytest.raises(TypeError, match="Payload"):
        stable_unknown_cluster_id("tcp", {"payload": b"secret"})


def test_confirmed_protocol_requires_deterministic_basis():
    with pytest.raises(ValidationError, match="确定性"):
        ProtocolCandidate(
            name="vendor-private",
            confidence=0.99,
            status=ProtocolCandidateStatus.CONFIRMED,
            basis=[ProtocolBasis(type=ProtocolBasisType.AI_HYPOTHESIS, value="looks familiar")],
        )

    candidate = ProtocolCandidate(
        name="TLS",
        confidence=0.99,
        status=ProtocolCandidateStatus.CONFIRMED,
        basis=[
            ProtocolBasis(
                type=ProtocolBasisType.TSHARK_DISSECTOR,
                value="tls",
                frame_number=3,
            )
        ],
    )
    assert candidate.name == "TLS"


def test_flow_contract_validates_ip_frame_range_and_nested_flow_id():
    with pytest.raises(ValidationError):
        ObservedFlow(
            flow_id="flow-test",
            transport="TCP",
            ip_version=4,
            src_ip="not-an-ip",
            src_port=1,
            dst_ip="198.51.100.8",
            dst_port=443,
            first_frame=10,
            last_frame=2,
            frame_count=1,
        )


def test_undeclared_alignment_cannot_bind_a_declaration():
    with pytest.raises(ValidationError):
        DeclarationAlignment(
            alignment_id="alignment-1",
            declaration_id="decl-1",
            overall=AlignmentStatus.UNDECLARED_OBSERVED,
            reason="observed but not declared",
            confidence=1.0,
        )


def test_bundle_writer_commits_and_store_verifies(tmp_path):
    capture = b"synthetic pcap placeholder"
    capture_path = tmp_path / "capture.pcap"
    capture_path.write_bytes(capture)

    with TrafficIntelligenceBundleWriter(tmp_path, _manifest(capture)) as writer:
        writer.write_json("inventory.json", {"flow_count": 1})
        writer.write_jsonl("flows.jsonl", [{"flow_id": "flow-1"}])
        output = writer.commit()

    assert output == tmp_path / "traffic-intelligence"
    store = TrafficIntelligenceBundleStore(tmp_path)
    manifest = store.load_manifest(capture_path=capture_path)
    assert manifest.complete is True
    assert [item.path for item in manifest.artifacts] == ["flows.jsonl", "inventory.json"]
    assert store.read_json("inventory.json") == {"flow_count": 1}
    assert list(store.iter_jsonl("flows.jsonl")) == [{"flow_id": "flow-1"}]


def test_bundle_tamper_is_detected(tmp_path):
    capture = b"synthetic pcap placeholder"
    capture_path = tmp_path / "capture.pcap"
    capture_path.write_bytes(capture)
    with TrafficIntelligenceBundleWriter(tmp_path, _manifest(capture)) as writer:
        writer.write_json("inventory.json", {"flow_count": 1})
        writer.commit()

    (tmp_path / "traffic-intelligence" / "inventory.json").write_text(
        '{"flow_count":2}\n', encoding="utf-8"
    )
    with pytest.raises(BundleIntegrityError, match="不一致"):
        TrafficIntelligenceBundleStore(tmp_path).load_manifest()


def test_bundle_rejects_undeclared_files(tmp_path):
    capture = b"synthetic pcap placeholder"
    (tmp_path / "capture.pcap").write_bytes(capture)
    with TrafficIntelligenceBundleWriter(tmp_path, _manifest(capture)) as writer:
        writer.write_json("inventory.json", {"flow_count": 0})
        writer.commit()

    (tmp_path / "traffic-intelligence" / "untracked.json").write_text(
        "{}\n", encoding="utf-8"
    )
    with pytest.raises(BundleIntegrityError, match="未在 manifest 声明"):
        TrafficIntelligenceBundleStore(tmp_path).load_manifest()


def test_failed_rebuild_preserves_previous_bundle(tmp_path):
    capture = b"synthetic pcap placeholder"
    (tmp_path / "capture.pcap").write_bytes(capture)
    with TrafficIntelligenceBundleWriter(tmp_path, _manifest(capture)) as first:
        first.write_json("inventory.json", {"generation": 1})
        first.commit()

    with pytest.raises(RuntimeError, match="simulated"):
        with TrafficIntelligenceBundleWriter(tmp_path, _manifest(capture)) as second:
            second.write_json("inventory.json", {"generation": 2})
            raise RuntimeError("simulated failure before commit")

    store = TrafficIntelligenceBundleStore(tmp_path)
    assert store.read_json("inventory.json") == {"generation": 1}
    assert not list(tmp_path.glob(".traffic-intelligence.staging-*"))


def test_bundle_rejects_absolute_and_parent_paths(tmp_path):
    capture = b"synthetic pcap placeholder"
    (tmp_path / "capture.pcap").write_bytes(capture)
    with TrafficIntelligenceBundleWriter(tmp_path, _manifest(capture)) as writer:
        with pytest.raises(ValueError):
            writer.write_json("../escape.json", {})
        with pytest.raises(ValueError):
            writer.write_json("C:/escape.json", {})


def test_backend_request_enforces_workspace_boundary(tmp_path):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"fixture")
    with pytest.raises(ValueError, match="output_dir"):
        BackendRequest(
            workspace=tmp_path,
            capture_path=capture,
            output_dir=tmp_path.parent / "outside-output",
            tshark_path="tshark",
        )


def test_direct_tshark_backend_normalizes_frames_flows_and_non_sessions(
    tmp_path, monkeypatch
):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"synthetic fixture")
    output = tmp_path / "backend-staging"
    request = BackendRequest(
        workspace=tmp_path,
        capture_path=capture,
        output_dir=output,
        tshark_path="fixture-tshark",
        dut_addresses=("192.0.2.10",),
    )
    backend = DirectTsharkBackend("fixture-tshark")
    fields = {
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "frame.protocols",
        "_ws.col.Protocol",
        "eth.src",
        "eth.dst",
        "ip.version",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "tcp.flags",
        "tls.handshake.type",
        "tls.handshake.extensions_server_name",
        "tls.handshake.extensions.supported_version",
        "tls.handshake.ciphersuite",
    }
    monkeypatch.setattr(backend, "availability", lambda: (True, "TShark fixture"))
    monkeypatch.setattr(backend, "_available_fields", lambda _request: fields)

    rows = [
        {
            "frame.number": "1",
            "frame.time_epoch": "1000.0",
            "frame.len": "100",
            "frame.protocols": "eth:ip:tcp:tls",
            "_ws.col.Protocol": "TLS",
            "eth.src": "00:00:5e:00:53:01",
            "eth.dst": "00:00:5e:00:53:02",
            "ip.version": "4",
            "ip.src": "192.0.2.10",
            "ip.dst": "198.51.100.8",
            "tcp.srcport": "51000",
            "tcp.dstport": "443",
            "tcp.stream": "0",
            "tcp.flags": "0x0002",
            "tls.handshake.type": "1",
            "tls.handshake.extensions_server_name": "cloud.example.test",
        },
        {
            "frame.number": "2",
            "frame.time_epoch": "1000.25",
            "frame.len": "120",
            "frame.protocols": "eth:ip:tcp:tls",
            "_ws.col.Protocol": "TLS",
            "eth.src": "00:00:5e:00:53:02",
            "eth.dst": "00:00:5e:00:53:01",
            "ip.version": "4",
            "ip.src": "198.51.100.8",
            "ip.dst": "192.0.2.10",
            "tcp.srcport": "443",
            "tcp.dstport": "51000",
            "tcp.stream": "0",
            "tcp.flags": "0x0012",
            "tls.handshake.type": "2",
            "tls.handshake.extensions.supported_version": "0x0304",
            "tls.handshake.ciphersuite": "0x1301",
        },
        {
            "frame.number": "3",
            "frame.time_epoch": "1001.0",
            "frame.len": "42",
            "frame.protocols": "eth:ethertype:arp",
            "_ws.col.Protocol": "ARP",
            "eth.src": "00:00:5e:00:53:01",
            "eth.dst": "ff:ff:ff:ff:ff:ff",
        },
    ]

    def fake_run(_args, output_path, stderr_path, _timeout):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        ordered_fields = [name for name in fields]
        with output_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=ordered_fields, delimiter="\t")
            writer.writeheader()
            writer.writerows(rows)
        stderr_path.write_text("", encoding="utf-8")

    monkeypatch.setattr(backend, "_run_to_file", fake_run)
    # analyze 会基于 request path 创建一个同配置实例做版本探测。
    monkeypatch.setattr(DirectTsharkBackend, "availability", lambda _self: (True, "TShark fixture"))

    result = backend.analyze(request)

    assert result.frame_count == 3
    assert result.flow_count == 1
    flow_data = json.loads(result.flow_index_path.read_text(encoding="utf-8").splitlines()[0])
    assert flow_data["direction_relative_to_dut"] == "OUTBOUND"
    assert flow_data["bytes_src_to_dst"] == 100
    assert flow_data["bytes_dst_to_src"] == 120
    assert flow_data["encryption"]["classification"] == "STANDARD_ENCRYPTION_CONFIRMED"
    assert flow_data["sni"] == ["cloud.example.test"]
    observations = result.non_session_observations_path.read_text(encoding="utf-8").splitlines()
    assert len(observations) == 1


def test_pipeline_builds_valid_backend_independent_bundle(tmp_path, monkeypatch):
    capture = b"synthetic fixture"
    capture_path = tmp_path / "capture.pcap"
    capture_path.write_bytes(capture)
    (tmp_path / "ixit.json").write_text(json.dumps({
        "ics": [],
        "ixit_tables": {
            "11-ComMech": {
                "rows": [{
                    "ID": "ComMech-HTTPS (client)",
                    "Description": "The DUT acts as a client for the declared cloud service.",
                    "Protocol": "HTTPS",
                    "Transport": "TCP",
                    "Remote Port": 443,
                    "Remote Host": "cloud.example.test",
                }],
            },
            "15-Intf": {"rows": []},
        },
    }), encoding="utf-8")

    def fake_analyze(_backend, request):
        request.output_dir.mkdir(parents=True, exist_ok=True)
        flow_id = stable_flow_id(
            "TCP", "192.0.2.10", 51000, "198.51.100.8", 443, stream_id=0
        )
        frames = [
            ObservedFrame(
                frame_number=1,
                flow_id=flow_id,
                timestamp_epoch=1000.0,
                frame_length=100,
                src_address="192.0.2.10",
                dst_address="198.51.100.8",
                src_port=51000,
                dst_port=443,
                transport="TCP",
                stream_id=0,
                protocol_stack=["eth", "ip", "tcp", "tls"],
                displayed_protocol="TLS",
                sni=["cloud.example.test"],
            ),
            ObservedFrame(
                frame_number=2,
                flow_id=flow_id,
                timestamp_epoch=1000.5,
                frame_length=120,
                src_address="198.51.100.8",
                dst_address="192.0.2.10",
                src_port=443,
                dst_port=51000,
                transport="TCP",
                stream_id=0,
                protocol_stack=["eth", "ip", "tcp", "tls"],
                displayed_protocol="TLS",
            ),
        ]
        candidate = ProtocolCandidate(
            name="TLS",
            confidence=1.0,
            status=ProtocolCandidateStatus.CONFIRMED,
            basis=[
                ProtocolBasis(
                    type=ProtocolBasisType.TSHARK_DISSECTOR,
                    value="tls",
                    frame_number=1,
                )
            ],
        )
        flow = ObservedFlow(
            flow_id=flow_id,
            transport="TCP",
            ip_version=4,
            src_ip="192.0.2.10",
            src_port=51000,
            dst_ip="198.51.100.8",
            dst_port=443,
            direction_relative_to_dut=FlowDirection.OUTBOUND,
            first_frame=1,
            last_frame=2,
            frame_count=2,
            bytes_src_to_dst=100,
            bytes_dst_to_src=120,
            duration_ms=500,
            stream_id=0,
            sni=["cloud.example.test"],
            protocol_candidates=[candidate],
            encryption=EncryptionAssessment(
                flow_id=flow_id,
                classification=EncryptionClassification.STANDARD_ENCRYPTION_CONFIRMED,
                confidence=1.0,
                basis=["fixture"],
                security_protocol="TLS",
                frame_refs=[1, 2],
            ),
            frame_refs=[1, 2],
        )
        frame_path = request.output_dir / "frames.jsonl"
        flow_path = request.output_dir / "flows.jsonl"
        observation_path = request.output_dir / "non-session-observations.jsonl"
        frame_path.write_text(
            "".join(item.model_dump_json() + "\n" for item in frames), encoding="utf-8"
        )
        flow_path.write_text(flow.model_dump_json() + "\n", encoding="utf-8")
        observation_path.write_text("", encoding="utf-8")
        return BackendResult(
            backend_name="direct_tshark",
            backend_version="fixture-1",
            tshark_version="fixture-tshark",
            frame_index_path=frame_path,
            flow_index_path=flow_path,
            non_session_observations_path=observation_path,
            frame_count=2,
            flow_count=1,
        )

    monkeypatch.setattr(DirectTsharkBackend, "analyze", fake_analyze)
    result = TrafficIntelligencePipeline().run(
        tmp_path,
        capture_path=capture_path,
        dut_addresses=["192.0.2.10"],
        tshark_path="fixture-tshark",
    )

    assert result.frame_count == 2
    assert result.flow_count == 1
    assert result.manifest.analysis_backend == "direct_tshark"
    assert result.manifest.capture_started_at == datetime.fromtimestamp(1000.0, timezone.utc)
    store = TrafficIntelligenceBundleStore(tmp_path)
    assert store.read_json("inventory.json")["flow_count"] == 1
    assert store.read_json("inventory.json")["declaration_count"] == 1
    assert store.read_json("summary-for-ai.json")["protocol_counts"] == {"TLS": 1}
    [alignment] = store.read_json("declaration-alignments.json")
    assert alignment["overall"] == "MATCH"
    assert alignment["dimensions"]["remote_target"] == "MATCH"
    assert list(store.iter_jsonl("flow-frame-index.jsonl")) == [
        {"flow_id": stable_flow_id(
            "TCP", "192.0.2.10", 51000, "198.51.100.8", 443, stream_id=0
        ), "frame_number": 1},
        {"flow_id": stable_flow_id(
            "TCP", "192.0.2.10", 51000, "198.51.100.8", 443, stream_id=0
        ), "frame_number": 2},
    ]


def test_explicit_easytshark_without_worker_records_direct_fallback(tmp_path, monkeypatch):
    capture_path = tmp_path / "capture.pcap"
    capture_path.write_bytes(b"fixture")

    def fake_analyze(_backend, request):
        request.output_dir.mkdir(parents=True, exist_ok=True)
        frames = request.output_dir / "frames.jsonl"
        flows = request.output_dir / "flows.jsonl"
        observations = request.output_dir / "non-session-observations.jsonl"
        frames.write_text("", encoding="utf-8")
        flows.write_text("", encoding="utf-8")
        observations.write_text("", encoding="utf-8")
        return BackendResult(
            backend_name="direct_tshark",
            backend_version="fixture",
            tshark_version="fixture",
            frame_index_path=frames,
            flow_index_path=flows,
            non_session_observations_path=observations,
        )

    monkeypatch.setattr(DirectTsharkBackend, "analyze", fake_analyze)
    settings = TrafficIntelligenceSettings(backend="easytshark_batch", easytshark_path=None)
    result = TrafficIntelligencePipeline(settings).run(tmp_path, tshark_path="fixture-tshark")

    assert result.manifest.analysis_backend == "direct_tshark"
    assert "未配置" in result.manifest.fallback_reason


def test_easytshark_worker_contract_is_offline_and_payload_free(tmp_path, monkeypatch):
    capture_path = tmp_path / "capture.pcap"
    capture_path.write_bytes(b"fixture")
    output_dir = tmp_path / "worker-output"
    request = BackendRequest(
        workspace=tmp_path,
        capture_path=capture_path,
        output_dir=output_dir,
        tshark_path="fixture-tshark",
        timeout_seconds=30,
    )
    backend = EasyTsharkBatchBackend("fixture-easytshark")
    monkeypatch.setattr(backend, "availability", lambda: (True, "EasyTshark fixture"))
    invoked = {}

    class FakeProcess:
        returncode = 0

        def wait(self, timeout):
            invoked["timeout"] = timeout

    def fake_popen(command, **kwargs):
        invoked["command"] = command
        invoked["kwargs"] = kwargs
        worker_output = Path(command[command.index("--output") + 1])
        (worker_output / "manifest.json").write_text(
            json.dumps({
                "complete": True,
                "backend_version": "fixture-1",
                "tshark_version": "fixture-tshark",
            }),
            encoding="utf-8",
        )
        (worker_output / "frames.jsonl").write_text("", encoding="utf-8")
        (worker_output / "flows.jsonl").write_text("", encoding="utf-8")
        return FakeProcess()

    monkeypatch.setattr(easytshark_module.subprocess, "Popen", fake_popen)
    result = backend.analyze(request)

    assert result.backend_name == "easytshark_batch"
    assert "--no-network" in invoked["command"]
    assert "--no-raw-payload" in invoked["command"]
    assert invoked["kwargs"]["shell"] is False
    assert invoked["timeout"] == 30
    assert not list(output_dir.glob(".worker-*"))


def test_easytshark_worker_failure_cleans_output_and_falls_back(tmp_path, monkeypatch):
    capture_path = tmp_path / "capture.pcap"
    capture_path.write_bytes(b"fixture")

    def fail_worker(_backend, request):
        request.output_dir.mkdir(parents=True, exist_ok=True)
        (request.output_dir / "partial.sqlite").write_bytes(b"partial")
        raise BackendExecutionError("fixture worker failed")

    def direct_fallback(_backend, request):
        request.output_dir.mkdir(parents=True, exist_ok=True)
        frames = request.output_dir / "frames.jsonl"
        flows = request.output_dir / "flows.jsonl"
        observations = request.output_dir / "non-session-observations.jsonl"
        frames.write_text("", encoding="utf-8")
        flows.write_text("", encoding="utf-8")
        observations.write_text("", encoding="utf-8")
        return BackendResult(
            backend_name="direct_tshark",
            backend_version="fixture",
            tshark_version="fixture",
            frame_index_path=frames,
            flow_index_path=flows,
            non_session_observations_path=observations,
        )

    monkeypatch.setattr(EasyTsharkBatchBackend, "analyze", fail_worker)
    monkeypatch.setattr(DirectTsharkBackend, "analyze", direct_fallback)
    settings = TrafficIntelligenceSettings(
        backend="easytshark_batch",
        easytshark_path="fixture-easytshark",
    )
    result = TrafficIntelligencePipeline(settings).run(
        tmp_path,
        capture_path=capture_path,
        tshark_path="fixture-tshark",
    )

    assert result.manifest.analysis_backend == "direct_tshark"
    assert "fixture worker failed" in result.manifest.fallback_reason
    assert not list(tmp_path.rglob("partial.sqlite"))


def test_agent_tools_are_workspace_bound_bounded_and_payload_free(tmp_path):
    capture = b"fixture"
    (tmp_path / "capture.pcap").write_bytes(capture)
    flow_id = stable_flow_id(
        "TCP", "192.0.2.10", 51000, "198.51.100.8", 443, stream_id=0
    )
    flow = ObservedFlow(
        flow_id=flow_id,
        transport="TCP",
        ip_version=4,
        src_ip="192.0.2.10",
        src_port=51000,
        dst_ip="198.51.100.8",
        dst_port=443,
        direction_relative_to_dut=FlowDirection.OUTBOUND,
        first_frame=1,
        last_frame=1,
        frame_count=1,
        protocol_candidates=[
            ProtocolCandidate(
                name="TLS",
                confidence=1.0,
                status=ProtocolCandidateStatus.CONFIRMED,
                basis=[
                    ProtocolBasis(
                        type=ProtocolBasisType.TSHARK_DISSECTOR,
                        value="tls",
                        frame_number=1,
                    )
                ],
            )
        ],
        encryption=EncryptionAssessment(
            flow_id=flow_id,
            classification=EncryptionClassification.STANDARD_ENCRYPTION_CONFIRMED,
            confidence=1.0,
            basis=["fixture"],
            frame_refs=[1],
        ),
        frame_refs=[1],
    )
    frame = ObservedFrame(
        frame_number=1,
        flow_id=flow_id,
        timestamp_epoch=1000,
        frame_length=100,
        src_address="192.0.2.10",
        dst_address="198.51.100.8",
        src_port=51000,
        dst_port=443,
        transport="TCP",
        stream_id=0,
        protocol_stack=["eth", "ip", "tcp", "tls"],
    )
    with TrafficIntelligenceBundleWriter(tmp_path, _manifest(capture)) as writer:
        writer.write_json("inventory.json", {"flow_count": 1})
        writer.write_jsonl("flows.jsonl", [flow])
        writer.write_jsonl("frames.jsonl", [frame])
        writer.write_jsonl("encryption-assessments.jsonl", [flow.encryption])
        writer.write_json("unknown-protocol-clusters.json", [])
        writer.write_json("declaration-alignments.json", [])
        writer.commit()

    registry = ToolRegistry()
    build_traffic_intelligence_registry(registry, tmp_path)
    names = registry.resolve_categories((TRAFFIC_INTELLIGENCE_CATEGORY,))
    assert "traffic_get_inventory" in names
    assert "traffic_get_frame_details" in names
    assert "traffic_list_activity_windows" in names
    assert "traffic_list_dns_correlations" in names
    frame_schema = registry.get_def("traffic_get_frame_details").to_anthropic_schema()
    assert frame_schema["input_schema"]["properties"]["frame_numbers"]["items"] == {
        "type": "integer"
    }

    inventory = asyncio.run(registry.execute("traffic_get_inventory", {}))
    assert json.loads(inventory.content) == {"flow_count": 1}
    listed = asyncio.run(registry.execute(
        "traffic_list_flows",
        {"endpoint": "198.51.100.8", "limit": 1},
    ))
    assert json.loads(listed.content)["flows"][0]["flow_id"] == flow_id
    details = asyncio.run(registry.execute(
        "traffic_get_frame_details",
        {"frame_numbers": [1]},
    ))
    assert json.loads(details.content)["payload_included"] is False
    assert "payload" not in json.loads(details.content)["frames"][0]


def test_traffic_tools_filter_flows_and_expose_automatic_correlations(tmp_path):
    capture = b"fixture"
    (tmp_path / "capture.pcap").write_bytes(capture)
    flow_id = "flow-private-1"
    cluster_id = "unknown-tcp-private-1"
    flow = {
        "flow_id": flow_id,
        "transport": "TCP",
        "src_ip": "192.0.2.10",
        "src_port": 51000,
        "dst_ip": "198.51.100.8",
        "dst_port": 9000,
        "direction_relative_to_dut": "OUTBOUND",
        "protocol_candidates": [{"name": "UNKNOWN"}],
        "encryption": {"classification": "OPAQUE_HIGH_ENTROPY"},
        "unknown_cluster_id": cluster_id,
    }
    with TrafficIntelligenceBundleWriter(tmp_path, _manifest(capture)) as writer:
        writer.write_json("inventory.json", {"flow_count": 1})
        writer.write_jsonl("flows.jsonl", [flow])
        writer.write_json("unknown-protocol-clusters.json", [{
            "cluster_id": cluster_id,
            "flow_ids": [flow_id],
        }])
        writer.write_json("declaration-alignments.json", [{
            "alignment_id": "alignment-private-1",
            "declaration_id": None,
            "flow_ids": [flow_id],
            "overall": "UNDECLARED_OBSERVED",
        }])
        writer.write_json("automatic-activity-windows.json", [{
            "window_id": "activity-private-1",
            "kind": "HEARTBEAT",
            "flow_ids": [flow_id],
        }])
        writer.write_json("dns-correlations.json", [{
            "hostname": "api.example.test",
            "resolved_addresses": ["198.51.100.8"],
            "observed_endpoint_addresses": ["198.51.100.8"],
            "flow_ids": [flow_id],
        }])
        writer.commit()

    registry = ToolRegistry()
    build_traffic_intelligence_registry(registry, tmp_path)

    listed = asyncio.run(registry.execute("traffic_list_flows", {
        "unknown_cluster_id": cluster_id,
        "alignment_status": "UNDECLARED_OBSERVED",
    }))
    assert [item["flow_id"] for item in json.loads(listed.content)["flows"]] == [flow_id]

    windows = asyncio.run(registry.execute("traffic_list_activity_windows", {
        "kind": "heartbeat",
        "flow_id": flow_id,
    }))
    assert json.loads(windows.content)["windows"][0]["window_id"] == "activity-private-1"

    dns = asyncio.run(registry.execute("traffic_list_dns_correlations", {
        "hostname": "API.EXAMPLE.TEST.",
        "endpoint": "198.51.100.8",
        "flow_id": flow_id,
    }))
    assert json.loads(dns.content)["correlations"][0]["hostname"] == "api.example.test"


def test_traffic_tool_policy_treats_endpoint_as_local_filter_but_rejects_paths(tmp_path):
    policy = ToolExecutionPolicy({"workspace": str(tmp_path)})

    endpoint_filter = policy.validate(
        "traffic_list_flows", {"endpoint": "198.51.100.8"}
    )
    injected_path = policy.validate(
        "traffic_get_flow", {"flow_id": "flow-1", "path": "../capture.pcap"}
    )

    assert endpoint_filter.allowed is True
    assert endpoint_filter.code == "allowed_local_traffic_query"
    assert injected_path.allowed is False
    assert injected_path.code == "path_parameter_blocked"


def test_payload_profiler_classifies_explicit_http_without_storing_raw_bytes():
    profiler = IncrementalPayloadProfiler()
    profiler.add(b"GET /status HTTP/1.1\r\nHost: device.example.test\r\n\r\n", from_origin=True)
    profile = profiler.to_model("flow-http")
    assessment = classify_encryption("flow-http", payload_profile=profile, frame_refs=[7])

    assert "HTTP" in profile.format_hints
    assert profile.stable_prefix_sha256
    assert assessment.classification == EncryptionClassification.PLAINTEXT_CONFIRMED
    serialized = profile.model_dump_json()
    assert "GET /status" not in serialized
    assert "device.example.test" not in serialized


def test_high_entropy_payload_is_opaque_not_claimed_as_custom_encryption():
    profiler = IncrementalPayloadProfiler()
    profiler.add(bytes(range(256)) * 4, from_origin=True)
    profile = profiler.to_model("flow-opaque")
    assessment = classify_encryption("flow-opaque", payload_profile=profile, frame_refs=[9])

    assert profile.entropy == pytest.approx(8.0)
    assert assessment.classification == EncryptionClassification.OPAQUE_HIGH_ENTROPY
    assert assessment.security_protocol is None
    assert any("压缩" in limitation for limitation in assessment.limitations)


def test_absence_of_tls_without_payload_remains_insufficient_evidence():
    profile = IncrementalPayloadProfiler().to_model("flow-empty")
    assessment = classify_encryption("flow-empty", payload_profile=profile)

    assert assessment.classification == EncryptionClassification.INSUFFICIENT_EVIDENCE


def test_unknown_protocol_sessions_with_same_profile_receive_stable_cluster():
    def unknown_flow(flow_id, src_port, stream_id):
        return ObservedFlow(
            flow_id=flow_id,
            transport="TCP",
            ip_version=4,
            src_ip="192.0.2.10",
            src_port=src_port,
            dst_ip="198.51.100.8",
            dst_port=9000,
            direction_relative_to_dut=FlowDirection.OUTBOUND,
            first_frame=stream_id + 1,
            last_frame=stream_id + 1,
            frame_count=1,
            stream_id=stream_id,
            protocol_candidates=[
                ProtocolCandidate(
                    name="UNKNOWN",
                    confidence=0.0,
                    status=ProtocolCandidateStatus.UNKNOWN,
                )
            ],
        )

    flow_a = unknown_flow("flow-private-a", 51000, 0)
    flow_b = unknown_flow("flow-private-b", 51001, 1)
    profile_a = IncrementalPayloadProfiler()
    profile_b = IncrementalPayloadProfiler()
    payload = b"\x01\x02private-message" * 8
    profile_a.add(payload, from_origin=True)
    profile_b.add(payload, from_origin=True)

    clusters, assignments = build_unknown_protocol_clusters(
        [flow_b, flow_a],
        {
            flow_a.flow_id: profile_a.to_model(flow_a.flow_id),
            flow_b.flow_id: profile_b.to_model(flow_b.flow_id),
        },
    )

    assert len(clusters) == 1
    assert clusters[0].flow_ids == ["flow-private-a", "flow-private-b"]
    assert assignments[flow_a.flow_id] == assignments[flow_b.flow_id]
    assert clusters[0].cluster_id.startswith("unknown-tcp-")


def test_declaration_extractor_combines_communication_and_interface_tables():
    fixture_path = Path(__file__).parent / "fixtures" / "mini_ixit.json"
    ixit = json.loads(fixture_path.read_text(encoding="utf-8"))

    result = extract_traffic_declarations(ixit, artifact="inputs/ixit.normalized.json")

    assert result.communication_table_present is True
    assert len(result.declarations) == 3
    by_protocol = {
        declaration.application_protocol[0]: declaration
        for declaration in result.declarations
    }
    https = by_protocol["HTTPS"]
    assert https.local_ports == [443]
    assert https.encryption_expected is True
    assert https.encryption_protocol == ["TLS"]
    assert https.minimum_version == "1.2"
    assert "ECDHE-RSA-AES256-GCM-SHA384" in https.algorithm_claims
    assert https.source.artifact == "inputs/ixit.normalized.json"
    assert by_protocol["HTTP"].encryption_expected is False
    assert by_protocol["RTSP"].encryption_expected is False
    assert any("15-Intf" in warning for warning in result.warnings)


def test_declaration_matcher_surfaces_port_mismatch_without_hiding_other_matches():
    declaration = TrafficDeclaration(
        declaration_id="decl-cloud-https",
        source=TrafficDeclarationSource(artifact="ixit.json", table="11-ComMech", row=1),
        raw_text_sha256="a" * 64,
        direction=FlowDirection.OUTBOUND,
        transport=["TCP"],
        application_protocol=["HTTPS"],
        remote_ports=[443],
        remote_hosts=["cloud.example.test"],
        encryption_expected=True,
        encryption_protocol=["TLS"],
        minimum_version="1.2",
        algorithm_claims=["TLS-AES-128-GCM-SHA256"],
    )
    flow = ObservedFlow(
        flow_id="flow-cloud-https",
        transport="TCP",
        ip_version=4,
        src_ip="192.0.2.10",
        src_port=51000,
        dst_ip="198.51.100.8",
        dst_port=8443,
        direction_relative_to_dut=FlowDirection.OUTBOUND,
        first_frame=3,
        last_frame=7,
        frame_count=5,
        sni=["cloud.example.test"],
        protocol_candidates=[
            ProtocolCandidate(
                name="TLS",
                confidence=1.0,
                status=ProtocolCandidateStatus.CONFIRMED,
                basis=[
                    ProtocolBasis(
                        type=ProtocolBasisType.TSHARK_DISSECTOR,
                        value="tls",
                        frame_number=3,
                    )
                ],
            )
        ],
        encryption=EncryptionAssessment(
            flow_id="flow-cloud-https",
            classification=EncryptionClassification.STANDARD_ENCRYPTION_CONFIRMED,
            confidence=1.0,
            basis=["fixture"],
            security_protocol="TLS",
            negotiated_version="TLS 1.3",
            cipher_suites=["0x1301"],
            frame_refs=[3, 7],
            algorithm_claim_verifiable=True,
        ),
        frame_refs=[3, 7],
    )

    [alignment] = align_traffic_declarations([declaration], [flow])

    assert alignment.overall == AlignmentStatus.MISMATCH
    assert alignment.dimensions["port"] == AlignmentStatus.MISMATCH
    assert alignment.dimensions["remote_target"] == AlignmentStatus.MATCH
    assert alignment.dimensions["application_protocol"] == AlignmentStatus.MATCH
    assert alignment.dimensions["encryption"] == AlignmentStatus.MATCH
    assert alignment.dimensions["minimum_version"] == AlignmentStatus.MATCH
    assert alignment.dimensions["algorithm_claims"] == AlignmentStatus.MATCH
    assert alignment.frame_refs == [3, 7]


def test_declaration_matcher_keeps_not_observed_distinct_from_undeclared_observed():
    declaration = TrafficDeclaration(
        declaration_id="decl-http-server",
        source=TrafficDeclarationSource(artifact="ixit.json", table="11-ComMech", row=1),
        raw_text_sha256="b" * 64,
        direction=FlowDirection.INBOUND,
        transport=["TCP"],
        application_protocol=["HTTP"],
        local_ports=[80],
        encryption_expected=False,
    )
    flow = ObservedFlow(
        flow_id="flow-unexpected-tls",
        transport="TCP",
        ip_version=4,
        src_ip="192.0.2.10",
        src_port=51000,
        dst_ip="198.51.100.8",
        dst_port=443,
        direction_relative_to_dut=FlowDirection.OUTBOUND,
        first_frame=10,
        last_frame=10,
        frame_count=1,
        protocol_candidates=[
            ProtocolCandidate(
                name="TLS",
                confidence=1.0,
                status=ProtocolCandidateStatus.CONFIRMED,
                basis=[
                    ProtocolBasis(
                        type=ProtocolBasisType.TSHARK_DISSECTOR,
                        value="tls",
                        frame_number=10,
                    )
                ],
            )
        ],
        frame_refs=[10],
    )

    alignments = align_traffic_declarations([declaration], [flow])

    assert [item.overall for item in alignments] == [
        AlignmentStatus.NOT_OBSERVED,
        AlignmentStatus.UNDECLARED_OBSERVED,
    ]
    assert alignments[0].declaration_id == declaration.declaration_id
    assert alignments[1].declaration_id is None
    assert alignments[1].flow_ids == [flow.flow_id]


def test_decode_as_is_allowlisted_flow_scoped_and_does_not_rewrite_original_facts(
    tmp_path,
    monkeypatch,
):
    capture = b"fixture"
    (tmp_path / "capture.pcap").write_bytes(capture)
    flow = ObservedFlow(
        flow_id="flow-private",
        transport="TCP",
        ip_version=4,
        src_ip="192.0.2.10",
        src_port=51000,
        dst_ip="198.51.100.8",
        dst_port=8080,
        direction_relative_to_dut=FlowDirection.OUTBOUND,
        first_frame=1,
        last_frame=2,
        frame_count=2,
        stream_id=4,
        protocol_candidates=[
            ProtocolCandidate(
                name="UNKNOWN",
                confidence=0.0,
                status=ProtocolCandidateStatus.UNKNOWN,
            )
        ],
        frame_refs=[1, 2],
    )
    with TrafficIntelligenceBundleWriter(tmp_path, _manifest(capture)) as writer:
        writer.write_json("inventory.json", {"flow_count": 1})
        writer.write_jsonl("flows.jsonl", [flow])
        writer.commit()

    invoked: dict[str, list[str]] = {}
    runner = DecodeAsRunner(tmp_path, tshark_path="fixture-tshark")
    monkeypatch.setattr(runner, "_tshark_version", lambda: "TShark fixture")

    def fake_run(args, output_path, stderr_path):
        invoked["args"] = args
        with output_path.open("w", encoding="utf-8", newline="") as handle:
            tab_writer = csv.DictWriter(
                handle,
                fieldnames=["frame.number", "frame.protocols", "_ws.col.Protocol"],
                delimiter="\t",
            )
            tab_writer.writeheader()
            tab_writer.writerow({
                "frame.number": "1",
                "frame.protocols": "eth:ip:tcp:http",
                "_ws.col.Protocol": "HTTP",
            })
            tab_writer.writerow({
                "frame.number": "2",
                "frame.protocols": "eth:ip:tcp:http",
                "_ws.col.Protocol": "HTTP",
            })
        stderr_path.write_text("", encoding="utf-8")

    monkeypatch.setattr(runner, "_run_tshark", fake_run)
    result = runner.run(flow.flow_id, "http")

    assert result["status"] == "probable"
    assert result["candidate"]["status"] == "PROBABLE"
    assert result["decode_selector"] == "tcp.port==8080,http"
    assert result["flow_filter"] == "tcp.stream == 4"
    assert result["original_flow_modified"] is False
    assert result["payload_included"] is False
    assert invoked["args"][invoked["args"].index("-d") + 1] == "tcp.port==8080,http"
    assert invoked["args"][invoked["args"].index("-Y") + 1] == "tcp.stream == 4"
    result_path = tmp_path / result["artifact"]
    assert result_path.is_file()
    attempt_manifest = json.loads(
        (result_path.parent / "manifest.json").read_text(encoding="utf-8")
    )
    assert attempt_manifest["capture_sha256"] == hashlib.sha256(capture).hexdigest()
    assert attempt_manifest["parent_bundle_manifest_sha256"] == hashlib.sha256(
        (tmp_path / "traffic-intelligence" / "manifest.json").read_bytes()
    ).hexdigest()
    assert not (tmp_path / "traffic-intelligence" / "decode-as-attempts").exists()
    assert not list((tmp_path / "traffic-intelligence").rglob("*.tsv"))
    [preserved] = TrafficIntelligenceBundleStore(tmp_path).iter_jsonl("flows.jsonl")
    assert preserved["protocol_candidates"][0]["status"] == "UNKNOWN"

    with pytest.raises(DecodeAsError, match="allowlist"):
        runner.run(flow.flow_id, "evil;rm")


def test_decode_as_failure_removes_empty_derived_directories(tmp_path, monkeypatch):
    capture = b"fixture"
    (tmp_path / "capture.pcap").write_bytes(capture)
    flow = ObservedFlow(
        flow_id="flow-failing-decode",
        transport="TCP",
        ip_version=4,
        src_ip="192.0.2.10",
        src_port=51000,
        dst_ip="198.51.100.8",
        dst_port=8080,
        direction_relative_to_dut=FlowDirection.OUTBOUND,
        first_frame=1,
        last_frame=1,
        frame_count=1,
        stream_id=4,
        protocol_candidates=[ProtocolCandidate(
            name="UNKNOWN",
            confidence=0.0,
            status=ProtocolCandidateStatus.UNKNOWN,
        )],
        frame_refs=[1],
    )
    with TrafficIntelligenceBundleWriter(tmp_path, _manifest(capture)) as writer:
        writer.write_jsonl("flows.jsonl", [flow])
        writer.commit()

    runner = DecodeAsRunner(tmp_path, tshark_path="fixture-tshark")
    monkeypatch.setattr(runner, "_tshark_version", lambda: "TShark fixture")

    def fail_decode(*_args):
        raise DecodeAsError("fixture decode failed")

    monkeypatch.setattr(runner, "_run_tshark", fail_decode)
    with pytest.raises(DecodeAsError, match="fixture decode failed"):
        runner.run(flow.flow_id, "http")

    assert not (tmp_path / "traffic-intelligence-derived").exists()


def test_automatic_activity_segmenter_detects_periodic_small_flow_without_user_labels():
    segmenter = AutomaticActivitySegmenter()
    for number, timestamp in enumerate((1000.0, 1001.0, 1002.0, 1003.0), start=1):
        segmenter.add(ObservedFrame(
            frame_number=number,
            flow_id="flow-heartbeat",
            timestamp_epoch=timestamp,
            frame_length=96,
            src_address="192.0.2.10",
            dst_address="198.51.100.8",
            src_port=51000,
            dst_port=9000,
            transport="TCP",
        ))

    [window] = segmenter.finish()

    assert window.kind.value == "HEARTBEAT"
    assert window.start_offset_ms == 0
    assert window.end_offset_ms == 3000
    assert window.flow_ids == ["flow-heartbeat"]
    assert all("用户" not in observation for observation in window.observations)


def test_dns_answer_enriches_endpoint_flow_and_correlates_sni():
    dns_index = DnsCorrelationIndex()
    dns_index.add(ObservedFrame(
        frame_number=1,
        timestamp_epoch=1000,
        frame_length=120,
        src_address="203.0.113.53",
        dst_address="192.0.2.10",
        src_port=53,
        dst_port=53000,
        transport="UDP",
        protocol_stack=["eth", "ip", "udp", "dns"],
        dns_names=["api.example.test"],
        dns_answers=["198.51.100.8"],
        dns_cnames=["edge.example.test"],
    ))
    flow = ObservedFlow(
        flow_id="flow-api",
        transport="TCP",
        ip_version=4,
        src_ip="192.0.2.10",
        src_port=51000,
        dst_ip="198.51.100.8",
        dst_port=443,
        direction_relative_to_dut=FlowDirection.OUTBOUND,
        first_frame=2,
        last_frame=3,
        frame_count=2,
        sni=["api.example.test"],
        frame_refs=[2, 3],
    )

    enriched = dns_index.enrich_flow(flow)
    correlations = dns_index.correlations([enriched])
    api = next(row for row in correlations if row["hostname"] == "api.example.test")

    assert enriched.dns_names == ["api.example.test", "edge.example.test"]
    assert api["resolved_addresses"] == ["198.51.100.8"]
    assert api["observed_endpoint_addresses"] == ["198.51.100.8"]
    assert api["sni_names"] == ["api.example.test"]
    assert api["dns_frame_refs"] == [1]
    assert api["basis"] == ["dns_answer", "endpoint_flow", "sni_equals_dns_name"]
