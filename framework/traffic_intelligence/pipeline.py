"""连续 PCAP 到可校验 Traffic Intelligence Bundle 的编排入口。"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from pydantic import BaseModel

from contracts.traffic_intelligence import (
    AlignmentStatus,
    ObservedFlow,
    ObservedFrame,
    PayloadProfile,
    TrafficCaptureManifest,
    TrafficIntelligenceBundleIndex,
)
from framework.traffic_intelligence.backends.base import (
    AnalysisBackend,
    BackendError,
    BackendRequest,
    BackendResult,
)
from framework.traffic_intelligence.backends.direct_tshark import DirectTsharkBackend
from framework.traffic_intelligence.backends.easytshark_batch import EasyTsharkBatchBackend
from framework.traffic_intelligence.activity_segmenter import AutomaticActivitySegmenter
from framework.traffic_intelligence.bundle_store import (
    TrafficIntelligenceBundleStore,
    TrafficIntelligenceBundleWriter,
    sha256_file,
)
from framework.traffic_intelligence.declaration_extractor import (
    extract_traffic_declarations,
)
from framework.traffic_intelligence.declaration_matcher import align_traffic_declarations
from framework.traffic_intelligence.dns_correlator import DnsCorrelationIndex
from framework.traffic_intelligence.protocol_profiler import build_unknown_protocol_clusters


@dataclass(frozen=True)
class TrafficIntelligenceSettings:
    backend: str = "auto"
    timeout_seconds: int = 1800
    payload_policy: str = "metadata_only"
    max_stream_sample_bytes: int = 4096
    easytshark_path: str | None = None

    def __post_init__(self) -> None:
        if self.backend not in {"auto", "direct_tshark", "easytshark_batch"}:
            raise ValueError("TRAFFIC_ANALYZER_BACKEND 值无效")
        if self.timeout_seconds <= 0:
            raise ValueError("TRAFFIC_EASYTSHARK_TIMEOUT_SECONDS 必须大于 0")
        if self.payload_policy not in {"metadata_only", "bounded_redacted", "disabled"}:
            raise ValueError("TRAFFIC_AI_PAYLOAD_POLICY 值无效")
        if self.max_stream_sample_bytes < 0 or self.max_stream_sample_bytes > 1024 * 1024:
            raise ValueError("TRAFFIC_MAX_STREAM_SAMPLE_BYTES 必须位于 0..1048576")

    @classmethod
    def from_environment(cls, environ: dict[str, str] | None = None) -> "TrafficIntelligenceSettings":
        env = environ if environ is not None else os.environ
        return cls(
            backend=env.get("TRAFFIC_ANALYZER_BACKEND", "auto").strip().lower(),
            timeout_seconds=int(env.get("TRAFFIC_EASYTSHARK_TIMEOUT_SECONDS", "1800")),
            payload_policy=env.get("TRAFFIC_AI_PAYLOAD_POLICY", "metadata_only").strip().lower(),
            max_stream_sample_bytes=int(env.get("TRAFFIC_MAX_STREAM_SAMPLE_BYTES", "4096")),
            easytshark_path=(env.get("TRAFFIC_EASYTSHARK_PATH") or "").strip() or None,
        )


@dataclass(frozen=True)
class TrafficIntelligenceRunResult:
    output_dir: Path
    manifest: TrafficCaptureManifest
    frame_count: int
    flow_count: int


def _capture_format(path: Path) -> str:
    with path.open("rb") as handle:
        magic = handle.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    if magic in {
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    }:
        return "pcap"
    return "unknown"


def _normalize_dut_addresses(values: list[str] | tuple[str, ...]) -> tuple[list[str], list[str]]:
    addresses: list[str] = []
    warnings: list[str] = []
    for value in values:
        try:
            addresses.append(str(ipaddress.ip_address(value)))
        except ValueError:
            warnings.append(f"DUT 标识 {value!r} 不是 IP，无法据此判定流量方向")
    return list(dict.fromkeys(addresses)), warnings


def _iter_models(path: Path, model: type[BaseModel]) -> Iterator[BaseModel]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            if len(line.encode("utf-8")) > 1024 * 1024:
                raise ValueError(f"{path.name} 第 {line_number} 行超过 1 MiB")
            yield model.model_validate_json(line)


class TrafficIntelligencePipeline:
    """统一调度后端并生成与具体后端无关的 Bundle。"""

    def __init__(self, settings: TrafficIntelligenceSettings | None = None) -> None:
        self.settings = settings or TrafficIntelligenceSettings.from_environment()

    def _initial_backend(self, tshark_path: str) -> tuple[AnalysisBackend, str | None]:
        if self.settings.backend == "easytshark_batch":
            if self.settings.easytshark_path:
                return EasyTsharkBatchBackend(self.settings.easytshark_path), None
            return (
                DirectTsharkBackend(tshark_path),
                "easytshark_batch 未配置可执行文件，已回退 direct_tshark",
            )
        # A/B 结论形成前，auto 固定走 Direct Tshark；不因本机偶然存在 Worker 改变证据。
        return DirectTsharkBackend(tshark_path), None

    @staticmethod
    def _clean_failed_backend_output(path: Path, staging_root: Path) -> None:
        resolved = path.resolve(strict=False)
        if not resolved.is_relative_to(staging_root.resolve()):
            raise ValueError("拒绝清理 staging 之外的 backend 输出")
        if not path.exists():
            return
        if path.is_symlink():
            path.unlink()
        else:
            shutil.rmtree(path)

    def _run_backend_with_fallback(
        self,
        writer: TrafficIntelligenceBundleWriter,
        capture_path: Path,
        tshark_path: str,
        dut_addresses: list[str],
    ) -> tuple[BackendResult, str | None]:
        backend, initial_fallback_reason = self._initial_backend(tshark_path)
        output_dir = writer.staging_dir / "backend-staging" / backend.name
        request = BackendRequest(
            workspace=writer.workspace,
            capture_path=capture_path,
            output_dir=output_dir,
            tshark_path=tshark_path,
            dut_addresses=tuple(dut_addresses),
            timeout_seconds=self.settings.timeout_seconds,
            options={"payload_policy": self.settings.payload_policy},
        )
        try:
            return backend.analyze(request), initial_fallback_reason
        except BackendError as exc:
            if backend.name == "direct_tshark":
                raise
            fallback_reason = f"{backend.name} 失败，已回退 direct_tshark: {type(exc).__name__}: {exc}"
            self._clean_failed_backend_output(output_dir, writer.staging_dir)
            direct = DirectTsharkBackend(tshark_path)
            direct_output = writer.staging_dir / "backend-staging" / direct.name
            direct_request = BackendRequest(
                workspace=writer.workspace,
                capture_path=capture_path,
                output_dir=direct_output,
                tshark_path=tshark_path,
                dut_addresses=tuple(dut_addresses),
                timeout_seconds=self.settings.timeout_seconds,
                options={"payload_policy": self.settings.payload_policy},
            )
            return direct.analyze(direct_request), fallback_reason

    @staticmethod
    def _load_ixit(workspace: Path) -> tuple[dict[str, Any] | None, str | None, list[str]]:
        candidates = (
            (workspace / "inputs" / "ixit.normalized.json", "inputs/ixit.normalized.json"),
            (workspace / "ixit.json", "ixit.json"),
        )
        for path, artifact in candidates:
            if not path.is_file():
                continue
            if path.stat().st_size > 20 * 1024 * 1024:
                return None, None, [f"{artifact} 超过 20 MiB，未执行流量声明提取"]
            try:
                value = json.loads(path.read_text(encoding="utf-8-sig"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                return None, None, [f"{artifact} 无法解析，未执行流量声明提取: {exc}"]
            if not isinstance(value, dict):
                return None, None, [f"{artifact} 顶层不是 object，未执行流量声明提取"]
            return value, artifact, []
        return None, None, ["workspace 未提供 IXIT，未执行声明对齐"]

    @staticmethod
    def _promote_backend_output(
        writer: TrafficIntelligenceBundleWriter,
        result: BackendResult,
    ) -> tuple[Path, Path, Path, Path | None]:
        destinations = (
            (result.frame_index_path, writer.staging_dir / "frames.jsonl"),
            (result.flow_index_path, writer.staging_dir / "flows.jsonl"),
            (
                result.non_session_observations_path,
                writer.staging_dir / "non-session-observations.jsonl",
            ),
        )
        promoted: list[Path] = []
        for source, destination in destinations:
            if source is None or source.is_symlink() or not source.is_file():
                raise ValueError("后端缺少规范化输出")
            destination.parent.mkdir(parents=True, exist_ok=True)
            source.replace(destination)
            promoted.append(destination)
        profiles_destination: Path | None = None
        if result.payload_profiles_path is not None:
            source = result.payload_profiles_path
            if source.is_symlink() or not source.is_file():
                raise ValueError("后端 payload profile 输出无效")
            profiles_destination = writer.staging_dir / ".payload-profiles.jsonl"
            source.replace(profiles_destination)
        backend_root = result.frame_index_path.parent
        if backend_root.exists():
            TrafficIntelligencePipeline._clean_failed_backend_output(
                backend_root,
                writer.staging_dir,
            )
        return promoted[0], promoted[1], promoted[2], profiles_destination

    def run(
        self,
        workspace: Path,
        *,
        capture_path: Path | None = None,
        dut_addresses: list[str] | tuple[str, ...] = (),
        tshark_path: str = "tshark",
    ) -> TrafficIntelligenceRunResult:
        workspace = Path(workspace).resolve()
        selected_capture = Path(capture_path) if capture_path else workspace / "capture.pcap"
        if not selected_capture.is_absolute():
            selected_capture = workspace / selected_capture
        selected_capture = selected_capture.resolve()
        if not selected_capture.is_relative_to(workspace):
            raise ValueError("capture_path 必须位于当前 workspace")
        if not selected_capture.is_file():
            raise FileNotFoundError(selected_capture)

        normalized_dut, warnings = _normalize_dut_addresses(dut_addresses)
        manifest = TrafficCaptureManifest(
            capture_sha256=sha256_file(selected_capture),
            capture_size=selected_capture.stat().st_size,
            capture_format=_capture_format(selected_capture),
            capture_artifact=selected_capture.relative_to(workspace).as_posix(),
            dut_addresses=normalized_dut,
            requested_backend=self.settings.backend,
            analysis_backend="pending",
            analysis_started_at=datetime.now(timezone.utc),
            warnings=warnings,
        )

        with TrafficIntelligenceBundleWriter(
            workspace,
            manifest,
            capture_path=selected_capture,
        ) as writer:
            result, fallback_reason = self._run_backend_with_fallback(
                writer,
                selected_capture,
                tshark_path,
                normalized_dut,
            )
            frames_path, flows_path, observations_path, profiles_path = self._promote_backend_output(
                writer,
                result,
            )
            payload_profiles: dict[str, PayloadProfile] = {}
            if profiles_path is not None:
                for profile_model in _iter_models(profiles_path, PayloadProfile):
                    assert isinstance(profile_model, PayloadProfile)
                    payload_profiles[profile_model.flow_id] = profile_model

            def cluster_flow_models() -> Iterator[ObservedFlow]:
                for flow_model in _iter_models(flows_path, ObservedFlow):
                    assert isinstance(flow_model, ObservedFlow)
                    yield flow_model

            unknown_clusters, cluster_assignments = build_unknown_protocol_clusters(
                cluster_flow_models(),
                payload_profiles,
            )
            if cluster_assignments:
                rewritten = flows_path.with_name(
                    f".{flows_path.name}.{uuid.uuid4().hex}.tmp"
                )
                with rewritten.open("w", encoding="utf-8", newline="\n") as handle:
                    for flow_model in cluster_flow_models():
                        cluster_id = cluster_assignments.get(flow_model.flow_id)
                        if cluster_id:
                            flow_model = flow_model.model_copy(
                                update={"unknown_cluster_id": cluster_id}
                            )
                        handle.write(flow_model.model_dump_json())
                        handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                rewritten.replace(flows_path)

            timing: dict[str, float | None] = {"first": None, "last": None}
            activity_segmenter = AutomaticActivitySegmenter()
            dns_index = DnsCorrelationIndex()

            def frame_index_rows() -> Iterator[dict[str, Any]]:
                for frame in _iter_models(frames_path, ObservedFrame):
                    assert isinstance(frame, ObservedFrame)
                    activity_segmenter.add(frame)
                    dns_index.add(frame)
                    timing["first"] = (
                        frame.timestamp_epoch
                        if timing["first"] is None
                        else min(timing["first"], frame.timestamp_epoch)
                    )
                    timing["last"] = (
                        frame.timestamp_epoch
                        if timing["last"] is None
                        else max(timing["last"], frame.timestamp_epoch)
                    )
                    if frame.flow_id:
                        yield {"frame_number": frame.frame_number, "flow_id": frame.flow_id}

            writer.write_jsonl("flow-frame-index.jsonl", frame_index_rows())
            automatic_activity_windows = activity_segmenter.finish()

            flow_models: list[ObservedFlow] = []
            rewritten = flows_path.with_name(
                f".{flows_path.name}.{uuid.uuid4().hex}.tmp"
            )
            with rewritten.open("w", encoding="utf-8", newline="\n") as handle:
                for flow_model in _iter_models(flows_path, ObservedFlow):
                    assert isinstance(flow_model, ObservedFlow)
                    flow_model = dns_index.enrich_flow(flow_model)
                    flow_models.append(flow_model)
                    handle.write(flow_model.model_dump_json())
                    handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            rewritten.replace(flows_path)

            writer.register_existing("frames.jsonl")
            writer.register_existing("flows.jsonl")
            writer.register_existing("non-session-observations.jsonl")

            protocol_counts: Counter[str] = Counter()
            encryption_counts: Counter[str] = Counter()
            endpoint_flows: dict[str, set[str]] = defaultdict(set)
            endpoint_ports: dict[str, set[int]] = defaultdict(set)
            high_risk_flow_ids: list[str] = []
            unknown_flow_ids: list[str] = []

            for flow_model in flow_models:
                endpoint_flows[flow_model.src_ip].add(flow_model.flow_id)
                endpoint_flows[flow_model.dst_ip].add(flow_model.flow_id)
                endpoint_ports[flow_model.src_ip].add(flow_model.src_port)
                endpoint_ports[flow_model.dst_ip].add(flow_model.dst_port)
                for candidate in flow_model.protocol_candidates:
                    protocol_counts[candidate.name] += 1
                    if candidate.status.value == "UNKNOWN":
                        unknown_flow_ids.append(flow_model.flow_id)
                if flow_model.encryption:
                    classification = flow_model.encryption.classification.value
                    encryption_counts[classification] += 1
                    if classification == "PLAINTEXT_CONFIRMED":
                        high_risk_flow_ids.append(flow_model.flow_id)
            dns_correlations = dns_index.correlations(flow_models)

            ixit, ixit_artifact, declaration_warnings = self._load_ixit(workspace)
            declarations = []
            alignments = []
            if ixit is not None and ixit_artifact is not None:
                extraction = extract_traffic_declarations(ixit, artifact=ixit_artifact)
                declarations = extraction.declarations
                declaration_warnings.extend(extraction.warnings)
                if extraction.communication_table_present:
                    alignments = align_traffic_declarations(declarations, flow_models)
            alignment_counts = Counter(alignment.overall for alignment in alignments)

            def protocol_rows() -> Iterator[dict[str, Any]]:
                for flow_model in flow_models:
                    for candidate in flow_model.protocol_candidates:
                        yield {
                            "flow_id": flow_model.flow_id,
                            "candidate": candidate.model_dump(mode="json"),
                        }

            def encryption_rows() -> Iterator[dict[str, Any]]:
                for flow_model in flow_models:
                    if flow_model.encryption:
                        yield flow_model.encryption.model_dump(mode="json")

            writer.write_jsonl("protocol-candidates.jsonl", protocol_rows())
            writer.write_jsonl("encryption-assessments.jsonl", encryption_rows())
            if profiles_path is not None:
                for profile_model in payload_profiles.values():
                    writer.write_json(
                        f"payload-profiles/{profile_model.flow_id}.json",
                        profile_model,
                    )
                profiles_path.unlink(missing_ok=True)
            writer.write_json("unknown-protocol-clusters.json", unknown_clusters)
            writer.write_json("automatic-activity-windows.json", automatic_activity_windows)
            writer.write_json("declarations.json", declarations)
            writer.write_json("declaration-alignments.json", alignments)
            writer.write_json("dns-correlations.json", dns_correlations)
            writer.write_json("endpoints.json", [
                {
                    "address": address,
                    "flow_count": len(endpoint_flows[address]),
                    "ports": sorted(endpoint_ports[address]),
                }
                for address in sorted(endpoint_flows)
            ])

            inventory = TrafficIntelligenceBundleIndex(
                capture_sha256=manifest.capture_sha256,
                flow_count=result.flow_count,
                non_session_observation_count=self._count_non_empty_lines(observations_path),
                endpoint_count=len(endpoint_flows),
                unknown_cluster_count=len(unknown_clusters),
                declaration_count=len(declarations),
                alignment_counts={
                    status: alignment_counts.get(status, 0)
                    for status in AlignmentStatus
                },
                high_risk_flow_ids=sorted(set(high_risk_flow_ids)),
                warnings=[*warnings, *result.warnings, *declaration_warnings],
            )
            writer.write_json("inventory.json", inventory)
            writer.write_json("summary-for-ai.json", {
                "schema_version": 1,
                "capture_sha256": manifest.capture_sha256,
                "backend": result.backend_name,
                "frame_count": result.frame_count,
                "flow_count": result.flow_count,
                "endpoint_count": len(endpoint_flows),
                "protocol_counts": dict(sorted(protocol_counts.items())),
                "encryption_counts": dict(sorted(encryption_counts.items())),
                "unknown_flow_count": len(set(unknown_flow_ids)),
                "unknown_cluster_count": len(unknown_clusters),
                "declaration_count": len(declarations),
                "alignment_counts": {
                    status.value: alignment_counts.get(status, 0)
                    for status in AlignmentStatus
                },
                "high_risk_flow_ids": sorted(set(high_risk_flow_ids))[:100],
                "warnings": [*warnings, *result.warnings, *declaration_warnings],
            })

            capture_started_at = (
                datetime.fromtimestamp(timing["first"], timezone.utc)
                if timing["first"] is not None
                else None
            )
            capture_finished_at = (
                datetime.fromtimestamp(timing["last"], timezone.utc)
                if timing["last"] is not None
                else None
            )
            writer.update_manifest(
                analysis_backend=result.backend_name,
                backend_version=result.backend_version,
                tshark_version=result.tshark_version,
                fallback_reason=fallback_reason,
                capture_started_at=capture_started_at,
                capture_finished_at=capture_finished_at,
                warnings=[*warnings, *result.warnings, *declaration_warnings],
            )
            output_dir = writer.commit()

        store = TrafficIntelligenceBundleStore(workspace)
        committed_manifest = store.load_manifest(capture_path=selected_capture)
        return TrafficIntelligenceRunResult(
            output_dir=output_dir,
            manifest=committed_manifest,
            frame_count=result.frame_count,
            flow_count=result.flow_count,
        )

    @staticmethod
    def _count_non_empty_lines(path: Path) -> int:
        with path.open("r", encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())
