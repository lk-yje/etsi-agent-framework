"""同一合成 PCAP 上比较两个 Traffic 后端，产出无 Payload 的决策输入。"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from framework.traffic_intelligence.backends.base import AnalysisBackend, BackendRequest, BackendResult


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _jsonl_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            if len(line.encode("utf-8")) > 1024 * 1024:
                raise ValueError(f"{path.name} 第 {number} 行超过 1 MiB")
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path.name} 第 {number} 行不是 object")
            rows.append(value)
    return rows


@dataclass(frozen=True)
class BackendBenchmarkSnapshot:
    backend_name: str
    backend_version: str
    duration_ms: float
    frame_count: int
    flow_count: int
    non_session_count: int
    artifact_bytes: int
    frame_numbers: frozenset[int]
    flow_ids: frozenset[str]
    protocol_frame_numbers: frozenset[int]

    def public_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("frame_numbers")
        value.pop("flow_ids")
        value.pop("protocol_frame_numbers")
        return value


def snapshot_backend_result(result: BackendResult, duration_ms: float) -> BackendBenchmarkSnapshot:
    frames = _jsonl_rows(result.frame_index_path)
    flows = _jsonl_rows(result.flow_index_path)
    observations = _jsonl_rows(result.non_session_observations_path) if result.non_session_observations_path else []
    paths = [result.frame_index_path, result.flow_index_path]
    if result.non_session_observations_path:
        paths.append(result.non_session_observations_path)
    if result.payload_profiles_path:
        paths.append(result.payload_profiles_path)
    return BackendBenchmarkSnapshot(
        backend_name=result.backend_name,
        backend_version=result.backend_version,
        duration_ms=round(duration_ms, 3),
        frame_count=len(frames),
        flow_count=len(flows),
        non_session_count=len(observations),
        artifact_bytes=sum(path.stat().st_size for path in paths if path.is_file()),
        frame_numbers=frozenset(int(row["frame_number"]) for row in frames),
        flow_ids=frozenset(str(row["flow_id"]) for row in flows),
        protocol_frame_numbers=frozenset(
            int(row["frame_number"]) for row in frames if row.get("protocol_stack")
        ),
    )


def compare_snapshots(baseline: BackendBenchmarkSnapshot, candidate: BackendBenchmarkSnapshot) -> dict[str, Any]:
    """以 Direct Tshark 为基线；不从比率推导“协议正确”或安全结论。"""
    common_flows = len(baseline.flow_ids & candidate.flow_ids)
    return {
        "frame_coverage_vs_baseline": _ratio(len(baseline.frame_numbers & candidate.frame_numbers), len(baseline.frame_numbers)),
        "flow_coverage_vs_baseline": _ratio(common_flows, len(baseline.flow_ids)),
        "protocol_field_retention_vs_baseline": _ratio(
            len(baseline.protocol_frame_numbers & candidate.protocol_frame_numbers),
            len(baseline.protocol_frame_numbers),
        ),
        "non_session_count_ratio_vs_baseline": _ratio(candidate.non_session_count, baseline.non_session_count),
        "flow_count_ratio_vs_baseline": _ratio(candidate.flow_count, baseline.flow_count),
        "runtime_ratio_vs_baseline": _ratio(int(candidate.duration_ms * 1000), int(baseline.duration_ms * 1000)),
        "artifact_size_ratio_vs_baseline": _ratio(candidate.artifact_bytes, baseline.artifact_bytes),
        "flow_key_intersection_count": common_flows,
        "interpretation": "仅衡量标准化索引覆盖与成本；不证明私有协议语义、加密安全性或真机适用性。",
    }


def evaluate_candidate(comparison: dict[str, Any]) -> dict[str, Any]:
    """给出保守准入建议；它永远不改变 ``auto`` 的 Direct Tshark 选择。"""
    required = {
        "frame_coverage_vs_baseline": "帧覆盖率",
        "flow_coverage_vs_baseline": "Flow 覆盖率",
        "protocol_field_retention_vs_baseline": "协议字段保留率",
    }
    unavailable = [label for key, label in required.items() if comparison.get(key) is None]
    degraded = [
        label for key, label in required.items()
        if comparison.get(key) is not None and float(comparison[key]) < 1.0
    ]
    if unavailable:
        status = "INCONCLUSIVE"
        reason = f"基线没有足够的 {', '.join(unavailable)} 样本，不能得出后端选择结论"
    elif degraded:
        status = "REJECT"
        reason = f"候选后端降低了 {', '.join(degraded)}，不能作为运行依赖"
    else:
        status = "REVIEW_REQUIRED"
        reason = "索引覆盖未下降；仍需多语料、资源指标、故障行为与真机 UAT 审查"
    return {
        "status": status,
        "reason": reason,
        "automatic_selection_changed": False,
        "required_additional_evidence": [
            "完整合成协议语料结果",
            "畸形/取消输入行为",
            "跨平台构建记录",
            "授权真机 UAT",
        ],
    }


def run_backend_benchmark(
    *,
    workspace: Path,
    capture_path: Path,
    tshark_path: str,
    baseline: AnalysisBackend,
    candidate: AnalysisBackend,
    dut_addresses: tuple[str, ...] = (),
    timeout_seconds: int = 1800,
) -> tuple[Path, dict[str, Any]]:
    """执行两个后端且保留隔离 staging；任一失败即抛错，绝不使用回退掩盖差异。"""
    workspace = workspace.resolve()
    capture_path = capture_path.resolve()
    if not capture_path.is_relative_to(workspace) or not capture_path.is_file():
        raise ValueError("benchmark capture 必须位于 workspace 内且存在")
    root = workspace / "traffic-backend-benchmark" / uuid.uuid4().hex
    root.mkdir(parents=True)

    def run_one(label: str, backend: AnalysisBackend) -> BackendBenchmarkSnapshot:
        output = root / label
        request = BackendRequest(
            workspace=workspace, capture_path=capture_path, output_dir=output,
            tshark_path=tshark_path, dut_addresses=dut_addresses, timeout_seconds=timeout_seconds,
            options={"payload_policy": "metadata_only", "benchmark": True},
        )
        started = time.perf_counter()
        result = backend.analyze(request)
        return snapshot_backend_result(result, (time.perf_counter() - started) * 1000)

    baseline_snapshot = run_one("baseline", baseline)
    candidate_snapshot = run_one("candidate", candidate)
    report = {
        "schema_version": 1,
        "capture_name": capture_path.name,
        "baseline": baseline_snapshot.public_dict(),
        "candidate": candidate_snapshot.public_dict(),
        "comparison": compare_snapshots(baseline_snapshot, candidate_snapshot),
        "safety": {"raw_payload_in_report": False, "network_permitted": False, "automatic_backend_selection_changed": False},
    }
    report["decision"] = evaluate_candidate(report["comparison"])
    report_path = root / "benchmark.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report_path, report
