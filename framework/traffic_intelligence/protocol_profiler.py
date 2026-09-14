"""未知/私有协议的稳定指纹与聚类。"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from contracts.traffic_intelligence import (
    ObservedFlow,
    PayloadProfile,
    ProtocolCandidateStatus,
    UnknownProtocolCluster,
)
from framework.traffic_intelligence.flow_ids import stable_unknown_cluster_id


def _bucket(value: float | None, step: float) -> str:
    if value is None:
        return "unknown"
    lower = int(value / step) * step
    return f"{lower:.2f}-{lower + step:.2f}"


def _service_port(flow: ObservedFlow) -> int:
    if flow.src_port >= 49152 > flow.dst_port:
        return flow.dst_port
    if flow.dst_port >= 49152 > flow.src_port:
        return flow.src_port
    return min(flow.src_port, flow.dst_port)


def _length_signature(profile: PayloadProfile | None) -> list[str]:
    if profile is None:
        return []
    signature: list[str] = []
    for item in profile.direction_length_sequence[:12]:
        try:
            direction, raw_length = item.rsplit(":", 1)
            length = int(raw_length)
        except (ValueError, TypeError):
            continue
        # 16-byte buckets reduce incidental length differences without exposing payload.
        signature.append(f"{direction}:{(length // 16) * 16}")
    return signature


def fingerprint_unknown_flow(
    flow: ObservedFlow,
    profile: PayloadProfile | None,
) -> dict[str, Any]:
    return {
        "transport": flow.transport,
        "service_port": _service_port(flow),
        "first_packet_direction": flow.direction_relative_to_dut.value,
        "entropy_bucket": _bucket(profile.entropy if profile else None, 0.5),
        "printable_bucket": _bucket(profile.printable_ratio if profile else None, 0.1),
        "format_hints": sorted(profile.format_hints if profile else []),
        "length_signature": _length_signature(profile),
    }


def is_unknown_flow(flow: ObservedFlow) -> bool:
    return not flow.protocol_candidates or all(
        candidate.status == ProtocolCandidateStatus.UNKNOWN
        for candidate in flow.protocol_candidates
    )


def build_unknown_protocol_clusters(
    flows: Iterable[ObservedFlow],
    profiles: Mapping[str, PayloadProfile],
) -> tuple[list[UnknownProtocolCluster], dict[str, str]]:
    grouped: dict[str, list[ObservedFlow]] = defaultdict(list)
    fingerprints: dict[str, dict[str, Any]] = {}
    full_hashes: dict[str, str] = {}
    for flow in flows:
        if not is_unknown_flow(flow):
            continue
        fingerprint = fingerprint_unknown_flow(flow, profiles.get(flow.flow_id))
        serialized = json.dumps(
            fingerprint,
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
        full_hash = hashlib.sha256(serialized).hexdigest()
        cluster_id = stable_unknown_cluster_id(flow.transport, fingerprint)
        grouped[cluster_id].append(flow)
        fingerprints[cluster_id] = fingerprint
        full_hashes[cluster_id] = full_hash

    clusters: list[UnknownProtocolCluster] = []
    assignments: dict[str, str] = {}
    for cluster_id in sorted(grouped):
        members = sorted(grouped[cluster_id], key=lambda flow: flow.flow_id)
        for flow in members:
            assignments[flow.flow_id] = cluster_id
        clusters.append(UnknownProtocolCluster(
            cluster_id=cluster_id,
            transport=members[0].transport,
            flow_ids=[flow.flow_id for flow in members],
            fingerprint_sha256=full_hashes[cluster_id],
            confidence=0.8 if len(members) >= 2 else 0.55,
            profile=fingerprints[cluster_id],
            hypotheses=[],
        ))
    return clusters, assignments
