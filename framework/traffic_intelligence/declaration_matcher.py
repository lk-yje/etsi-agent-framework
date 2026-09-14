"""IXIT 流量声明与观测 Flow 的保守、逐维匹配。"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Iterable, Sequence

from contracts.traffic_intelligence import (
    AlignmentStatus,
    DeclarationAlignment,
    EncryptionClassification,
    FlowDirection,
    ObservedFlow,
    ProtocolCandidateStatus,
    TrafficDeclaration,
)


_TLS_CIPHER_IDS = {
    "0X1301": "TLS-AES-128-GCM-SHA256",
    "0X1302": "TLS-AES-256-GCM-SHA384",
    "0X1303": "TLS-CHACHA20-POLY1305-SHA256",
}

_IDENTITY_DIMENSIONS = ("application_protocol", "port", "remote_target")
_CLAIM_DIMENSIONS = (
    "direction",
    "transport",
    "application_protocol",
    "port",
    "remote_target",
    "encryption",
    "encryption_protocol",
    "minimum_version",
    "algorithm_claims",
)


def _normalize_token(value: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "", value.upper())


def _normalize_cipher(value: str) -> str:
    upper = value.strip().upper().replace("_", "-")
    return _TLS_CIPHER_IDS.get(upper, upper)


def _observed_protocols(flow: ObservedFlow) -> tuple[set[str], bool]:
    names = {
        _normalize_token(candidate.name)
        for candidate in flow.protocol_candidates
        if candidate.status != ProtocolCandidateStatus.UNKNOWN
    }
    unknown_only = not names
    if flow.encryption and flow.encryption.security_protocol:
        names.add(_normalize_token(flow.encryption.security_protocol))
    return names, unknown_only


def _application_status(declaration: TrafficDeclaration, flow: ObservedFlow) -> AlignmentStatus:
    if not declaration.application_protocol:
        return AlignmentStatus.NOT_APPLICABLE
    observed, unknown_only = _observed_protocols(flow)
    declared = {_normalize_token(item) for item in declaration.application_protocol}
    if declared.intersection(observed):
        return AlignmentStatus.MATCH

    # 加密封装下 tshark 可能只能确定 TLS，而看不到内层 HTTP/MQTT。
    secure_aliases = {
        "HTTPS": "TLS",
        "MQTTS": "TLS",
        "COAPS": "DTLS",
        "FTPS": "TLS",
        "SMTPS": "TLS",
        "IMAPS": "TLS",
        "POP3S": "TLS",
        "RTSPS": "TLS",
        "SFTP": "SSH",
    }
    if any(secure_aliases.get(item) in observed for item in declared):
        return AlignmentStatus.MATCH
    if unknown_only:
        return AlignmentStatus.INSUFFICIENT_EVIDENCE
    return AlignmentStatus.MISMATCH


def _flow_ports(flow: ObservedFlow) -> tuple[int | None, int | None]:
    if flow.direction_relative_to_dut == FlowDirection.OUTBOUND:
        return flow.src_port, flow.dst_port
    if flow.direction_relative_to_dut == FlowDirection.INBOUND:
        return flow.dst_port, flow.src_port
    return None, None


def _port_status(declaration: TrafficDeclaration, flow: ObservedFlow) -> AlignmentStatus:
    if not declaration.local_ports and not declaration.remote_ports:
        return AlignmentStatus.NOT_APPLICABLE
    local_port, remote_port = _flow_ports(flow)
    if local_port is None or remote_port is None:
        observed = {flow.src_port, flow.dst_port}
        expected = set(declaration.local_ports) | set(declaration.remote_ports)
        return (
            AlignmentStatus.MATCH
            if expected.intersection(observed)
            else AlignmentStatus.INSUFFICIENT_EVIDENCE
        )
    local_matches = not declaration.local_ports or local_port in declaration.local_ports
    remote_matches = not declaration.remote_ports or remote_port in declaration.remote_ports
    return AlignmentStatus.MATCH if local_matches and remote_matches else AlignmentStatus.MISMATCH


def _remote_endpoint(flow: ObservedFlow) -> str | None:
    if flow.direction_relative_to_dut == FlowDirection.OUTBOUND:
        return flow.dst_ip
    if flow.direction_relative_to_dut == FlowDirection.INBOUND:
        return flow.src_ip
    return None


def _normalize_host(value: str) -> str:
    candidate = value.strip().strip("[]").rstrip(".").casefold()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return candidate


def _remote_target_status(declaration: TrafficDeclaration, flow: ObservedFlow) -> AlignmentStatus:
    if not declaration.remote_hosts:
        return AlignmentStatus.NOT_APPLICABLE
    observed = {_normalize_host(item) for item in (*flow.dns_names, *flow.sni)}
    endpoint = _remote_endpoint(flow)
    if endpoint:
        observed.add(_normalize_host(endpoint))
    if not observed:
        return AlignmentStatus.INSUFFICIENT_EVIDENCE
    expected = {_normalize_host(item) for item in declaration.remote_hosts}
    return AlignmentStatus.MATCH if expected.intersection(observed) else AlignmentStatus.MISMATCH


def _encryption_status(declaration: TrafficDeclaration, flow: ObservedFlow) -> AlignmentStatus:
    if declaration.encryption_expected is None:
        return AlignmentStatus.NOT_APPLICABLE
    if flow.encryption is None:
        return AlignmentStatus.INSUFFICIENT_EVIDENCE
    classification = flow.encryption.classification
    confirmed_encrypted = {
        EncryptionClassification.STANDARD_ENCRYPTION_CONFIRMED,
        EncryptionClassification.ENCAPSULATED_ENCRYPTION,
    }
    if classification == EncryptionClassification.MIXED:
        return AlignmentStatus.MISMATCH
    if classification in {
        EncryptionClassification.OPAQUE_HIGH_ENTROPY,
        EncryptionClassification.CUSTOM_ENCRYPTION_POSSIBLE,
        EncryptionClassification.INSUFFICIENT_EVIDENCE,
    }:
        return AlignmentStatus.INSUFFICIENT_EVIDENCE
    observed_encrypted = classification in confirmed_encrypted
    return (
        AlignmentStatus.MATCH
        if observed_encrypted == declaration.encryption_expected
        else AlignmentStatus.MISMATCH
    )


def _encryption_protocol_status(
    declaration: TrafficDeclaration,
    flow: ObservedFlow,
) -> AlignmentStatus:
    if not declaration.encryption_protocol:
        return AlignmentStatus.NOT_APPLICABLE
    if not flow.encryption or not flow.encryption.security_protocol:
        return AlignmentStatus.INSUFFICIENT_EVIDENCE
    declared = {_normalize_token(item) for item in declaration.encryption_protocol}
    observed = _normalize_token(flow.encryption.security_protocol)
    return AlignmentStatus.MATCH if observed in declared else AlignmentStatus.MISMATCH


def _version_tuple(value: str) -> tuple[int, ...] | None:
    match = re.search(r"\d+(?:\.\d+)+", value)
    return tuple(int(part) for part in match.group().split(".")) if match else None


def _minimum_version_status(
    declaration: TrafficDeclaration,
    flow: ObservedFlow,
) -> AlignmentStatus:
    if not declaration.minimum_version:
        return AlignmentStatus.NOT_APPLICABLE
    if not flow.encryption or not flow.encryption.negotiated_version:
        return AlignmentStatus.INSUFFICIENT_EVIDENCE
    minimum = _version_tuple(declaration.minimum_version)
    observed = _version_tuple(flow.encryption.negotiated_version)
    if minimum is None or observed is None:
        return AlignmentStatus.INSUFFICIENT_EVIDENCE
    return AlignmentStatus.MATCH if observed >= minimum else AlignmentStatus.MISMATCH


def _algorithm_status(declaration: TrafficDeclaration, flow: ObservedFlow) -> AlignmentStatus:
    if not declaration.algorithm_claims:
        return AlignmentStatus.NOT_APPLICABLE
    if not flow.encryption or not flow.encryption.algorithm_claim_verifiable:
        return AlignmentStatus.INSUFFICIENT_EVIDENCE
    observed = {_normalize_cipher(value) for value in flow.encryption.cipher_suites}
    if not observed:
        return AlignmentStatus.INSUFFICIENT_EVIDENCE
    declared = {_normalize_cipher(value) for value in declaration.algorithm_claims}
    return AlignmentStatus.MATCH if declared.intersection(observed) else AlignmentStatus.MISMATCH


def _dimension_statuses(
    declaration: TrafficDeclaration,
    flow: ObservedFlow,
) -> dict[str, AlignmentStatus]:
    if declaration.direction is None:
        direction = AlignmentStatus.NOT_APPLICABLE
    elif flow.direction_relative_to_dut == FlowDirection.UNKNOWN:
        direction = AlignmentStatus.INSUFFICIENT_EVIDENCE
    else:
        direction = (
            AlignmentStatus.MATCH
            if declaration.direction == flow.direction_relative_to_dut
            else AlignmentStatus.MISMATCH
        )

    if not declaration.transport:
        transport = AlignmentStatus.NOT_APPLICABLE
    else:
        transport = (
            AlignmentStatus.MATCH
            if flow.transport.upper() in {item.upper() for item in declaration.transport}
            else AlignmentStatus.MISMATCH
        )

    return {
        "direction": direction,
        "transport": transport,
        "application_protocol": _application_status(declaration, flow),
        "port": _port_status(declaration, flow),
        "remote_target": _remote_target_status(declaration, flow),
        "encryption": _encryption_status(declaration, flow),
        "encryption_protocol": _encryption_protocol_status(declaration, flow),
        "minimum_version": _minimum_version_status(declaration, flow),
        "algorithm_claims": _algorithm_status(declaration, flow),
    }


def _relevance(dimensions: dict[str, AlignmentStatus]) -> int:
    weights = {
        "direction": 1,
        "transport": 2,
        "application_protocol": 5,
        "port": 5,
        "remote_target": 6,
        "encryption": 1,
        "encryption_protocol": 2,
    }
    return sum(
        weights.get(name, 0)
        for name, status in dimensions.items()
        if status == AlignmentStatus.MATCH
    )


def _has_identity_match(dimensions: dict[str, AlignmentStatus]) -> bool:
    return any(dimensions[name] == AlignmentStatus.MATCH for name in _IDENTITY_DIMENSIONS)


def _aggregate(values: Sequence[AlignmentStatus]) -> AlignmentStatus:
    if AlignmentStatus.MISMATCH in values:
        return AlignmentStatus.MISMATCH
    if AlignmentStatus.MATCH in values:
        return AlignmentStatus.MATCH
    if AlignmentStatus.INSUFFICIENT_EVIDENCE in values:
        return AlignmentStatus.INSUFFICIENT_EVIDENCE
    return AlignmentStatus.NOT_APPLICABLE


def _overall(dimensions: dict[str, AlignmentStatus]) -> AlignmentStatus:
    comparable = [dimensions[name] for name in _CLAIM_DIMENSIONS]
    if AlignmentStatus.MISMATCH in comparable:
        return AlignmentStatus.MISMATCH
    if AlignmentStatus.INSUFFICIENT_EVIDENCE in comparable:
        return AlignmentStatus.INSUFFICIENT_EVIDENCE
    if AlignmentStatus.MATCH in comparable:
        return AlignmentStatus.MATCH
    return AlignmentStatus.INSUFFICIENT_EVIDENCE


def _alignment_id(declaration_id: str | None, flow_ids: Sequence[str], overall: AlignmentStatus) -> str:
    material = "\0".join((declaration_id or "undeclared", overall.value, *sorted(flow_ids)))
    return f"alignment-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"


def _confidence(overall: AlignmentStatus, dimensions: dict[str, AlignmentStatus]) -> float:
    compared = [status for status in dimensions.values() if status != AlignmentStatus.NOT_APPLICABLE]
    if not compared:
        return 0.0
    coverage = len(compared) / len(dimensions)
    base = {
        AlignmentStatus.MATCH: 0.95,
        AlignmentStatus.MISMATCH: 0.95,
        AlignmentStatus.INSUFFICIENT_EVIDENCE: 0.45,
        AlignmentStatus.NOT_OBSERVED: 0.75,
        AlignmentStatus.UNDECLARED_OBSERVED: 0.9,
    }.get(overall, 0.5)
    return round(min(1.0, base * (0.75 + 0.25 * coverage)), 3)


def align_traffic_declarations(
    declarations: Iterable[TrafficDeclaration],
    flows: Iterable[ObservedFlow],
) -> list[DeclarationAlignment]:
    """为每条声明选择最相关 Flow，并单独列出未被任何声明解释的 Flow。"""
    declaration_list = sorted(declarations, key=lambda item: item.declaration_id)
    flow_list = sorted(flows, key=lambda item: item.flow_id)
    alignments: list[DeclarationAlignment] = []
    associated_flow_ids: set[str] = set()

    for declaration in declaration_list:
        scored: list[tuple[int, ObservedFlow, dict[str, AlignmentStatus]]] = []
        for flow in flow_list:
            dimensions = _dimension_statuses(declaration, flow)
            if not _has_identity_match(dimensions):
                continue
            scored.append((_relevance(dimensions), flow, dimensions))

        if not scored:
            overall = AlignmentStatus.NOT_OBSERVED
            alignments.append(DeclarationAlignment(
                alignment_id=_alignment_id(declaration.declaration_id, [], overall),
                declaration_id=declaration.declaration_id,
                flow_ids=[],
                overall=overall,
                dimensions={},
                reason="当前连续抓包中没有 Flow 与该声明的协议、端口或远端目标形成确定关联",
                frame_refs=[],
                confidence=0.75,
            ))
            continue

        best_score = max(score for score, _flow, _dimensions in scored)
        selected = [item for item in scored if item[0] == best_score]
        selected_flows = [flow for _score, flow, _dimensions in selected]
        aggregate_dimensions = {
            name: _aggregate([dimensions[name] for _score, _flow, dimensions in selected])
            for name in _CLAIM_DIMENSIONS
        }
        overall = _overall(aggregate_dimensions)
        flow_ids = [flow.flow_id for flow in selected_flows]
        associated_flow_ids.update(flow_ids)
        mismatches = [
            name for name, status in aggregate_dimensions.items()
            if status == AlignmentStatus.MISMATCH
        ]
        insufficient = [
            name for name, status in aggregate_dimensions.items()
            if status == AlignmentStatus.INSUFFICIENT_EVIDENCE
        ]
        if mismatches:
            reason = "已关联 Flow，但以下维度与声明不一致: " + ", ".join(mismatches)
        elif insufficient:
            reason = "已关联 Flow，但以下声明维度缺少可验证事实: " + ", ".join(insufficient)
        else:
            reason = "已关联 Flow 的可验证维度与声明一致"
        refs = sorted({ref for flow in selected_flows for ref in flow.frame_refs})[:40]
        alignments.append(DeclarationAlignment(
            alignment_id=_alignment_id(declaration.declaration_id, flow_ids, overall),
            declaration_id=declaration.declaration_id,
            flow_ids=flow_ids,
            overall=overall,
            dimensions=aggregate_dimensions,
            reason=reason,
            frame_refs=refs,
            confidence=_confidence(overall, aggregate_dimensions),
        ))

    for flow in flow_list:
        if flow.flow_id in associated_flow_ids:
            continue
        overall = AlignmentStatus.UNDECLARED_OBSERVED
        alignments.append(DeclarationAlignment(
            alignment_id=_alignment_id(None, [flow.flow_id], overall),
            declaration_id=None,
            flow_ids=[flow.flow_id],
            overall=overall,
            dimensions={"declaration": AlignmentStatus.UNDECLARED_OBSERVED},
            reason="该观测 Flow 未能与任何 11-ComMech 声明建立确定关联",
            frame_refs=flow.frame_refs[:40],
            confidence=0.9,
        ))

    return alignments


__all__ = ["align_traffic_declarations"]
