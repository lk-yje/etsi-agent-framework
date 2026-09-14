"""Traffic Intelligence 的稳定数据合约。

这些模型只描述可进入标准 Bundle 的结构化事实和脱敏画像。原始 Payload、
完整 Stream、Cookie、Authorization 等受限数据不得加入这些公共合约。
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class TrafficModel(BaseModel):
    """所有 Traffic Intelligence 合约的严格基类。"""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class FlowDirection(str, Enum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    LATERAL = "LATERAL"
    UNKNOWN = "UNKNOWN"


class ProtocolCandidateStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    UNKNOWN = "UNKNOWN"


class ProtocolBasisType(str, Enum):
    TSHARK_DISSECTOR = "tshark_dissector"
    DECODE_AS = "decode_as"
    PORT_HINT = "port_hint"
    PAYLOAD_SIGNATURE = "payload_signature"
    TLS_METADATA = "tls_metadata"
    VENDOR_DISSECTOR = "vendor_dissector"
    AI_HYPOTHESIS = "ai_hypothesis"
    FRAME_PROTOCOLS = "frame_protocols"


class EncryptionClassification(str, Enum):
    STANDARD_ENCRYPTION_CONFIRMED = "STANDARD_ENCRYPTION_CONFIRMED"
    PLAINTEXT_CONFIRMED = "PLAINTEXT_CONFIRMED"
    OPAQUE_HIGH_ENTROPY = "OPAQUE_HIGH_ENTROPY"
    CUSTOM_ENCRYPTION_POSSIBLE = "CUSTOM_ENCRYPTION_POSSIBLE"
    ENCAPSULATED_ENCRYPTION = "ENCAPSULATED_ENCRYPTION"
    MIXED = "MIXED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class AlignmentStatus(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    NOT_OBSERVED = "NOT_OBSERVED"
    UNDECLARED_OBSERVED = "UNDECLARED_OBSERVED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ActivityKind(str, Enum):
    FLOW_BURST = "FLOW_BURST"
    TRANSFER = "TRANSFER"
    HEARTBEAT = "HEARTBEAT"
    RECONNECT = "RECONNECT"
    ENDPOINT_CHANGE = "ENDPOINT_CHANGE"
    UNATTRIBUTED_ACTIVITY = "UNATTRIBUTED_ACTIVITY"


def _validate_sha256(value: str) -> str:
    normalized = value.lower()
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise ValueError("必须是 64 位十六进制 SHA-256")
    return normalized


def _validate_relative_artifact_path(value: str) -> str:
    normalized = value.replace("\\", "/").strip()
    posix = PurePosixPath(normalized)
    windows = PureWindowsPath(value)
    if (
        not normalized
        or normalized.startswith("/")
        or windows.is_absolute()
        or windows.drive
        or ".." in posix.parts
        or any(part in {"", "."} for part in posix.parts)
    ):
        raise ValueError("artifact path 必须是 Bundle 内的安全相对路径")
    return posix.as_posix()


def _validate_identifier(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}", value):
        raise ValueError("identifier 只能包含字母、数字、点、下划线和连字符")
    return value


class BundleArtifact(TrafficModel):
    path: str
    sha256: str
    size: int = Field(ge=0)
    media_type: str = "application/json"

    _path_is_relative = field_validator("path")(_validate_relative_artifact_path)
    _sha256_is_valid = field_validator("sha256")(_validate_sha256)


class TrafficCaptureManifest(TrafficModel):
    schema_version: int = Field(default=1, ge=1)
    capture_sha256: str
    capture_size: int = Field(ge=0)
    capture_format: str
    capture_artifact: str = "capture.pcap"
    capture_started_at: datetime | None = None
    capture_finished_at: datetime | None = None
    dut_addresses: list[str] = Field(default_factory=list)
    requested_backend: str = "auto"
    analysis_backend: str
    fallback_reason: str | None = None
    backend_version: str = "unknown"
    tshark_version: str = "unknown"
    analysis_started_at: datetime
    analysis_finished_at: datetime | None = None
    complete: bool = False
    warnings: list[str] = Field(default_factory=list)
    artifacts: list[BundleArtifact] = Field(default_factory=list)

    _sha256_is_valid = field_validator("capture_sha256")(_validate_sha256)
    _capture_artifact_is_relative = field_validator("capture_artifact")(
        _validate_relative_artifact_path
    )

    @field_validator("dut_addresses")
    @classmethod
    def validate_dut_addresses(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            normalized.append(str(ipaddress.ip_address(value)))
        return list(dict.fromkeys(normalized))

    @model_validator(mode="after")
    def complete_manifest_has_finish_time(self) -> "TrafficCaptureManifest":
        if self.complete and self.analysis_finished_at is None:
            raise ValueError("complete manifest 必须包含 analysis_finished_at")
        return self


class ObservedPacketRef(TrafficModel):
    frame_number: int = Field(ge=1)
    reasons: list[str] = Field(default_factory=list)


class ProtocolBasis(TrafficModel):
    type: ProtocolBasisType
    value: str
    frame_number: int | None = Field(default=None, ge=1)
    details: dict[str, Any] = Field(default_factory=dict)


class ProtocolCandidate(TrafficModel):
    name: str = Field(min_length=1)
    layer: str = "application"
    confidence: float = Field(ge=0.0, le=1.0)
    status: ProtocolCandidateStatus
    basis: list[ProtocolBasis] = Field(default_factory=list)

    @model_validator(mode="after")
    def confirmed_candidate_has_deterministic_basis(self) -> "ProtocolCandidate":
        if self.status != ProtocolCandidateStatus.CONFIRMED:
            return self
        deterministic = {
            ProtocolBasisType.TSHARK_DISSECTOR,
            ProtocolBasisType.DECODE_AS,
            ProtocolBasisType.VENDOR_DISSECTOR,
            ProtocolBasisType.FRAME_PROTOCOLS,
            ProtocolBasisType.TLS_METADATA,
        }
        if not any(item.type in deterministic for item in self.basis):
            raise ValueError("CONFIRMED 协议必须包含确定性解析依据")
        return self


class PayloadProfile(TrafficModel):
    flow_id: str
    payload_bytes: int = Field(default=0, ge=0)
    sampled_bytes: int = Field(default=0, ge=0)
    printable_ratio: float | None = Field(default=None, ge=0.0, le=1.0)
    utf8_ratio: float | None = Field(default=None, ge=0.0, le=1.0)
    entropy: float | None = Field(default=None, ge=0.0, le=8.0)
    format_hints: list[str] = Field(default_factory=list)
    stable_prefix_sha256: str | None = None
    packet_length_summary: dict[str, float | int] = Field(default_factory=dict)
    timing_summary: dict[str, float | int] = Field(default_factory=dict)
    direction_length_sequence: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    sample_policy: str = "metadata_only"

    _flow_id_is_safe = field_validator("flow_id")(_validate_identifier)

    @field_validator("stable_prefix_sha256")
    @classmethod
    def validate_optional_sha256(cls, value: str | None) -> str | None:
        return _validate_sha256(value) if value is not None else None


class EncryptionAssessment(TrafficModel):
    flow_id: str
    classification: EncryptionClassification
    confidence: float = Field(ge=0.0, le=1.0)
    basis: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    security_protocol: str | None = None
    negotiated_version: str | None = None
    cipher_suites: list[str] = Field(default_factory=list)
    frame_refs: list[int] = Field(default_factory=list)
    algorithm_claim_verifiable: bool = False

    _flow_id_is_safe = field_validator("flow_id")(_validate_identifier)

    @field_validator("frame_refs")
    @classmethod
    def validate_frame_refs(cls, values: list[int]) -> list[int]:
        if any(value < 1 for value in values):
            raise ValueError("frame refs 必须大于 0")
        return sorted(set(values))


class ObservedFrame(TrafficModel):
    frame_number: int = Field(ge=1)
    flow_id: str | None = None
    timestamp_epoch: float = Field(ge=0)
    frame_length: int = Field(ge=0)
    src_address: str | None = None
    dst_address: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    transport: str | None = None
    stream_id: int | None = Field(default=None, ge=0)
    protocol_stack: list[str] = Field(default_factory=list)
    displayed_protocol: str | None = None
    dns_names: list[str] = Field(default_factory=list)
    dns_answers: list[str] = Field(default_factory=list)
    dns_cnames: list[str] = Field(default_factory=list)
    sni: list[str] = Field(default_factory=list)
    http_method: str | None = None
    http_host: str | None = None
    http_status: int | None = Field(default=None, ge=100, le=999)
    tls_handshake_types: list[int] = Field(default_factory=list)
    tcp_flags: str | None = None
    retransmission: bool = False
    out_of_order: bool = False

    @field_validator("flow_id")
    @classmethod
    def validate_optional_flow_id(cls, value: str | None) -> str | None:
        return _validate_identifier(value) if value else None

    @field_validator("src_address", "dst_address")
    @classmethod
    def validate_optional_ip(cls, value: str | None) -> str | None:
        return str(ipaddress.ip_address(value)) if value else None

    @field_validator("dns_answers")
    @classmethod
    def validate_dns_answers(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            normalized.append(str(ipaddress.ip_address(value)))
        return list(dict.fromkeys(normalized))


class ObservedFlow(TrafficModel):
    flow_id: str
    transport: str
    ip_version: int = Field(ge=4, le=6)
    src_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_ip: str
    dst_port: int = Field(ge=0, le=65535)
    direction_relative_to_dut: FlowDirection = FlowDirection.UNKNOWN
    first_frame: int = Field(ge=1)
    last_frame: int = Field(ge=1)
    frame_count: int = Field(ge=1)
    bytes_src_to_dst: int = Field(default=0, ge=0)
    bytes_dst_to_src: int = Field(default=0, ge=0)
    duration_ms: float = Field(default=0, ge=0)
    stream_id: int | None = Field(default=None, ge=0)
    dns_names: list[str] = Field(default_factory=list)
    sni: list[str] = Field(default_factory=list)
    protocol_candidates: list[ProtocolCandidate] = Field(default_factory=list)
    encryption: EncryptionAssessment | None = None
    payload_profile_ref: str | None = None
    frame_refs: list[int] = Field(default_factory=list)
    unknown_cluster_id: str | None = None

    _flow_id_is_safe = field_validator("flow_id")(_validate_identifier)

    @field_validator("unknown_cluster_id")
    @classmethod
    def validate_optional_cluster_id(cls, value: str | None) -> str | None:
        return _validate_identifier(value) if value else None

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))

    @field_validator("transport")
    @classmethod
    def normalize_transport(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in {"TCP", "UDP", "SCTP"}:
            raise ValueError("ObservedFlow 仅用于 TCP、UDP 或 SCTP 会话")
        return normalized

    @field_validator("payload_profile_ref")
    @classmethod
    def validate_payload_ref(cls, value: str | None) -> str | None:
        return _validate_relative_artifact_path(value) if value else None

    @model_validator(mode="after")
    def validate_frame_range(self) -> "ObservedFlow":
        if self.last_frame < self.first_frame:
            raise ValueError("last_frame 不能小于 first_frame")
        object.__setattr__(self, "frame_refs", sorted(set(self.frame_refs)))
        if any(value < 1 for value in self.frame_refs):
            raise ValueError("frame refs 必须大于 0")
        if self.encryption and self.encryption.flow_id != self.flow_id:
            raise ValueError("encryption.flow_id 必须与 flow_id 一致")
        return self


class ObservedProtocolRecord(TrafficModel):
    observation_id: str
    frame_number: int = Field(ge=1)
    protocol: str
    src_address: str | None = None
    dst_address: str | None = None
    frame_length: int = Field(default=0, ge=0)
    direction_relative_to_dut: FlowDirection = FlowDirection.UNKNOWN
    protocol_stack: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class UnknownProtocolCluster(TrafficModel):
    cluster_id: str
    transport: str
    flow_ids: list[str]
    fingerprint_sha256: str
    confidence: float = Field(ge=0.0, le=1.0)
    profile: dict[str, Any] = Field(default_factory=dict)
    hypotheses: list[str] = Field(default_factory=list)

    _cluster_id_is_safe = field_validator("cluster_id")(_validate_identifier)
    _fingerprint_is_valid = field_validator("fingerprint_sha256")(_validate_sha256)


class AutomaticActivityWindow(TrafficModel):
    window_id: str
    start_offset_ms: float = Field(ge=0)
    end_offset_ms: float = Field(ge=0)
    flow_ids: list[str] = Field(default_factory=list)
    kind: ActivityKind = ActivityKind.UNATTRIBUTED_ACTIVITY
    confidence: float = Field(ge=0.0, le=1.0)
    observations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_window(self) -> "AutomaticActivityWindow":
        if self.end_offset_ms < self.start_offset_ms:
            raise ValueError("活动窗口结束时间不能早于开始时间")
        return self


class TrafficDeclarationSource(TrafficModel):
    artifact: str
    table: str
    row: int | None = Field(default=None, ge=1)

    _artifact_is_relative = field_validator("artifact")(_validate_relative_artifact_path)


class TrafficDeclaration(TrafficModel):
    declaration_id: str
    source: TrafficDeclarationSource
    raw_text_sha256: str
    purpose: str | None = None
    direction: FlowDirection | None = None
    transport: list[str] = Field(default_factory=list)
    application_protocol: list[str] = Field(default_factory=list)
    local_ports: list[int] = Field(default_factory=list)
    remote_ports: list[int] = Field(default_factory=list)
    remote_hosts: list[str] = Field(default_factory=list)
    encryption_expected: bool | None = None
    encryption_protocol: list[str] = Field(default_factory=list)
    minimum_version: str | None = None
    algorithm_claims: list[str] = Field(default_factory=list)
    normalization_warnings: list[str] = Field(default_factory=list)

    _raw_text_hash_is_valid = field_validator("raw_text_sha256")(_validate_sha256)

    @field_validator("local_ports", "remote_ports")
    @classmethod
    def validate_ports(cls, values: list[int]) -> list[int]:
        if any(value < 0 or value > 65535 for value in values):
            raise ValueError("端口必须位于 0..65535")
        return sorted(set(values))


class DeclarationAlignment(TrafficModel):
    alignment_id: str
    declaration_id: str | None = None
    flow_ids: list[str] = Field(default_factory=list)
    overall: AlignmentStatus
    dimensions: dict[str, AlignmentStatus] = Field(default_factory=dict)
    reason: str
    frame_refs: list[int] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_alignment_semantics(self) -> "DeclarationAlignment":
        if self.overall == AlignmentStatus.UNDECLARED_OBSERVED and self.declaration_id is not None:
            raise ValueError("UNDECLARED_OBSERVED 不应绑定 declaration_id")
        if self.overall != AlignmentStatus.UNDECLARED_OBSERVED and self.declaration_id is None:
            raise ValueError("声明对齐结果必须绑定 declaration_id")
        object.__setattr__(self, "frame_refs", sorted(set(self.frame_refs)))
        return self


class TrafficIntelligenceBundleIndex(TrafficModel):
    schema_version: int = Field(default=1, ge=1)
    capture_sha256: str
    flow_count: int = Field(default=0, ge=0)
    non_session_observation_count: int = Field(default=0, ge=0)
    endpoint_count: int = Field(default=0, ge=0)
    unknown_cluster_count: int = Field(default=0, ge=0)
    declaration_count: int = Field(default=0, ge=0)
    alignment_counts: dict[AlignmentStatus, int] = Field(default_factory=dict)
    high_risk_flow_ids: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    _capture_hash_is_valid = field_validator("capture_sha256")(_validate_sha256)
