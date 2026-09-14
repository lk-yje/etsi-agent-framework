"""基于确定性协议事实与脱敏 Payload 统计的保守加密分类。"""

from __future__ import annotations

from contracts.traffic_intelligence import (
    EncryptionAssessment,
    EncryptionClassification,
    PayloadProfile,
)


def classify_encryption(
    flow_id: str,
    *,
    payload_profile: PayloadProfile | None,
    security_protocols: set[str] | None = None,
    tls_versions: set[str] | None = None,
    cipher_suites: set[str] | None = None,
    frame_refs: list[int] | None = None,
) -> EncryptionAssessment:
    security = {item.lower() for item in (security_protocols or set())}
    versions = sorted(tls_versions or set())
    ciphers = sorted(cipher_suites or set())
    refs = sorted(set(frame_refs or []))
    if security:
        protocol = sorted(security)[0].upper()
        return EncryptionAssessment(
            flow_id=flow_id,
            classification=EncryptionClassification.STANDARD_ENCRYPTION_CONFIRMED,
            confidence=1.0,
            basis=[f"tshark frame.protocols 包含 {protocol}"],
            security_protocol=protocol,
            negotiated_version=versions[-1] if versions else None,
            cipher_suites=ciphers,
            frame_refs=refs,
            algorithm_claim_verifiable=bool(ciphers),
        )

    if payload_profile is None or payload_profile.sampled_bytes == 0:
        return EncryptionAssessment(
            flow_id=flow_id,
            classification=EncryptionClassification.INSUFFICIENT_EVIDENCE,
            confidence=0.0,
            basis=["没有可分析的应用 Payload"],
            limitations=["未观察到标准安全协议不能等同于明文"],
            frame_refs=refs[:2],
        )

    hints = set(payload_profile.format_hints)
    strong_plaintext = bool(hints & {"HTTP", "JSON_LIKE", "XML_LIKE"})
    mostly_printable = (
        payload_profile.sampled_bytes >= 64
        and (payload_profile.printable_ratio or 0.0) >= 0.92
        and (payload_profile.entropy or 0.0) <= 6.5
    )
    if strong_plaintext or mostly_printable:
        return EncryptionAssessment(
            flow_id=flow_id,
            classification=EncryptionClassification.PLAINTEXT_CONFIRMED,
            confidence=0.98 if strong_plaintext else 0.9,
            basis=[
                "Payload 具有可复核的明文格式特征",
                f"format_hints={','.join(payload_profile.format_hints) or 'none'}",
                f"printable_ratio={payload_profile.printable_ratio}",
                f"entropy={payload_profile.entropy}",
            ],
            limitations=["分类说明传输可读性，不评价字段语义或认证机制安全性"],
            frame_refs=refs[:8],
        )

    if payload_profile.sampled_bytes >= 256 and (payload_profile.entropy or 0.0) >= 7.2:
        return EncryptionAssessment(
            flow_id=flow_id,
            classification=EncryptionClassification.OPAQUE_HIGH_ENTROPY,
            confidence=0.85,
            basis=[
                f"有界样本 entropy={payload_profile.entropy}",
                f"sampled_bytes={payload_profile.sampled_bytes}",
            ],
            limitations=[
                "高熵可能来自压缩、编码或加密；不能据此确认算法或安全强度",
                "未观察到标准 TLS/DTLS/QUIC dissector",
            ],
            frame_refs=refs[:8],
        )

    return EncryptionAssessment(
        flow_id=flow_id,
        classification=EncryptionClassification.INSUFFICIENT_EVIDENCE,
        confidence=0.25,
        basis=[
            f"sampled_bytes={payload_profile.sampled_bytes}",
            f"printable_ratio={payload_profile.printable_ratio}",
            f"entropy={payload_profile.entropy}",
        ],
        limitations=["现有统计不足以证明明文或加密，需要协议说明或 dissector"],
        frame_refs=refs[:8],
    )
