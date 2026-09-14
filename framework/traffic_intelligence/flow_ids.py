"""与输入顺序无关、可重复生成的 Flow 和未知协议集群 ID。"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Mapping
from typing import Any


def _endpoint_sort_key(address: str, port: int) -> tuple[int, bytes, int]:
    parsed = ipaddress.ip_address(address)
    if port < 0 or port > 65535:
        raise ValueError("端口必须位于 0..65535")
    return parsed.version, parsed.packed, port


def canonical_flow_key(
    transport: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    *,
    stream_id: int | None = None,
) -> tuple[str, str, int, str, int, int | None]:
    """生成双向一致的会话键，同时保留 tshark stream 以区分重复连接。"""
    normalized_transport = transport.strip().upper()
    if normalized_transport not in {"TCP", "UDP", "SCTP"}:
        raise ValueError("Flow transport 必须是 TCP、UDP 或 SCTP")
    if stream_id is not None and stream_id < 0:
        raise ValueError("stream_id 不能为负数")

    left_ip = str(ipaddress.ip_address(src_ip))
    right_ip = str(ipaddress.ip_address(dst_ip))
    left = (left_ip, src_port)
    right = (right_ip, dst_port)
    if _endpoint_sort_key(*right) < _endpoint_sort_key(*left):
        left, right = right, left
    return normalized_transport, left[0], left[1], right[0], right[1], stream_id


def stable_flow_id(
    transport: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    *,
    stream_id: int | None = None,
) -> str:
    key = canonical_flow_key(
        transport,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        stream_id=stream_id,
    )
    encoded = json.dumps(key, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return f"flow-{hashlib.sha256(encoded).hexdigest()[:20]}"


def _normalize_fingerprint_value(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("fingerprint 不得包含原始 Payload bytes")
    if isinstance(value, Mapping):
        return {
            str(key): _normalize_fingerprint_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_fingerprint_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"不支持的指纹字段类型: {type(value).__name__}")


def stable_unknown_cluster_id(transport: str, fingerprint: Mapping[str, Any]) -> str:
    """根据脱敏聚合特征生成稳定 cluster ID，不接收原始 Payload bytes。"""
    normalized_transport = transport.strip().lower()
    if normalized_transport not in {"tcp", "udp", "sctp"}:
        raise ValueError("未知协议 cluster transport 必须是 TCP、UDP 或 SCTP")
    normalized = _normalize_fingerprint_value(fingerprint)
    encoded = json.dumps(
        {"transport": normalized_transport, "fingerprint": normalized},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return f"unknown-{normalized_transport}-{hashlib.sha256(encoded).hexdigest()[:16]}"
