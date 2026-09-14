"""对 Payload 做有界增量统计，绝不把原始字节写入标准 Bundle。"""

from __future__ import annotations

import hashlib
import math
from collections import Counter

from contracts.traffic_intelligence import PayloadProfile


class IncrementalPayloadProfiler:
    """每个 Flow 最多采样固定字节数，内存不会随 PCAP 无限增长。"""

    def __init__(self, *, sample_limit: int = 65_536) -> None:
        if sample_limit < 0:
            raise ValueError("sample_limit 不能为负数")
        self.sample_limit = sample_limit
        self.payload_bytes = 0
        self.payload_packets = 0
        self.sampled_bytes = 0
        self.printable_bytes = 0
        self.byte_counts: Counter[int] = Counter()
        self.first_prefix_hash: str | None = None
        self.length_min: int | None = None
        self.length_max = 0
        self.direction_length_sequence: list[str] = []
        self._utf8_valid_bytes = 0
        self._format_hints: set[str] = set()

    @staticmethod
    def decode_tshark_hex(value: str | None) -> bytes:
        if not value:
            return b""
        # occurrence=a 可能以逗号拼接多个字段；逐段清理 Wireshark 的冒号格式。
        chunks: list[bytes] = []
        for part in value.split(","):
            compact = part.strip().replace(":", "").replace(" ", "")
            if not compact or len(compact) % 2:
                continue
            try:
                chunks.append(bytes.fromhex(compact))
            except ValueError:
                continue
        return b"".join(chunks)

    def add_tshark_hex(self, value: str | None, *, from_origin: bool) -> None:
        payload = self.decode_tshark_hex(value)
        if payload:
            self.add(payload, from_origin=from_origin)

    def add(self, payload: bytes, *, from_origin: bool) -> None:
        if not payload:
            return
        length = len(payload)
        self.payload_bytes += length
        self.payload_packets += 1
        self.length_min = length if self.length_min is None else min(self.length_min, length)
        self.length_max = max(self.length_max, length)
        if len(self.direction_length_sequence) < 32:
            direction = "origin_to_peer" if from_origin else "peer_to_origin"
            self.direction_length_sequence.append(f"{direction}:{length}")
        if self.first_prefix_hash is None:
            self.first_prefix_hash = hashlib.sha256(payload[:32]).hexdigest()

        remaining = max(0, self.sample_limit - self.sampled_bytes)
        sample = payload[:remaining]
        if not sample:
            return
        self.sampled_bytes += len(sample)
        self.byte_counts.update(sample)
        self.printable_bytes += sum(
            1 for value in sample if value in {9, 10, 13} or 32 <= value <= 126
        )
        decoded = sample.decode("utf-8", errors="ignore")
        self._utf8_valid_bytes += min(len(sample), len(decoded.encode("utf-8")))
        self._detect_format(sample)

    def _detect_format(self, sample: bytes) -> None:
        stripped = sample.lstrip()
        upper = stripped[:16].upper()
        if any(upper.startswith(method) for method in (
            b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"HTTP/"
        )):
            self._format_hints.add("HTTP")
        if stripped.startswith((b"{", b"[")):
            self._format_hints.add("JSON_LIKE")
        if stripped.startswith(b"<"):
            self._format_hints.add("XML_LIKE")

    def _entropy(self) -> float | None:
        if not self.sampled_bytes:
            return None
        return -sum(
            (count / self.sampled_bytes) * math.log2(count / self.sampled_bytes)
            for count in self.byte_counts.values()
        )

    def to_model(self, flow_id: str) -> PayloadProfile:
        printable_ratio = (
            self.printable_bytes / self.sampled_bytes if self.sampled_bytes else None
        )
        utf8_ratio = self._utf8_valid_bytes / self.sampled_bytes if self.sampled_bytes else None
        hints = set(self._format_hints)
        if printable_ratio is not None and printable_ratio >= 0.9:
            hints.add("MOSTLY_PRINTABLE")
        return PayloadProfile(
            flow_id=flow_id,
            payload_bytes=self.payload_bytes,
            sampled_bytes=self.sampled_bytes,
            printable_ratio=printable_ratio,
            utf8_ratio=utf8_ratio,
            entropy=self._entropy(),
            format_hints=sorted(hints),
            stable_prefix_sha256=self.first_prefix_hash,
            packet_length_summary={
                "packet_count": self.payload_packets,
                "min": self.length_min or 0,
                "max": self.length_max,
                "mean": (
                    self.payload_bytes / self.payload_packets if self.payload_packets else 0
                ),
            },
            direction_length_sequence=self.direction_length_sequence,
            findings=[],
            sample_policy="metadata_only",
        )
