"""直接调用 tshark 的流式离线分析后端。

后端不导出 tcp/udp payload，也不保留 tshark 原始 TSV。tshark 输出先落到当前
workspace 的临时文件以支持超时控制，再逐行规范化为 JSONL。
"""

from __future__ import annotations

import csv
import json
import os
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from contracts.traffic_intelligence import (
    FlowDirection,
    ObservedFlow,
    ObservedFrame,
    ObservedProtocolRecord,
    ProtocolBasis,
    ProtocolBasisType,
    ProtocolCandidate,
    ProtocolCandidateStatus,
)
from framework.traffic_intelligence.backends.base import (
    AnalysisBackend,
    BackendExecutionError,
    BackendRequest,
    BackendResult,
)
from framework.traffic_intelligence.flow_ids import canonical_flow_key, stable_flow_id
from framework.traffic_intelligence.encryption_classifier import classify_encryption
from framework.traffic_intelligence.payload_profiler import IncrementalPayloadProfiler


_DESIRED_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "_ws.col.Protocol",
    "eth.src",
    "eth.dst",
    "vlan.id",
    "ip.version",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "ipv6.nxt",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.len",
    "tcp.payload",
    "tcp.flags",
    "tcp.analysis.retransmission",
    "tcp.analysis.out_of_order",
    "udp.srcport",
    "udp.dstport",
    "udp.stream",
    "udp.length",
    "udp.payload",
    "sctp.srcport",
    "sctp.dstport",
    "sctp.assoc_index",
    "dns.qry.name",
    "dns.a",
    "dns.aaaa",
    "dns.cname",
    "http.request.method",
    "http.host",
    "http.response.code",
    "http.content_type",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
    "tls.handshake.extensions_alpn_str",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.ciphersuite",
)

_REQUIRED_FIELDS = {
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
}

_NON_APPLICATION_PROTOCOLS = {
    "eth",
    "ethertype",
    "vlan",
    "ip",
    "ipv6",
    "tcp",
    "udp",
    "sctp",
    "data",
    "icmp",
    "icmpv6",
    "arp",
}


def _creation_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def _as_int(value: str | None, default: int | None = None) -> int | None:
    try:
        return int(str(value).split(",", 1)[0]) if value not in {None, ""} else default
    except ValueError:
        return default


def _as_float(value: str | None, default: float = 0.0) -> float:
    try:
        return float(str(value).split(",", 1)[0]) if value not in {None, ""} else default
    except ValueError:
        return default


def _split_values(value: str | None) -> list[str]:
    if not value:
        return []
    return list(dict.fromkeys(part.strip() for part in value.split(",") if part.strip()))


def _protocol_stack(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip().lower() for part in value.split(":") if part.strip()]


def _direction(src: str, dst: str, dut_addresses: set[str]) -> FlowDirection:
    src_is_dut = src in dut_addresses
    dst_is_dut = dst in dut_addresses
    if src_is_dut and not dst_is_dut:
        return FlowDirection.OUTBOUND
    if dst_is_dut and not src_is_dut:
        return FlowDirection.INBOUND
    if src_is_dut and dst_is_dut:
        return FlowDirection.LATERAL
    return FlowDirection.UNKNOWN


def _application_protocol(displayed: str | None, stack: list[str]) -> str | None:
    shown = (displayed or "").strip().lower()
    if shown and shown not in _NON_APPLICATION_PROTOCOLS:
        return shown
    candidates = [item for item in stack if item not in _NON_APPLICATION_PROTOCOLS]
    return candidates[-1] if candidates else None


def _protocol_candidate(name: str | None, frame: int, stack: list[str]) -> ProtocolCandidate:
    if not name:
        return ProtocolCandidate(
            name="UNKNOWN",
            confidence=0.0,
            status=ProtocolCandidateStatus.UNKNOWN,
            basis=[],
        )
    return ProtocolCandidate(
        name=name.upper() if name in {"tls", "dtls", "quic", "http", "http2"} else name,
        confidence=1.0,
        status=ProtocolCandidateStatus.CONFIRMED,
        basis=[
            ProtocolBasis(
                type=ProtocolBasisType.TSHARK_DISSECTOR,
                value=name,
                frame_number=frame,
                details={"frame_protocols": ":".join(stack)},
            )
        ],
    )


@dataclass
class _FlowAccumulator:
    flow_id: str
    transport: str
    ip_version: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    direction: FlowDirection
    first_frame: int
    last_frame: int
    first_timestamp: float
    last_timestamp: float
    stream_id: int | None
    frame_count: int = 0
    bytes_src_to_dst: int = 0
    bytes_dst_to_src: int = 0
    dns_names: set[str] = field(default_factory=set)
    sni: set[str] = field(default_factory=set)
    application_protocols: dict[str, tuple[int, list[str]]] = field(default_factory=dict)
    security_protocols: set[str] = field(default_factory=set)
    cipher_suites: set[str] = field(default_factory=set)
    tls_versions: set[str] = field(default_factory=set)
    frame_refs: set[int] = field(default_factory=set)
    payload_profiler: IncrementalPayloadProfiler = field(
        default_factory=IncrementalPayloadProfiler
    )

    def update(
        self,
        *,
        frame_number: int,
        timestamp: float,
        frame_length: int,
        src_ip: str,
        src_port: int,
        stack: list[str],
        displayed_protocol: str | None,
        dns_names: list[str],
        sni: list[str],
        tls_versions: list[str],
        cipher_suites: list[str],
        handshake_types: list[int],
        payload_hex: str | None,
    ) -> None:
        self.frame_count += 1
        self.last_frame = max(self.last_frame, frame_number)
        self.last_timestamp = max(self.last_timestamp, timestamp)
        if src_ip == self.src_ip and src_port == self.src_port:
            self.bytes_src_to_dst += frame_length
            from_origin = True
        else:
            self.bytes_dst_to_src += frame_length
            from_origin = False
        self.payload_profiler.add_tshark_hex(payload_hex, from_origin=from_origin)
        self.dns_names.update(dns_names)
        self.sni.update(sni)
        self.tls_versions.update(tls_versions)
        self.cipher_suites.update(cipher_suites)
        app_protocol = _application_protocol(displayed_protocol, stack)
        if app_protocol and app_protocol not in self.application_protocols:
            self.application_protocols[app_protocol] = (frame_number, stack)
        for security_protocol in ("tls", "dtls", "quic"):
            if security_protocol in stack:
                self.security_protocols.add(security_protocol)
        self.frame_refs.update({self.first_frame, frame_number})
        if handshake_types:
            self.frame_refs.add(frame_number)
        if len(self.frame_refs) > 12:
            self.frame_refs = {self.first_frame, self.last_frame, *sorted(self.frame_refs)[:10]}

    def to_model(self) -> ObservedFlow:
        candidates = [
            _protocol_candidate(name, frame, stack)
            for name, (frame, stack) in sorted(self.application_protocols.items())
        ]
        if not candidates:
            candidates = [_protocol_candidate(None, self.first_frame, [])]
        profile = self.payload_profiler.to_model(self.flow_id)
        encryption = classify_encryption(
            self.flow_id,
            payload_profile=profile,
            security_protocols=self.security_protocols,
            tls_versions=self.tls_versions,
            cipher_suites=self.cipher_suites,
            frame_refs=sorted(self.frame_refs),
        )
        return ObservedFlow(
            flow_id=self.flow_id,
            transport=self.transport,
            ip_version=self.ip_version,
            src_ip=self.src_ip,
            src_port=self.src_port,
            dst_ip=self.dst_ip,
            dst_port=self.dst_port,
            direction_relative_to_dut=self.direction,
            first_frame=self.first_frame,
            last_frame=self.last_frame,
            frame_count=self.frame_count,
            bytes_src_to_dst=self.bytes_src_to_dst,
            bytes_dst_to_src=self.bytes_dst_to_src,
            duration_ms=max(0.0, (self.last_timestamp - self.first_timestamp) * 1000),
            stream_id=self.stream_id,
            dns_names=sorted(self.dns_names),
            sni=sorted(self.sni),
            protocol_candidates=candidates,
            encryption=encryption,
            payload_profile_ref=(
                f"payload-profiles/{self.flow_id}.json"
                if profile.payload_bytes
                else None
            ),
            frame_refs=sorted(self.frame_refs),
        )


class DirectTsharkBackend(AnalysisBackend):
    name = "direct_tshark"

    def __init__(self, tshark_path: str = "tshark") -> None:
        self.tshark_path = tshark_path

    def availability(self) -> tuple[bool, str]:
        try:
            result = subprocess.run(
                [self.tshark_path, "--version"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                shell=False,
                creationflags=_creation_flags(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"{type(exc).__name__}: {exc}"
        if result.returncode != 0:
            return False, (result.stderr or result.stdout or "tshark --version failed")[:500]
        return True, self._first_line(result.stdout)

    @staticmethod
    def _first_line(value: str) -> str:
        return next((line.strip() for line in value.splitlines() if line.strip()), "unknown")

    def _run_to_file(
        self,
        args: list[str],
        output_path: Path,
        stderr_path: Path,
        timeout_seconds: int,
    ) -> None:
        with output_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            try:
                process = subprocess.Popen(
                    args,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    shell=False,
                    creationflags=_creation_flags(),
                )
                process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait(timeout=10)
                raise BackendExecutionError(
                    f"tshark 超过 {timeout_seconds} 秒未完成"
                ) from exc
            except OSError as exc:
                raise BackendExecutionError(f"无法启动 tshark: {exc}") from exc
        if process.returncode != 0:
            details = stderr_path.read_text(encoding="utf-8", errors="replace")[:2000]
            raise BackendExecutionError(
                f"tshark 返回 {process.returncode}: {details or 'no stderr'}"
            )

    def _available_fields(self, request: BackendRequest) -> set[str]:
        registry = request.output_dir / f".tshark-fields-{uuid.uuid4().hex}.tsv"
        stderr = request.output_dir / f".tshark-fields-{uuid.uuid4().hex}.stderr"
        try:
            self._run_to_file(
                [request.tshark_path, "-G", "fields"],
                registry,
                stderr,
                min(request.timeout_seconds, 120),
            )
            available: set[str] = set()
            with registry.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    columns = line.rstrip("\n").split("\t")
                    if len(columns) >= 3 and columns[0] == "F":
                        available.add(columns[2])
            missing = _REQUIRED_FIELDS - available
            if missing:
                raise BackendExecutionError(
                    "tshark 缺少基础字段: " + ", ".join(sorted(missing))
                )
            return available
        finally:
            registry.unlink(missing_ok=True)
            stderr.unlink(missing_ok=True)

    def analyze(self, request: BackendRequest) -> BackendResult:
        request.output_dir.mkdir(parents=True, exist_ok=True)
        if request.output_dir.is_symlink():
            raise BackendExecutionError("拒绝写入符号链接形式的 backend output_dir")
        available, version = DirectTsharkBackend(request.tshark_path).availability()
        if not available:
            raise BackendExecutionError(version)

        supported = self._available_fields(request)
        fields = [field for field in _DESIRED_FIELDS if field in supported]
        warnings = [
            f"当前 tshark 不支持字段 {field}"
            for field in _DESIRED_FIELDS
            if field not in supported
        ]
        raw_output = request.output_dir / f".frames-{uuid.uuid4().hex}.tsv"
        raw_stderr = request.output_dir / f".frames-{uuid.uuid4().hex}.stderr"
        command = [
            request.tshark_path,
            "-n",
            "-r",
            str(request.capture_path),
            "-T",
            "fields",
            "-E",
            "header=y",
            "-E",
            "separator=/t",
            "-E",
            "quote=d",
            "-E",
            "occurrence=a",
            "-E",
            "aggregator=,",
        ]
        for field_name in fields:
            command.extend(["-e", field_name])

        try:
            self._run_to_file(
                command,
                raw_output,
                raw_stderr,
                request.timeout_seconds,
            )
            frame_count, flows, observations = self._normalize(
                raw_output,
                request.output_dir,
                set(request.dut_addresses),
            )
        finally:
            raw_output.unlink(missing_ok=True)
            raw_stderr.unlink(missing_ok=True)

        return BackendResult(
            backend_name=self.name,
            backend_version="1",
            tshark_version=version,
            frame_index_path=request.output_dir / "frames.jsonl",
            flow_index_path=request.output_dir / "flows.jsonl",
            non_session_observations_path=request.output_dir / "non-session-observations.jsonl",
            payload_profiles_path=request.output_dir / "payload-profiles.jsonl",
            frame_count=frame_count,
            flow_count=len(flows),
            warnings=tuple(warnings),
            metrics={"frame_count": frame_count, "flow_count": len(flows)},
        )

    def _normalize(
        self,
        raw_output: Path,
        output_dir: Path,
        dut_addresses: set[str],
    ) -> tuple[int, dict[tuple[Any, ...], _FlowAccumulator], list[ObservedProtocolRecord]]:
        flows: dict[tuple[Any, ...], _FlowAccumulator] = {}
        observations: list[ObservedProtocolRecord] = []
        frames_path = output_dir / "frames.jsonl"
        frames_tmp = frames_path.with_name(f".{frames_path.name}.{uuid.uuid4().hex}.tmp")
        frame_count = 0

        with raw_output.open("r", encoding="utf-8", errors="replace", newline="") as source, \
                frames_tmp.open("w", encoding="utf-8", newline="\n") as frames_handle:
            reader = csv.DictReader(source, delimiter="\t", quotechar='"')
            for row in reader:
                frame = self._normalize_frame(row)
                if frame is None:
                    continue
                frame_count += 1
                frames_handle.write(frame.model_dump_json())
                frames_handle.write("\n")
                self._accumulate(frame, row, flows, observations, dut_addresses)
            frames_handle.flush()
            os.fsync(frames_handle.fileno())
        frames_tmp.replace(frames_path)

        flows_path = output_dir / "flows.jsonl"
        flows_tmp = flows_path.with_name(f".{flows_path.name}.{uuid.uuid4().hex}.tmp")
        with flows_tmp.open("w", encoding="utf-8", newline="\n") as handle:
            for accumulator in sorted(flows.values(), key=lambda item: item.flow_id):
                handle.write(accumulator.to_model().model_dump_json())
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        flows_tmp.replace(flows_path)

        observations_path = output_dir / "non-session-observations.jsonl"
        observations_tmp = observations_path.with_name(
            f".{observations_path.name}.{uuid.uuid4().hex}.tmp"
        )
        with observations_tmp.open("w", encoding="utf-8", newline="\n") as handle:
            for observation in observations:
                handle.write(observation.model_dump_json())
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        observations_tmp.replace(observations_path)

        profiles_path = output_dir / "payload-profiles.jsonl"
        profiles_tmp = profiles_path.with_name(f".{profiles_path.name}.{uuid.uuid4().hex}.tmp")
        with profiles_tmp.open("w", encoding="utf-8", newline="\n") as handle:
            for accumulator in sorted(flows.values(), key=lambda item: item.flow_id):
                profile = accumulator.payload_profiler.to_model(accumulator.flow_id)
                if profile.payload_bytes:
                    handle.write(profile.model_dump_json())
                    handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        profiles_tmp.replace(profiles_path)
        return frame_count, flows, observations

    @staticmethod
    def _normalize_frame(row: dict[str, str]) -> ObservedFrame | None:
        frame_number = _as_int(row.get("frame.number"))
        if frame_number is None:
            return None
        src_address = row.get("ip.src") or row.get("ipv6.src") or None
        dst_address = row.get("ip.dst") or row.get("ipv6.dst") or None
        if row.get("tcp.srcport"):
            transport = "TCP"
            src_port = _as_int(row.get("tcp.srcport"))
            dst_port = _as_int(row.get("tcp.dstport"))
            stream_id = _as_int(row.get("tcp.stream"))
        elif row.get("udp.srcport"):
            transport = "UDP"
            src_port = _as_int(row.get("udp.srcport"))
            dst_port = _as_int(row.get("udp.dstport"))
            stream_id = _as_int(row.get("udp.stream"))
        elif row.get("sctp.srcport"):
            transport = "SCTP"
            src_port = _as_int(row.get("sctp.srcport"))
            dst_port = _as_int(row.get("sctp.dstport"))
            stream_id = _as_int(row.get("sctp.assoc_index"))
        else:
            transport = None
            src_port = None
            dst_port = None
            stream_id = None
        status = _as_int(row.get("http.response.code"))
        handshake_types = [
            value for item in _split_values(row.get("tls.handshake.type"))
            if (value := _as_int(item)) is not None
        ]
        return ObservedFrame(
            frame_number=frame_number,
            flow_id=(
                stable_flow_id(
                    transport,
                    src_address,
                    src_port,
                    dst_address,
                    dst_port,
                    stream_id=stream_id,
                )
                if transport
                and src_address
                and dst_address
                and src_port is not None
                and dst_port is not None
                else None
            ),
            timestamp_epoch=_as_float(row.get("frame.time_epoch")),
            frame_length=_as_int(row.get("frame.len"), 0) or 0,
            src_address=src_address,
            dst_address=dst_address,
            src_port=src_port,
            dst_port=dst_port,
            transport=transport,
            stream_id=stream_id,
            protocol_stack=_protocol_stack(row.get("frame.protocols")),
            displayed_protocol=row.get("_ws.col.Protocol") or None,
            dns_names=_split_values(row.get("dns.qry.name")),
            dns_answers=[
                *(_split_values(row.get("dns.a"))),
                *(_split_values(row.get("dns.aaaa"))),
            ],
            dns_cnames=_split_values(row.get("dns.cname")),
            sni=_split_values(row.get("tls.handshake.extensions_server_name")),
            http_method=row.get("http.request.method") or None,
            http_host=row.get("http.host") or None,
            http_status=status,
            tls_handshake_types=handshake_types,
            tcp_flags=row.get("tcp.flags") or None,
            retransmission=bool(row.get("tcp.analysis.retransmission")),
            out_of_order=bool(row.get("tcp.analysis.out_of_order")),
        )

    @staticmethod
    def _accumulate(
        frame: ObservedFrame,
        row: dict[str, str],
        flows: dict[tuple[Any, ...], _FlowAccumulator],
        observations: list[ObservedProtocolRecord],
        dut_addresses: set[str],
    ) -> None:
        if (
            frame.transport
            and frame.src_address
            and frame.dst_address
            and frame.src_port is not None
            and frame.dst_port is not None
        ):
            key = canonical_flow_key(
                frame.transport,
                frame.src_address,
                frame.src_port,
                frame.dst_address,
                frame.dst_port,
                stream_id=frame.stream_id,
            )
            accumulator = flows.get(key)
            if accumulator is None:
                flow_id = stable_flow_id(
                    frame.transport,
                    frame.src_address,
                    frame.src_port,
                    frame.dst_address,
                    frame.dst_port,
                    stream_id=frame.stream_id,
                )
                accumulator = _FlowAccumulator(
                    flow_id=flow_id,
                    transport=frame.transport,
                    ip_version=6 if ":" in frame.src_address else 4,
                    src_ip=frame.src_address,
                    src_port=frame.src_port,
                    dst_ip=frame.dst_address,
                    dst_port=frame.dst_port,
                    direction=_direction(frame.src_address, frame.dst_address, dut_addresses),
                    first_frame=frame.frame_number,
                    last_frame=frame.frame_number,
                    first_timestamp=frame.timestamp_epoch,
                    last_timestamp=frame.timestamp_epoch,
                    stream_id=frame.stream_id,
                )
                flows[key] = accumulator
            tls_versions = _split_values(row.get("tls.handshake.extensions.supported_version"))
            cipher_suites = _split_values(row.get("tls.handshake.ciphersuite"))
            accumulator.update(
                frame_number=frame.frame_number,
                timestamp=frame.timestamp_epoch,
                frame_length=frame.frame_length,
                src_ip=frame.src_address,
                src_port=frame.src_port,
                stack=frame.protocol_stack,
                displayed_protocol=frame.displayed_protocol,
                dns_names=frame.dns_names,
                sni=frame.sni,
                tls_versions=tls_versions,
                cipher_suites=cipher_suites,
                handshake_types=frame.tls_handshake_types,
                payload_hex=(
                    row.get("tcp.payload")
                    if frame.transport == "TCP"
                    else row.get("udp.payload")
                    if frame.transport == "UDP"
                    else None
                ),
            )
            return

        protocol = frame.displayed_protocol or (
            frame.protocol_stack[-1] if frame.protocol_stack else "UNKNOWN"
        )
        observations.append(ObservedProtocolRecord(
            observation_id=f"observation-{frame.frame_number:09d}",
            frame_number=frame.frame_number,
            protocol=protocol,
            src_address=frame.src_address,
            dst_address=frame.dst_address,
            frame_length=frame.frame_length,
            direction_relative_to_dut=(
                _direction(frame.src_address, frame.dst_address, dut_addresses)
                if frame.src_address and frame.dst_address
                else FlowDirection.UNKNOWN
            ),
            protocol_stack=frame.protocol_stack,
            details={
                "eth_src": row.get("eth.src") or None,
                "eth_dst": row.get("eth.dst") or None,
                "vlan_id": row.get("vlan.id") or None,
            },
        ))
