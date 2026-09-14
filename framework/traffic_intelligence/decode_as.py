"""限定当前 PCAP/Flow/端口的离线 TShark Decode-As 尝试。"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from contracts.traffic_intelligence import (
    ObservedFlow,
    ProtocolBasis,
    ProtocolBasisType,
    ProtocolCandidate,
    ProtocolCandidateStatus,
)
from framework.traffic_intelligence.bundle_store import (
    BundleIntegrityError,
    TrafficIntelligenceBundleStore,
    sha256_file,
)


DECODE_AS_ALLOWLIST: dict[str, frozenset[str]] = {
    "coap": frozenset({"UDP"}),
    "dns": frozenset({"TCP", "UDP"}),
    "http": frozenset({"TCP"}),
    "modbus": frozenset({"TCP"}),
    "mqtt": frozenset({"TCP"}),
    "rtp": frozenset({"UDP"}),
    "rtsp": frozenset({"TCP"}),
    "sip": frozenset({"TCP", "UDP"}),
    "ssh": frozenset({"TCP"}),
    "tls": frozenset({"TCP"}),
}

_MAX_TSV_LINE_BYTES = 1024 * 1024
_MAX_REPRESENTATIVE_FRAMES = 20


class DecodeAsError(RuntimeError):
    """受控 Decode-As 无法安全完成。"""


def _creation_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def _safe_within(root: Path, path: Path) -> Path:
    root = root.resolve()
    resolved = path.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise DecodeAsError("Decode-As 路径越出受控目录")
    return resolved


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def _is_unknown(flow: ObservedFlow) -> bool:
    return not flow.protocol_candidates or all(
        candidate.status == ProtocolCandidateStatus.UNKNOWN
        for candidate in flow.protocol_candidates
    )


def _service_port(flow: ObservedFlow) -> int:
    if flow.direction_relative_to_dut.value == "OUTBOUND":
        return flow.dst_port
    if flow.direction_relative_to_dut.value == "INBOUND":
        return flow.dst_port
    if flow.src_port >= 49152 > flow.dst_port:
        return flow.dst_port
    if flow.dst_port >= 49152 > flow.src_port:
        return flow.src_port
    return min(flow.src_port, flow.dst_port)


def _flow_filter(flow: ObservedFlow) -> str:
    transport = flow.transport.lower()
    if flow.stream_id is not None:
        stream_field = "sctp.assoc_index" if transport == "sctp" else f"{transport}.stream"
        return f"{stream_field} == {flow.stream_id}"
    ip_field = "ipv6" if flow.ip_version == 6 else "ip"
    forward = (
        f"({ip_field}.src == {flow.src_ip} && {transport}.srcport == {flow.src_port} && "
        f"{ip_field}.dst == {flow.dst_ip} && {transport}.dstport == {flow.dst_port})"
    )
    reverse = (
        f"({ip_field}.src == {flow.dst_ip} && {transport}.srcport == {flow.dst_port} && "
        f"{ip_field}.dst == {flow.src_ip} && {transport}.dstport == {flow.src_port})"
    )
    return f"({forward} || {reverse})"


class DecodeAsRunner:
    """运行一次受控复分析，产物与原始 Bundle 事实隔离。"""

    def __init__(self, workspace: Path, *, tshark_path: str = "tshark", timeout_seconds: int = 120) -> None:
        self.workspace = Path(workspace).resolve()
        self.tshark_path = str(tshark_path)
        self.timeout_seconds = max(1, min(int(timeout_seconds), 600))
        self.store = TrafficIntelligenceBundleStore(self.workspace)

    def _find_flow(self, flow_id: str) -> ObservedFlow:
        for value in self.store.iter_jsonl("flows.jsonl"):
            if value.get("flow_id") == flow_id:
                return ObservedFlow.model_validate(value)
        raise DecodeAsError(f"Flow 不存在: {flow_id}")

    def _capture_path(self) -> tuple[Path, str]:
        manifest = self.store.load_manifest()
        capture = _safe_within(self.workspace, self.workspace / manifest.capture_artifact)
        if not capture.is_file():
            raise DecodeAsError("当前 Bundle 对应的 PCAP 不存在")
        if capture.stat().st_size != manifest.capture_size:
            raise BundleIntegrityError("当前 PCAP 大小与 Bundle manifest 不一致")
        if sha256_file(capture) != manifest.capture_sha256:
            raise BundleIntegrityError("当前 PCAP 哈希与 Bundle manifest 不一致")
        return capture, manifest.capture_sha256

    def _tshark_version(self) -> str:
        try:
            completed = subprocess.run(
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
            raise DecodeAsError(f"无法启动 tshark: {exc}") from exc
        if completed.returncode != 0:
            raise DecodeAsError("tshark --version 执行失败")
        return next((line.strip() for line in completed.stdout.splitlines() if line.strip()), "unknown")

    def _run_tshark(self, args: list[str], stdout_path: Path, stderr_path: Path) -> None:
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            try:
                process = subprocess.Popen(
                    args,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    shell=False,
                    creationflags=_creation_flags(),
                )
                process.wait(timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait(timeout=10)
                raise DecodeAsError(
                    f"Decode-As 超过 {self.timeout_seconds} 秒未完成"
                ) from exc
            except OSError as exc:
                raise DecodeAsError(f"无法启动 tshark: {exc}") from exc
        if process.returncode != 0:
            details = stderr_path.read_text(encoding="utf-8", errors="replace")[:2000]
            raise DecodeAsError(f"tshark Decode-As 失败: {details or process.returncode}")

    @staticmethod
    def _parse_output(path: Path, dissector: str) -> dict[str, Any]:
        total = 0
        decoded = 0
        malformed = 0
        representatives: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle, delimiter="\t", quotechar='"')
            expected = {"frame.number", "frame.protocols", "_ws.col.Protocol"}
            if not reader.fieldnames or not expected.issubset(reader.fieldnames):
                raise DecodeAsError("tshark Decode-As 输出缺少基础字段")
            for row in reader:
                if sum(len(str(value).encode("utf-8")) for value in row.values()) > _MAX_TSV_LINE_BYTES:
                    raise DecodeAsError("tshark Decode-As 单帧输出超过 1 MiB")
                try:
                    frame_number = int(str(row.get("frame.number", "")).split(",", 1)[0])
                except ValueError:
                    continue
                total += 1
                stack = [
                    item.strip().lower()
                    for item in str(row.get("frame.protocols", "")).split(":")
                    if item.strip()
                ]
                displayed = str(row.get("_ws.col.Protocol", "")).strip()
                recognized = dissector in stack or displayed.casefold() == dissector
                if recognized:
                    decoded += 1
                if "malformed" in stack or displayed.casefold() == "malformed":
                    malformed += 1
                if recognized and len(representatives) < _MAX_REPRESENTATIVE_FRAMES:
                    representatives.append({
                        "frame_number": frame_number,
                        "protocol_stack": stack,
                        "displayed_protocol": displayed or None,
                    })
        coverage = decoded / total if total else 0.0
        return {
            "total_frames": total,
            "decoded_frames": decoded,
            "decode_coverage": round(coverage, 6),
            "malformed_frames": malformed,
            "malformed_ratio": round(malformed / total, 6) if total else 0.0,
            "field_completeness": round(decoded / total, 6) if total else 0.0,
            "representative_frames": representatives,
        }

    def run(self, flow_id: str, dissector: str) -> dict[str, Any]:
        flow_id = str(flow_id).strip()
        selected = str(dissector).strip().casefold()
        if selected not in DECODE_AS_ALLOWLIST:
            raise DecodeAsError(
                "dissector 不在 allowlist: " + ", ".join(sorted(DECODE_AS_ALLOWLIST))
            )
        capture, capture_sha256 = self._capture_path()
        flow = self._find_flow(flow_id)
        if not _is_unknown(flow):
            raise DecodeAsError("只有 UNKNOWN Flow 可以发起 Decode-As，原有确定性结论不会被覆盖")
        if flow.transport not in DECODE_AS_ALLOWLIST[selected]:
            raise DecodeAsError(f"{selected} 不允许用于 {flow.transport} Flow")

        service_port = _service_port(flow)
        selector = f"{flow.transport.lower()}.port=={service_port},{selected}"
        display_filter = _flow_filter(flow)
        attempt_id = f"decode-{uuid.uuid4().hex}"
        # 派生尝试不写进已经提交的主 Bundle。每个 attempt 用自己的 manifest
        # 绑定父 Bundle/PCAP 散列，主 Bundle 保持不可变且不接受未登记文件。
        derived_root = _safe_within(
            self.workspace,
            self.workspace / "traffic-intelligence-derived",
        )
        attempts_root = _safe_within(
            derived_root,
            derived_root / "decode-as-attempts",
        )
        attempts_root.mkdir(parents=True, exist_ok=True)
        staging = _safe_within(attempts_root, attempts_root / f".{attempt_id}.staging")
        output_dir = _safe_within(attempts_root, attempts_root / attempt_id)
        staging.mkdir(parents=False, exist_ok=False)
        output_tsv = staging / ".decode.tsv"
        stderr_path = staging / ".decode.stderr"
        try:
            command = [
                self.tshark_path,
                "-n",
                "-r",
                str(capture),
                "-Y",
                display_filter,
                "-d",
                selector,
                "-T",
                "fields",
                "-E",
                "header=y",
                "-E",
                "separator=/t",
                "-E",
                "quote=d",
                "-e",
                "frame.number",
                "-e",
                "frame.protocols",
                "-e",
                "_ws.col.Protocol",
            ]
            version = self._tshark_version()
            self._run_tshark(command, output_tsv, stderr_path)
            metrics = self._parse_output(output_tsv, selected)
            candidate: dict[str, Any] | None = None
            if metrics["total_frames"] and metrics["decode_coverage"] >= 0.8:
                candidate = ProtocolCandidate(
                    name=selected.upper(),
                    confidence=min(0.95, float(metrics["decode_coverage"])),
                    status=ProtocolCandidateStatus.PROBABLE,
                    basis=[ProtocolBasis(
                        type=ProtocolBasisType.DECODE_AS,
                        value=selector,
                        frame_number=(
                            metrics["representative_frames"][0]["frame_number"]
                            if metrics["representative_frames"]
                            else None
                        ),
                        details={
                            "attempt_id": attempt_id,
                            "coverage": metrics["decode_coverage"],
                            "malformed_ratio": metrics["malformed_ratio"],
                        },
                    )],
                ).model_dump(mode="json")
            result = {
                "schema_version": 1,
                "attempt_id": attempt_id,
                "status": "probable" if candidate else "insufficient_evidence",
                "flow_id": flow.flow_id,
                "dissector": selected,
                "transport": flow.transport,
                "service_port": service_port,
                "decode_selector": selector,
                "flow_filter": display_filter,
                **metrics,
                "candidate": candidate,
                "original_flow_modified": False,
                "payload_included": False,
            }
            result_path = staging / "result.json"
            _atomic_json(result_path, result)
            _atomic_json(staging / "manifest.json", {
                "schema_version": 1,
                "attempt_id": attempt_id,
                "complete": True,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "capture_sha256": capture_sha256,
                "parent_bundle_manifest_sha256": sha256_file(
                    self.store.bundle_dir / "manifest.json"
                ),
                "flow_id": flow.flow_id,
                "dissector": selected,
                "tshark_version": version,
                "result_sha256": sha256_file(result_path),
                "payload_included": False,
            })
            output_tsv.unlink(missing_ok=True)
            stderr_path.unlink(missing_ok=True)
            staging.replace(output_dir)
            result["artifact"] = (
                f"traffic-intelligence-derived/decode-as-attempts/{attempt_id}/result.json"
            )
            return result
        finally:
            if staging.exists():
                if staging.is_symlink():
                    staging.unlink()
                else:
                    shutil.rmtree(staging)
            for empty_candidate in (attempts_root, derived_root):
                try:
                    empty_candidate.rmdir()
                except OSError:
                    pass


__all__ = ["DECODE_AS_ALLOWLIST", "DecodeAsError", "DecodeAsRunner"]
