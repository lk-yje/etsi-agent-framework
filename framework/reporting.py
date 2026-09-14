"""统一的报告数据与条款证据包生成。

报告网页、HTML 归档与证据下载都读取同一份 report-data.json。原始证据不会按
条款盲目复制：每个条款包记录来源、提取方式和缺失状态；共享原件只硬链接/引用一次。
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from framework.traffic_state import TrafficStateStore
from framework.workspace import workspace_status
from framework.path_resolver import PathResolver


REPORT_DIR = "reports"
REPORT_DATA_FILE = f"{REPORT_DIR}/report-data.json"
PACKAGE_DIR = "evidence-packages"
_ROOT = Path(__file__).resolve().parent.parent
_CATALOG_PATH = _ROOT / "framework" / "clause_tool_map.json"
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_json(path: Path, value: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(path)
    return path


def _product_info(workspace: Path) -> dict:
    default = {
        "product_name": "Unknown", "model": "Unknown-Model",
        "product_version": "Unknown", "hardware_version": "Unknown",
        "firmware": "Unknown", "vendor": "Unknown", "device_type": "IoT 设备",
    }
    data = _read_json(workspace / "ixit.json")
    if not data:
        return default
    flat: dict[str, str] = {}
    for fields in data.get("meta", {}).get("dut_identification", {}).values():
        if isinstance(fields, dict):
            for key, value in fields.items():
                if key and value:
                    flat[str(key).lower()] = str(value)

    def grab(*keywords: str) -> str | None:
        return next((value for key, value in flat.items() if any(word in key for word in keywords)), None)

    return {
        "product_name": grab("product name", "device name") or "Unknown",
        "model": grab("model") or "Unknown-Model",
        "product_version": grab("product version", "device version") or "Unknown",
        "hardware_version": grab("hardware version", "hardware revision") or "Unknown",
        "firmware": grab("firmware", "software version") or "Unknown",
        "vendor": grab("vendor", "manufacturer", "supplier", "brand", "trade name", "organisation", "organization") or "Unknown",
        "device_type": grab("device type", "product category") or "IoT 设备",
    }


def _test_date(workspace: Path) -> str:
    state = _read_json(workspace / "pipeline_state.json") or {}
    return str(state.get("started_at", ""))[:10] or datetime.now().strftime("%Y-%m-%d")


def _catalog() -> dict:
    return _read_json(_CATALOG_PATH) or {}


def build_traffic_intelligence_report(workspace: Path) -> dict:
    """读取已校验 Bundle，只暴露报告所需的结构化摘要与差异。"""
    bundle_dir = Path(workspace) / "traffic-intelligence"
    if not (bundle_dir / "manifest.json").is_file():
        return {"status": "not_available"}
    try:
        from framework.traffic_intelligence.bundle_store import (
            TrafficIntelligenceBundleStore,
        )

        store = TrafficIntelligenceBundleStore(Path(workspace))
        manifest = store.load_manifest()
        inventory = store.read_json("inventory.json", max_bytes=2 * 1024 * 1024)
        summary = store.read_json("summary-for-ai.json", max_bytes=2 * 1024 * 1024)
        alignments = store.read_json("declaration-alignments.json", max_bytes=16 * 1024 * 1024)
        clusters = store.read_json("unknown-protocol-clusters.json", max_bytes=16 * 1024 * 1024)
        windows = store.read_json("automatic-activity-windows.json", max_bytes=8 * 1024 * 1024)
        correlations = store.read_json("dns-correlations.json", max_bytes=8 * 1024 * 1024)
        if not all(isinstance(value, list) for value in (alignments, clusters, windows, correlations)):
            raise ValueError("Traffic Intelligence 列表产物结构无效")
        mismatch = [item for item in alignments if item.get("overall") == "MISMATCH"]
        undeclared = [
            item for item in alignments if item.get("overall") == "UNDECLARED_OBSERVED"
        ]
        not_observed = [item for item in alignments if item.get("overall") == "NOT_OBSERVED"]
        return {
            "status": "complete",
            "capture_sha256": manifest.capture_sha256,
            "backend": manifest.analysis_backend,
            "fallback_reason": manifest.fallback_reason,
            "inventory": inventory,
            "summary": summary,
            "mismatches": mismatch[:100],
            "undeclared_observed": undeclared[:100],
            "not_observed": not_observed[:100],
            "unknown_clusters": clusters[:100],
            "activity_windows": windows[:100],
            "dns_correlation_count": len(correlations),
            "truncated": any(
                len(items) > 100
                for items in (mismatch, undeclared, not_observed, clusters, windows)
            ),
            "payload_included": False,
        }
    except Exception as exc:
        return {
            "status": "invalid",
            "reason": f"{type(exc).__name__}: {exc}",
            "payload_included": False,
        }


def build_report_data(workspace: Path) -> dict:
    """从工作区收集唯一的结构化报告数据，跳过 Phase 中间 evidence。"""
    workspace = Path(workspace)
    clauses: list[dict] = []
    counts = {"PASS": 0, "FAIL": 0, "NA": 0, "INCONCLUSIVE": 0, "PENDING_MANUAL": 0}
    evidence_dir = workspace / "evidence"
    if evidence_dir.exists():
        for path in sorted(evidence_dir.glob("pre-*-evidence.json")):
            if "phase_" in path.stem:
                continue
            manifest = _read_json(path) or {}
            module = manifest.get("meta", {}).get("moduleId", path.stem.split("-")[1])
            for raw in manifest.get("clauses", []):
                clause = dict(raw)
                clause["_module"] = module
                clauses.append(clause)
                verdict = clause.get("verdict", "?")
                if verdict in counts:
                    counts[verdict] += 1

    audits: list[dict] = []
    audit_dir = workspace / "audit-results"
    if audit_dir.exists():
        for path in sorted(audit_dir.glob("audit-result_*.json")):
            audit = _read_json(path) or {}
            info = audit.get("audit", audit)
            audits.append({
                "module": info.get("moduleId", info.get("module_id", path.stem)),
                "verdict": info.get("verdict", "?"),
                "summary": info.get("summary", ""),
                "finding_count": len(audit.get("findings", [])),
            })

    pipeline = _read_json(workspace / "pipeline_state.json") or {}
    _, receipt_count = _tool_receipts(workspace)
    return {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "workspace": str(workspace),
        "product": _product_info(workspace),
        "test_date": _test_date(workspace),
        "pipeline": {
            "current_state": pipeline.get("current_state"),
            "review_required": pipeline.get("review_required", False),
            "review_reasons": pipeline.get("review_reasons", []),
            "errors": pipeline.get("errors", []),
        },
        "traffic": TrafficStateStore(workspace).read(),
        "traffic_intelligence": build_traffic_intelligence_report(workspace),
        "verdict_counts": counts,
        "total_clauses": len(clauses),
        "clauses": clauses,
        "audit_summaries": audits,
        "tool_receipt_count": receipt_count,
        "workspace_status": workspace_status(workspace),
    }


def _group_for_clause(clause_id: str) -> str:
    return clause_id.split("-", 1)[0] or "unknown"


def _safe_component(value: str) -> str:
    return _SAFE_NAME.sub("_", value).strip("._") or "item"


def _within_workspace(workspace: Path, raw_path: str) -> Path | None:
    candidate = Path(raw_path)
    candidate = candidate if candidate.is_absolute() else workspace / candidate
    try:
        resolved = candidate.resolve()
        return resolved if resolved.is_relative_to(workspace.resolve()) else None
    except OSError:
        return None


def _link_or_copy(source: Path, destination: Path) -> str:
    """物化条款包内的小型或共享文件；替换仅限本次生成的精确目标。"""
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_suffix(destination.suffix + ".tmp")
    tmp.unlink(missing_ok=True)
    try:
        os.link(source, tmp)
        method = "hardlink"
    except OSError:
        shutil.copy2(source, tmp)
        method = "copy"
    tmp.replace(destination)
    return method


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pcap_outputs(workspace: Path) -> dict[str, list[dict]]:
    index = _read_json(workspace / "pcap_analysis" / "_index.json") or {}
    out: dict[str, list[dict]] = {}
    for query_id, query in index.get("queries", {}).items():
        clause = str(query.get("clause", ""))
        if clause and clause != "_global":
            out.setdefault(clause, []).append({"id": query_id, **query})
    return out


def _structured_refs(clause: dict) -> tuple[set[str], set[int]]:
    """读取结构化 Flow/frame 引用；不从自然语言 description 猜测。"""
    flow_ids: set[str] = set()
    frame_numbers: set[int] = set()
    for evidence in clause.get("evidence", []):
        if not isinstance(evidence, dict):
            continue
        raw_flow_ids = evidence.get("flow_ids", evidence.get("flowIds", []))
        raw_frames = evidence.get("frame_numbers", evidence.get("frameNumbers", []))
        if isinstance(raw_flow_ids, list):
            flow_ids.update(
                str(value).strip() for value in raw_flow_ids if str(value).strip()
            )
        if isinstance(raw_frames, list):
            for value in raw_frames:
                try:
                    number = int(value)
                except (TypeError, ValueError):
                    continue
                if number > 0:
                    frame_numbers.add(number)
    return flow_ids, frame_numbers


def _traffic_intelligence_refs_by_clause(
    workspace: Path,
    clauses: list[dict],
) -> dict[str, dict]:
    """一次校验、一次扫描 Bundle，解析所有条款的显式 Flow/frame 引用。"""
    requested: dict[str, tuple[set[str], set[int]]] = {}
    for clause in clauses:
        clause_id = str(clause.get("clause_id", "unknown"))
        flow_ids, frame_numbers = _structured_refs(clause)
        if flow_ids or frame_numbers:
            requested[clause_id] = (flow_ids, frame_numbers)
    if not requested:
        return {}

    base = {
        clause_id: {
            "schema_version": 1,
            "clause_id": clause_id,
            "status": "invalid_bundle",
            "source": "traffic-intelligence/manifest.json",
            "capture_sha256": None,
            "capture_artifact": "capture.pcap",
            "manifest_sha256": None,
            "requested_flow_ids": sorted(flow_ids),
            "flow_ids": [],
            "missing_flow_ids": sorted(flow_ids),
            "requested_frame_numbers": sorted(frame_numbers),
            "frame_numbers": [],
            "missing_frame_numbers": sorted(frame_numbers),
            "analysis_sources": ["traffic-intelligence/manifest.json"],
            "payload_included": False,
        }
        for clause_id, (flow_ids, frame_numbers) in requested.items()
    }

    try:
        from framework.traffic_intelligence.bundle_store import (
            TrafficIntelligenceBundleStore,
        )

        store = TrafficIntelligenceBundleStore(workspace)
        manifest = store.load_manifest()
        capture_path = _within_workspace(workspace, manifest.capture_artifact)
        if capture_path is None:
            raise ValueError("Bundle capture_artifact 越出工作区")
        if capture_path.is_file():
            manifest = store.load_manifest(
                verify_artifacts=False,
                capture_path=Path(manifest.capture_artifact),
            )
        manifest_hash = _sha256(workspace / "traffic-intelligence" / "manifest.json")
        declared = {artifact.path for artifact in manifest.artifacts}
        wanted_flow_ids = {
            flow_id for flow_ids, _ in requested.values() for flow_id in flow_ids
        }
        wanted_frames = {
            number for _, frame_numbers in requested.values() for number in frame_numbers
        }

        flows: dict[str, dict] = {}
        if wanted_flow_ids:
            if "flows.jsonl" not in declared:
                raise ValueError("Bundle 缺少 flows.jsonl，无法校验 flowIds")
            for flow in store.iter_jsonl("flows.jsonl"):
                flow_id = str(flow.get("flow_id", ""))
                if flow_id in wanted_flow_ids:
                    flows[flow_id] = flow

        existing_frames: set[int] = set()
        if wanted_frames:
            if "frames.jsonl" not in declared:
                raise ValueError("Bundle 缺少 frames.jsonl，无法校验 frameNumbers")
            for frame in store.iter_jsonl("frames.jsonl"):
                try:
                    number = int(frame.get("frame_number"))
                except (TypeError, ValueError):
                    continue
                if number in wanted_frames:
                    existing_frames.add(number)

        for clause_id, (flow_ids, frame_numbers) in requested.items():
            found_flow_ids = sorted(flow_ids & flows.keys())
            missing_flow_ids = sorted(flow_ids - flows.keys())
            found_explicit_frames = frame_numbers & existing_frames
            missing_frames = sorted(frame_numbers - existing_frames)
            resolved_frames = set(found_explicit_frames)
            for flow_id in found_flow_ids:
                for value in flows[flow_id].get("frame_refs", []):
                    try:
                        number = int(value)
                    except (TypeError, ValueError):
                        continue
                    if number > 0:
                        resolved_frames.add(number)

            missing_any = bool(missing_flow_ids or missing_frames)
            if resolved_frames:
                status = "partial" if missing_any else "ready"
            else:
                status = "unresolved"
            sources = ["traffic-intelligence/manifest.json"]
            if flow_ids:
                sources.append("traffic-intelligence/flows.jsonl")
            if frame_numbers:
                sources.append("traffic-intelligence/frames.jsonl")
            base[clause_id].update({
                "status": status,
                "capture_sha256": manifest.capture_sha256,
                "capture_artifact": manifest.capture_artifact,
                "manifest_sha256": manifest_hash,
                "flow_ids": found_flow_ids,
                "missing_flow_ids": missing_flow_ids,
                "frame_numbers": sorted(resolved_frames),
                "missing_frame_numbers": missing_frames,
                "analysis_sources": sources,
            })
    except Exception as exc:
        reason = f"{type(exc).__name__}: {exc}"
        for item in base.values():
            item["reason"] = reason
    return base


def _tool_receipts(workspace: Path) -> tuple[dict[str, list[tuple[Path, dict]]], int]:
    """按 receipt 声明的 phase 条款范围建立索引，不推断更细的条款归属。"""
    by_clause: dict[str, list[tuple[Path, dict]]] = {}
    count = 0
    directory = workspace / "tool-receipts"
    if not directory.exists():
        return by_clause, count
    for path in sorted(directory.glob("*.json")):
        receipt = _read_json(path)
        if receipt is None:
            continue
        count += 1
        for clause_id in receipt.get("clause_ids", []):
            if clause_id:
                by_clause.setdefault(str(clause_id), []).append((path, receipt))
    return by_clause, count


def _frame_numbers_from_output(path: Path) -> list[int]:
    """从 pcap_analyzer JSON 提取显式 frame 字段；未知格式不猜测。"""
    data = _read_json(path) or {}
    fields = data.get("command_fields", [])
    result = data.get("result", {})
    frames: set[int] = set()
    if "frame.number" in fields and isinstance(result, dict):
        index = fields.index("frame.number")
        for row in result.get("data", []):
            try:
                frames.add(int(row[index]))
            except (ValueError, TypeError, IndexError):
                pass

    def visit(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for nested_key, nested_value in value.items():
                visit(nested_value, nested_key)
        elif isinstance(value, list):
            for nested in value:
                visit(nested, key)
        elif "frame" in key.lower():
            try:
                frames.add(int(value))
            except (ValueError, TypeError):
                pass

    visit(result)
    return sorted(number for number in frames if number > 0)


def _pcap_slice_request(
    workspace: Path,
    clause_id: str,
    pcap_items: list[dict],
    traffic_refs: dict | None = None,
) -> dict:
    frames: set[int] = set()
    sources: list[str] = []
    flow_ids: list[str] = []
    reference_source = "pcap_analysis_compatibility"
    if traffic_refs is not None:
        reference_source = "traffic_intelligence"
        frames.update(traffic_refs.get("frame_numbers", []))
        flow_ids = list(traffic_refs.get("flow_ids", []))
        sources.extend(traffic_refs.get("analysis_sources", []))
    else:
        for item in pcap_items:
            source = workspace / "pcap_analysis" / item["file"]
            if source.suffix.lower() == ".json" and source.exists():
                frames.update(_frame_numbers_from_output(source))
                sources.append(f"pcap_analysis/{item['file']}")
    source_pcap = (
        str(traffic_refs.get("capture_artifact", "capture.pcap"))
        if traffic_refs is not None else "capture.pcap"
    )
    capture = _within_workspace(workspace, source_pcap)
    if capture is None or not capture.is_file():
        status = "no_capture"
    elif not frames:
        status = "no_frame_index"
    elif len(frames) > 500:
        status = "too_many_frames"
    else:
        status = "ready_for_tshark_slice"
    return {
        "clause_id": clause_id,
        "status": status,
        "source_pcap": source_pcap,
        "capture_sha256": (
            traffic_refs.get("capture_sha256") if traffic_refs is not None else None
        ),
        "frame_numbers": sorted(frames),
        "flow_ids": flow_ids,
        "reference_source": reference_source,
        "analysis_sources": sources,
        "display_filter": " or ".join(f"frame.number == {number}" for number in sorted(frames)),
        "note": "优先使用已校验 Traffic Intelligence 的结构化 Flow/frame 引用；仅在条款未提供该引用时回退 pcap_analysis 兼容索引。",
    }


def build_evidence_packages(workspace: Path, report: dict | None = None) -> dict:
    """按大条款/子条款写证据包与索引，不复制完整 capture.pcap。"""
    workspace = Path(workspace)
    report = report or build_report_data(workspace)
    catalog = _catalog()
    pcap_outputs = _pcap_outputs(workspace)
    traffic_refs_by_clause = _traffic_intelligence_refs_by_clause(
        workspace, report["clauses"]
    )
    receipt_index, _ = _tool_receipts(workspace)
    package_root = workspace / PACKAGE_DIR
    package_root.mkdir(parents=True, exist_ok=True)
    index: dict[str, dict] = {}

    ixit = _read_json(workspace / "ixit.json") or {}
    ixit_hash = _sha256(workspace / "ixit.json") if (workspace / "ixit.json").exists() else None
    for clause in report["clauses"]:
        clause_id = str(clause.get("clause_id", "unknown"))
        group = _group_for_clause(clause_id)
        package_rel = f"{PACKAGE_DIR}/{_safe_component(group)}/{_safe_component(clause_id)}"
        package_dir = workspace / package_rel
        evidence_dir = package_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        recipe = catalog.get(clause_id, {})
        records: list[dict] = []

        # Agent 明确交付的 evidence path：只物化工作区内的真实文件。
        for ordinal, evidence in enumerate(clause.get("evidence", []), 1):
            raw_path = evidence.get("path")
            record = {"kind": "agent_evidence", "source": raw_path, "metadata": evidence}
            if not raw_path:
                record["status"] = "logical_reference"
            else:
                source = _within_workspace(workspace, str(raw_path))
                if source is None:
                    record["status"] = "outside_workspace_rejected"
                elif not source.exists() or not source.is_file():
                    record["status"] = "declared_but_missing"
                elif source.name == "capture.pcap":
                    record["status"] = "raw_pcap_reference"
                    record["sha256"] = _sha256(source)
                else:
                    target_name = f"{ordinal:02d}_{_safe_component(source.name)}"
                    record["package_file"] = f"evidence/{target_name}"
                    record["status"] = _link_or_copy(source, evidence_dir / target_name)
                    record["sha256"] = _sha256(source)
            records.append(record)

        # IXIT 证据永远是最小表级摘录，不复制整个输入 JSON。
        excerpts = []
        for table in clause.get("ixit_references", []):
            value = ixit.get("ixit_tables", {}).get(table)
            excerpts.append({"table": table, "value": value, "status": "present" if value is not None else "missing"})
        if excerpts:
            excerpt_name = "ixit_excerpt.json"
            _write_json(evidence_dir / excerpt_name, {"source": "ixit.json", "sha256": ixit_hash, "excerpts": excerpts})
            records.append({"kind": "ixit_excerpt", "status": "generated", "package_file": f"evidence/{excerpt_name}"})

        # pcap_analyzer 的条款输出是可直接下载的小型派生证据。
        pcap_items = pcap_outputs.get(clause_id, [])
        for item in pcap_items:
            source = workspace / "pcap_analysis" / item["file"]
            record = {"kind": "pcap_analysis", "query_id": item["id"], "source": f"pcap_analysis/{item['file']}"}
            if source.exists() and source.is_file():
                target_name = f"pcap_{_safe_component(source.name)}"
                record.update({"status": _link_or_copy(source, evidence_dir / target_name), "package_file": f"evidence/{target_name}", "sha256": _sha256(source)})
            else:
                record["status"] = "declared_but_missing"
            records.append(record)

        # 新证据链只接受 Work Agent 的结构化 flowIds/frameNumbers，并在完整性
        # 校验通过的主 Bundle 中解析；不扫描描述文本，也不复制 Payload。
        traffic_refs = traffic_refs_by_clause.get(clause_id)
        if traffic_refs is not None:
            refs_name = "traffic_intelligence_refs.json"
            _write_json(evidence_dir / refs_name, traffic_refs)
            records.append({
                "kind": "traffic_intelligence_refs",
                "status": traffic_refs["status"],
                "source": traffic_refs["source"],
                "flow_ids": traffic_refs["flow_ids"],
                "frame_numbers": traffic_refs["frame_numbers"],
                "package_file": f"evidence/{refs_name}",
                "payload_included": False,
            })

        # Receipt 是 phase 级调用轨迹，不替代单条款 evidence。保留它实际覆盖的
        # clause_ids，避免将一次多条款调用误述为只证明当前条款。
        for ordinal, (source, receipt) in enumerate(receipt_index.get(clause_id, []), 1):
            target_name = f"receipt_{ordinal:02d}_{_safe_component(source.name)}"
            records.append({
                "kind": "tool_receipt",
                "scope": "phase",
                "source": f"tool-receipts/{source.name}",
                "tool": receipt.get("tool", {}).get("name"),
                "module_id": receipt.get("module_id"),
                "phase_id": receipt.get("phase_id"),
                "clause_ids": receipt.get("clause_ids", []),
                "artifact_refs": receipt.get("artifact_refs", []),
                "status": _link_or_copy(source, evidence_dir / target_name),
                "package_file": f"evidence/{target_name}",
                "sha256": _sha256(source),
            })

        slice_request = _pcap_slice_request(
            workspace, clause_id, pcap_items, traffic_refs
        )
        _write_json(evidence_dir / "pcap_slice_request.json", slice_request)
        records.append({"kind": "pcap_slice", "status": slice_request["status"], "package_file": "evidence/pcap_slice_request.json"})

        package = {
            "schema_version": 1,
            "clause_id": clause_id,
            "module": clause.get("_module"),
            "group": group,
            "verdict": clause.get("verdict"),
            "reason": clause.get("reason"),
            "ixit_references": clause.get("ixit_references", []),
            "recipe": {key: recipe.get(key) for key in ("automation", "tools", "method", "oracle", "manual_boundary", "evidence_artifacts") if key in recipe},
            "evidence_records": records,
        }
        _write_json(package_dir / "clause.json", package)
        summary = {"group": group, "package": package_rel, "record_count": len(records)}
        index[clause_id] = summary
        # 同一对象被写入 report-data.json，供 Web 展开时展示类型、来源和状态，
        # 不需要前端再猜测文件是否真实存在。
        clause["evidence_package"] = {**summary, "evidence_records": records}

    manifest = {"schema_version": 1, "generated_at": datetime.now().isoformat(timespec="seconds"), "packages": index}
    _write_json(package_root / "manifest.json", manifest)
    report["evidence_packages"] = index
    return manifest


def render_html_report(report: dict) -> str:
    """独立可归档 HTML；Web 控制台使用同一 report-data.json 并额外提供下载 API。"""
    product = report["product"]
    rows = []
    for clause in sorted(report["clauses"], key=lambda x: (x.get("_module", ""), x.get("clause_id", ""))):
        clause_id = str(clause.get("clause_id", "?"))
        package = report.get("evidence_packages", {}).get(clause_id, {}).get("package", "")
        details = html.escape(str(clause.get("reason", "")))
        evidence = "".join(f"<li>{html.escape(str(item.get('description', item.get('path', '证据'))))}</li>" for item in clause.get("evidence", [])) or "<li>无直接 evidence item</li>"
        rows.append(
            f"<details><summary><b>{html.escape(clause_id)}</b> · {html.escape(str(clause.get('verdict', '?')))} · {html.escape(str(clause.get('_module', '')))}</summary>"
            f"<p>{details}</p><ul>{evidence}</ul><p>证据包：<code>../{html.escape(package)}/</code></p></details>"
        )
    counts = " · ".join(f"{key}: {value}" for key, value in report["verdict_counts"].items())
    review = "；".join(report["pipeline"].get("review_reasons", [])) or "无"
    traffic_intelligence = report.get("traffic_intelligence") or {}
    ti_inventory = traffic_intelligence.get("inventory") or {}
    ti_rows = []
    for title, key in (
        ("声明不一致", "mismatches"),
        ("未声明但已观察", "undeclared_observed"),
        ("已声明但未观察", "not_observed"),
    ):
        for item in traffic_intelligence.get(key, [])[:30]:
            ti_rows.append(
                "<tr>"
                f"<td>{html.escape(title)}</td>"
                f"<td>{html.escape(str(item.get('declaration_id') or '-'))}</td>"
                f"<td>{html.escape(', '.join(str(value) for value in item.get('flow_ids', [])) or '-')}</td>"
                f"<td>{html.escape(str(item.get('reason', '')))}</td>"
                "</tr>"
            )
    ti_html = (
        "<h2>Traffic Intelligence</h2>"
        f"<p>状态：{html.escape(str(traffic_intelligence.get('status', 'not_available')))}；"
        f"Flow：{ti_inventory.get('flow_count', 0)}；"
        f"声明：{ti_inventory.get('declaration_count', 0)}；"
        f"未知协议集群：{ti_inventory.get('unknown_cluster_count', 0)}</p>"
        + (
            "<table><tr><th>类别</th><th>声明</th><th>Flow</th><th>说明</th></tr>"
            + "".join(ti_rows)
            + "</table>"
            if ti_rows else "<p>没有可展示的声明差异。</p>"
        )
    )
    return f"""<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><title>ETSI TS 103 701 认证检测报告</title>
<style>body{{font:15px system-ui,sans-serif;max-width:1100px;margin:32px auto;line-height:1.55;color:#19202a}}table{{border-collapse:collapse}}td,th{{border:1px solid #ccd4df;padding:7px 10px;text-align:left}}details{{border:1px solid #d8dee8;padding:10px 14px;margin:8px 0;border-radius:6px}}summary{{cursor:pointer}}code{{font-family:ui-monospace,monospace}}.warn{{color:#9a6700}}</style>
<h1>ETSI TS 103 701 认证检测报告</h1><p>任务日期：{html.escape(report['test_date'])}</p>
<h2>样品</h2><table>{''.join(f'<tr><th>{html.escape(k)}</th><td>{html.escape(str(v))}</td></tr>' for k,v in product.items())}</table>
<h2>结果汇总</h2><p>{html.escape(counts)}；总计：{report['total_clauses']}</p><p>已记录工具调用收据：{report.get('tool_receipt_count', 0)}</p>
<h2>状态与复核</h2><p class=\"warn\">{html.escape(review)}</p>
{ti_html}
<h2>逐条款检测结果</h2>{''.join(rows)}
</html>"""


_MANUAL_CLAUSE_IDS = {
    "5.1-4", "5.3-6", "5.3-15", "5.3-16",
    "5.6-3", "5.6-4", "5.9-1", "5.9-2",
}
_MANUAL_CLAUSE_PREFIXES = ("5.4-", "5.7-", "5.11")


def _markdown_text(value: Any, limit: int | None = None) -> str:
    text = str(value or "-").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    return text[:limit] if limit else text


def _is_manual_clause(clause: dict) -> bool:
    clause_id = str(clause.get("clause_id", ""))
    recipe = clause.get("evidence_package", {}).get("recipe", {})
    return (
        bool(clause.get("manualSteps"))
        or recipe.get("automation") == "manual"
        or clause_id in _MANUAL_CLAUSE_IDS
        or any(clause_id.startswith(prefix) for prefix in _MANUAL_CLAUSE_PREFIXES)
    )


def _manual_steps(clause: dict) -> list[str]:
    supplied = clause.get("manualSteps") or clause.get("warnings")
    if isinstance(supplied, str):
        return [supplied]
    if isinstance(supplied, list) and supplied:
        return [str(item) for item in supplied]
    recipe = clause.get("evidence_package", {}).get("recipe", {})
    boundary = recipe.get("manual_boundary")
    if boundary:
        return [str(boundary)]
    return ["该条款需在真机环境按条款包中的 method、IXIT 引用和证据要求执行。"]


def render_markdown_report(report: dict) -> str:
    """从 report-data 渲染 ETSI 原始记录 Markdown，不重新扫描工作区。"""
    product = report["product"]
    test_date = report["test_date"]
    task_id = f"HCTL-{test_date.replace('-', '')}"
    pipeline = report.get("pipeline", {})
    traffic = report.get("traffic") or {}
    traffic_intelligence = report.get("traffic_intelligence") or {}
    clauses = sorted(report.get("clauses", []), key=lambda item: (item.get("_module", ""), item.get("clause_id", "")))
    counts = report.get("verdict_counts", {})
    total = report.get("total_clauses", len(clauses))
    passed, failed = counts.get("PASS", 0), counts.get("FAIL", 0)
    judged = passed + failed
    pct = lambda value: f"{value / total * 100:.1f}%" if total else "-"
    pass_rate = f"{passed / judged * 100:.1f}%" if judged else "-"

    lines = [
        f"任务编号：{task_id}",
        "",
        "# ETSI TS 103 701 认证检测报告",
        "",
    ]
    if pipeline.get("review_required"):
        reasons = "；".join(str(reason) for reason in pipeline.get("review_reasons", [])) or "阶段闸门未满足"
        lines.extend([
            "> ⚠️ **部分报告 / 待人工复核**：本次运行不能作为认证通过结论。",
            f"> 原因：{_markdown_text(reasons)}",
            "",
        ])

    lines.extend([
        "## 1. 委托/样品/测试信息",
        "",
        "| 项目 | 内容 |",
        "|------|------|",
        f"| 产品名称 | {_markdown_text(product.get('product_name'))} |",
        f"| 产品型号 | {_markdown_text(product.get('model'))} |",
        f"| 产品版本 | {_markdown_text(product.get('product_version'))} |",
        f"| 硬件版本 | {_markdown_text(product.get('hardware_version'))} |",
        f"| 固件版本 | {_markdown_text(product.get('firmware'))} |",
        f"| 厂商 | {_markdown_text(product.get('vendor'))} |",
        f"| 设备类型 | {_markdown_text(product.get('device_type'))} |",
        f"| 检测日期 | {_markdown_text(test_date)} |",
        "| 检测依据 | ETSI EN 303 645 V2.1.1 / ETSI TS 103 701 V1.1.1 |",
        "| 测试工具/环境 | 以环境快照和各条款 evidence receipt 为准；未记录项不得视为已执行 |",
        "",
    ])

    if traffic:
        lines.extend([
            "## 2. 阶段 3.1 流量采集取证",
            "",
            f"- 状态：`{_markdown_text(traffic.get('status', 'UNKNOWN'))}`",
            f"- 操作模式：`{_markdown_text(traffic.get('operation_mode', 'continuous_unlabelled'))}`",
            f"- 采集 attempt：`{_markdown_text(traffic.get('attempt_id', '?'))}`",
            f"- PCAP：`{_markdown_text(traffic.get('capture_pcap', 'capture.pcap'))}`",
            "",
        ])

    if traffic_intelligence.get("status") == "complete":
        inventory = traffic_intelligence.get("inventory") or {}
        summary = traffic_intelligence.get("summary") or {}
        lines.extend([
            "## 2.1 Traffic Intelligence 结构化分析",
            "",
            f"- 分析后端：`{_markdown_text(traffic_intelligence.get('backend'))}`",
            f"- Flow：**{inventory.get('flow_count', 0)}**；端点：**{inventory.get('endpoint_count', 0)}**；未知协议集群：**{inventory.get('unknown_cluster_count', 0)}**",
            f"- IXIT 通信声明：**{inventory.get('declaration_count', 0)}**；DNS 关联：**{traffic_intelligence.get('dns_correlation_count', 0)}**",
            f"- 加密分类：`{_markdown_text(json.dumps(summary.get('encryption_counts', {}), ensure_ascii=False))}`",
            "- 报告不包含原始 Payload；协议、端口、目标和加密差异保留 Flow/frame 引用。",
            "",
            "| 类别 | 声明 ID | Flow | Frame | 说明 |",
            "|------|---------|------|-------|------|",
        ])
        for label, key in (
            ("声明不一致", "mismatches"),
            ("未声明但已观察", "undeclared_observed"),
            ("已声明但未观察", "not_observed"),
        ):
            for item in traffic_intelligence.get(key, []):
                lines.append(
                    f"| {label} | {_markdown_text(item.get('declaration_id'))} | "
                    f"{_markdown_text(', '.join(item.get('flow_ids', [])))} | "
                    f"{_markdown_text(', '.join(str(value) for value in item.get('frame_refs', [])))} | "
                    f"{_markdown_text(item.get('reason'))} |"
                )
        lines.append("")

    lines.extend([
        "## 3. 检测结果汇总",
        "",
        "| 裁决 | 数量 | 占比 |",
        "|------|:----:|:----:|",
        f"| PASS | {passed} | {pct(passed)} |",
        f"| FAIL | {failed} | {pct(failed)} |",
        f"| N/A | {counts.get('NA', 0)} | {pct(counts.get('NA', 0))} |",
        f"| INCONCLUSIVE | {counts.get('INCONCLUSIVE', 0)} | {pct(counts.get('INCONCLUSIVE', 0))} |",
        f"| PENDING_MANUAL | {counts.get('PENDING_MANUAL', 0)} | {pct(counts.get('PENDING_MANUAL', 0))} |",
        f"| **总计** | **{total}** | — |",
        f"| **通过率 (PASS/已判定)** | **{pass_rate}** | — |",
        f"| **工具调用收据** | **{report.get('tool_receipt_count', 0)}** | phase 级调用轨迹 |",
        "",
        "## 4. 审计意见",
        "",
    ])
    audits = report.get("audit_summaries", [])
    if audits:
        for audit in audits:
            lines.append(
                f"- **{_markdown_text(audit.get('module'))}**：`{_markdown_text(audit.get('verdict'))}` — "
                f"{_markdown_text(audit.get('summary'))}（{audit.get('finding_count', 0)} 发现）"
            )
    else:
        lines.append("- 未生成模块审计结果。")

    lines.extend([
        "",
        "## 5. 逐条款检测结果",
        "",
        "| 模块 | 条款 | 裁决 | 理由 | 证据包 | 备注 |",
        "|:----:|------|:----:|------|--------|------|",
    ])
    for clause in clauses:
        package = clause.get("evidence_package", {}).get("package", "未生成")
        note = "⚠ 需手工测试" if _is_manual_clause(clause) else _markdown_text(clause.get("warnings"), 60)
        lines.append(
            f"| {_markdown_text(clause.get('_module'))} | {_markdown_text(clause.get('clause_id'))} | "
            f"{_markdown_text(clause.get('verdict'))} | {_markdown_text(clause.get('reason'), 160)} | "
            f"`{_markdown_text(package)}` | {note} |"
        )

    lines.extend(["", "## 6. 条款复现与手工测试指引", ""])
    for clause in clauses:
        clause_id = _markdown_text(clause.get("clause_id"))
        package = clause.get("evidence_package", {})
        recipe = package.get("recipe", {})
        lines.extend([
            f"### {clause_id}（{_markdown_text(clause.get('_module'))}）",
            "",
            f"- **评估/测试过程**：{_markdown_text(clause.get('reason'))}",
            f"- **方法**：{_markdown_text(recipe.get('method', '见条款 evidence package'))}",
            f"- **IXIT 引用**：{', '.join(_markdown_text(item) for item in clause.get('ixit_references', [])) or '无'}",
            f"- **证据包**：`{_markdown_text(package.get('package', '未生成'))}`",
        ])
        if _is_manual_clause(clause):
            lines.append("- **手工步骤**：")
            for number, step in enumerate(_manual_steps(clause), 1):
                lines.append(f"  {number}. {_markdown_text(step)}")
        lines.append(f"- **评估/测试结果**：`{_markdown_text(clause.get('verdict'))}`")
        lines.append("")

    lines.extend(["## 附录 A：条款证据包清单", ""])
    for clause in clauses:
        package = clause.get("evidence_package", {}).get("package")
        if package:
            lines.append(f"- `{package}/clause.json`")
    lines.extend(["", "## 附录 B：审计结果清单", ""])
    for audit in audits:
        lines.append(f"- `{_markdown_text(audit.get('module'))}`：`{_markdown_text(audit.get('verdict'))}`")
    lines.extend(["", "---", "", f"*报告由 ETSI Agent Framework 于 {report.get('generated_at', '')} 生成；未记录的操作或工具不得推定为已执行。*"])
    return "\n".join(lines)


def write_report_bundle(workspace: Path, report: dict | None = None) -> dict:
    """从同一 report-data 写 Markdown、HTML 归档和条款证据包。"""
    workspace = Path(workspace)
    report = report or build_report_data(workspace)
    build_evidence_packages(workspace, report)
    report_dir = workspace / REPORT_DIR
    data_path = _write_json(report_dir / "report-data.json", report)
    model = report["product"]["model"]
    html_name = f"认证检测报告_{_safe_component(model)}_{report['test_date'].replace('-', '')}.html"
    html_path = report_dir / html_name
    html_path.write_text(render_html_report(report), encoding="utf-8")
    markdown_name = f"认证检测报告_{_safe_component(model)}_{report['test_date'].replace('-', '')}.md"
    markdown_path = workspace / markdown_name
    markdown_path.write_text(render_markdown_report(report), encoding="utf-8")
    return {
        "report_data": str(data_path.relative_to(workspace)),
        "markdown": str(markdown_path.relative_to(workspace)),
        "html": str(html_path.relative_to(workspace)),
        "packages": PACKAGE_DIR,
    }


def load_report_data(workspace: Path) -> dict:
    """优先读取已在 REPORT 阶段固化的数据；未生成报告时提供实时只读汇总。"""
    workspace = Path(workspace)
    persisted = _read_json(workspace / REPORT_DATA_FILE)
    return persisted if persisted is not None else build_report_data(workspace)


def create_evidence_zip(workspace: Path, scope: str, value: str | None = None) -> Path:
    """导出单条款 / 大条款 / 全部证据包；不把共享原始 capture.pcap 重复塞入 ZIP。"""
    workspace = Path(workspace)
    root = workspace / PACKAGE_DIR
    manifest = _read_json(root / "manifest.json") or {}
    if scope == "all":
        selected = [root]
        label = "all"
    elif scope == "group" and value:
        selected = [root / _safe_component(value)]
        label = _safe_component(value)
    elif scope == "clause" and value:
        package = manifest.get("packages", {}).get(value, {}).get("package")
        selected = [workspace / package] if package else []
        label = _safe_component(value)
    else:
        raise ValueError("scope 必须是 all、group 或 clause，且后两者需要 value")
    if not selected or any(not path.exists() for path in selected):
        raise FileNotFoundError("所选证据包不存在")

    export_dir = workspace / REPORT_DIR / "downloads"
    export_dir.mkdir(parents=True, exist_ok=True)
    target = export_dir / f"evidence_{scope}_{label}.zip"
    tmp = target.with_suffix(".zip.tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as archive:
        for directory in selected:
            for path in directory.rglob("*"):
                if path.is_file():
                    archive.write(path, path.relative_to(workspace))
    tmp.replace(target)
    return target


def materialize_clause_pcap_slice(workspace: Path, clause_id: str, timeout_seconds: int = 120) -> dict:
    """在条款已有明确帧号时，按需切出最小 PCAP 派生证据。

    这不是默认报告动作：缺少帧索引、原始抓包或 tshark 时会如实记录状态。
    工具路径只经 PathResolver / PATH 解析，绝不改动 skills/path-mapping.json。
    """
    workspace = Path(workspace)
    group = _group_for_clause(clause_id)
    evidence_dir = workspace / PACKAGE_DIR / _safe_component(group) / _safe_component(clause_id) / "evidence"
    request_path = evidence_dir / "pcap_slice_request.json"
    request = _read_json(request_path)
    if request is None:
        raise FileNotFoundError("条款 PCAP 切片请求不存在；请先生成报告证据包")
    if request.get("status") != "ready_for_tshark_slice":
        return request

    source = _within_workspace(workspace, str(request.get("source_pcap", "capture.pcap")))
    if source is None or not source.is_file():
        request.update({"status": "no_capture", "updated_at": datetime.now().isoformat(timespec="seconds")})
        _write_json(request_path, request)
        _sync_slice_status(workspace, clause_id, request)
        return request

    expected_capture_hash = request.get("capture_sha256")
    if expected_capture_hash and _sha256(source) != expected_capture_hash:
        request.update({
            "status": "capture_hash_mismatch",
            "updated_at": datetime.now().isoformat(timespec="seconds"),
        })
        _write_json(request_path, request)
        _sync_slice_status(workspace, clause_id, request)
        return request

    tshark = PathResolver().get_tool_path("tshark")
    if not tshark:
        request.update({"status": "tshark_unavailable", "updated_at": datetime.now().isoformat(timespec="seconds")})
        _write_json(request_path, request)
        _sync_slice_status(workspace, clause_id, request)
        return request

    destination = evidence_dir / "pcap_slice.pcapng"
    command = [tshark, "-r", str(source), "-Y", str(request["display_filter"]), "-w", str(destination)]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        request.update({
            "status": "slice_failed", "error": str(exc),
            "updated_at": datetime.now().isoformat(timespec="seconds"),
        })
        _write_json(request_path, request)
        _sync_slice_status(workspace, clause_id, request)
        return request

    request.update({
        "status": "generated" if completed.returncode == 0 and destination.is_file() else "slice_failed",
        "package_file": "evidence/pcap_slice.pcapng" if destination.is_file() else None,
        "returncode": completed.returncode,
        "stderr_tail": (completed.stderr or "")[-1000:],
        "updated_at": datetime.now().isoformat(timespec="seconds"),
    })
    _write_json(request_path, request)
    _sync_slice_status(workspace, clause_id, request)
    return request


def _sync_slice_status(workspace: Path, clause_id: str, request: dict) -> None:
    """把按需切片状态同步进条款元数据与已固化 report-data，便于 Web 实时显示。"""
    group = _group_for_clause(clause_id)
    package_path = workspace / PACKAGE_DIR / _safe_component(group) / _safe_component(clause_id) / "clause.json"
    package = _read_json(package_path)
    if package is not None:
        for record in package.get("evidence_records", []):
            if record.get("kind") == "pcap_slice":
                record.update({"status": request.get("status"), "package_file": request.get("package_file")})
        _write_json(package_path, package)

    data_path = workspace / REPORT_DATA_FILE
    report = _read_json(data_path)
    if report is None:
        return
    for clause in report.get("clauses", []):
        if clause.get("clause_id") != clause_id:
            continue
        for record in clause.get("evidence_package", {}).get("evidence_records", []):
            if record.get("kind") == "pcap_slice":
                record.update({"status": request.get("status"), "package_file": request.get("package_file")})
    _write_json(data_path, report)
