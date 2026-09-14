"""面向 Agent 的有界、只读 Traffic Intelligence 查询工具。"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from framework.tools import ToolDef, ToolParam, ToolRegistry
from framework.traffic_intelligence.bundle_store import TrafficIntelligenceBundleStore
from framework.traffic_intelligence.decode_as import DecodeAsRunner


TRAFFIC_INTELLIGENCE_CATEGORY = "traffic_intelligence"
_MAX_RESULT_CHARS = 64_000
_MAX_PAGE_SIZE = 100
_MAX_FRAME_DETAILS = 20


def _json(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if len(text) <= _MAX_RESULT_CHARS:
        return text
    return json.dumps({
        "truncated": True,
        "total_chars": len(text),
        "content": text[:_MAX_RESULT_CHARS],
    }, ensure_ascii=False, separators=(",", ":"))


def _bounded_int(params: dict, name: str, default: int, minimum: int, maximum: int) -> int:
    value = int(params.get(name, default))
    if value < minimum:
        raise ValueError(f"{name} 不能小于 {minimum}")
    return min(value, maximum)


def _read_array(store: TrafficIntelligenceBundleStore, path: str) -> list[dict]:
    value = store.read_json(path, max_bytes=16 * 1024 * 1024)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{path} 必须是对象数组")
    return value


def build_traffic_intelligence_registry(
    registry: ToolRegistry,
    workspace: Path,
    *,
    tshark_path: str = "tshark",
) -> None:
    """把工具永久绑定到一个 workspace；Agent 不能传入任意文件路径。"""
    store = TrafficIntelligenceBundleStore(Path(workspace).resolve())

    async def get_inventory(_params: dict) -> str:
        return _json(store.read_json("inventory.json", max_bytes=1024 * 1024))

    async def list_flows(params: dict) -> str:
        offset = _bounded_int(params, "offset", 0, 0, 10_000_000)
        limit = _bounded_int(params, "limit", 25, 1, _MAX_PAGE_SIZE)
        direction = str(params.get("direction", "")).strip().upper()
        transport = str(params.get("transport", "")).strip().upper()
        endpoint = str(params.get("endpoint", "")).strip()
        protocol = str(params.get("protocol", "")).strip().casefold()
        encryption = str(params.get("encryption", "")).strip().upper()
        unknown_cluster_id = str(params.get("unknown_cluster_id", "")).strip()
        alignment_status = str(params.get("alignment_status", "")).strip().upper()
        port = int(params["port"]) if params.get("port") not in {None, ""} else None
        if port is not None and not 0 <= port <= 65535:
            raise ValueError("port 必须位于 0..65535")

        aligned_flow_ids: set[str] | None = None
        if alignment_status:
            aligned_flow_ids = {
                str(flow_id)
                for item in _read_array(store, "declaration-alignments.json")
                if str(item.get("overall", "")).upper() == alignment_status
                for flow_id in item.get("flow_ids", [])
            }

        matches: list[dict] = []
        matched = 0
        has_more = False
        for flow in store.iter_jsonl("flows.jsonl"):
            if direction and str(flow.get("direction_relative_to_dut", "")).upper() != direction:
                continue
            if transport and str(flow.get("transport", "")).upper() != transport:
                continue
            if endpoint and endpoint not in {flow.get("src_ip"), flow.get("dst_ip")}:
                continue
            if port is not None and port not in {flow.get("src_port"), flow.get("dst_port")}:
                continue
            candidates = flow.get("protocol_candidates") or []
            if protocol and not any(
                str(item.get("name", "")).casefold() == protocol
                for item in candidates if isinstance(item, dict)
            ):
                continue
            assessment = flow.get("encryption") or {}
            if encryption and str(assessment.get("classification", "")).upper() != encryption:
                continue
            if unknown_cluster_id and flow.get("unknown_cluster_id") != unknown_cluster_id:
                continue
            if aligned_flow_ids is not None and flow.get("flow_id") not in aligned_flow_ids:
                continue
            if matched < offset:
                matched += 1
                continue
            if len(matches) >= limit:
                has_more = True
                break
            matches.append(flow)
            matched += 1
        return _json({
            "offset": offset,
            "limit": limit,
            "returned": len(matches),
            "has_more": has_more,
            "flows": matches,
        })

    async def get_flow(params: dict) -> str:
        flow_id = str(params.get("flow_id", "")).strip()
        if not flow_id:
            raise ValueError("flow_id 不能为空")
        for flow in store.iter_jsonl("flows.jsonl"):
            if flow.get("flow_id") == flow_id:
                return _json(flow)
        raise KeyError(f"Flow 不存在: {flow_id}")

    async def list_unknown_clusters(params: dict) -> str:
        clusters = _read_array(store, "unknown-protocol-clusters.json")
        offset = _bounded_int(params, "offset", 0, 0, len(clusters))
        limit = _bounded_int(params, "limit", 25, 1, _MAX_PAGE_SIZE)
        return _json({
            "offset": offset,
            "limit": limit,
            "total": len(clusters),
            "clusters": clusters[offset:offset + limit],
        })

    async def get_unknown_cluster(params: dict) -> str:
        cluster_id = str(params.get("cluster_id", "")).strip()
        for cluster in _read_array(store, "unknown-protocol-clusters.json"):
            if cluster.get("cluster_id") == cluster_id:
                return _json(cluster)
        raise KeyError(f"未知协议 cluster 不存在: {cluster_id}")

    async def get_encryption_assessment(params: dict) -> str:
        flow_id = str(params.get("flow_id", "")).strip()
        for assessment in store.iter_jsonl("encryption-assessments.jsonl"):
            if assessment.get("flow_id") == flow_id:
                return _json(assessment)
        raise KeyError(f"Flow 没有加密评估: {flow_id}")

    async def compare_declarations(params: dict) -> str:
        alignments = _read_array(store, "declaration-alignments.json")
        status = str(params.get("status", "")).strip().upper()
        declaration_id = str(params.get("declaration_id", "")).strip()
        filtered = [
            item for item in alignments
            if (not status or str(item.get("overall", "")).upper() == status)
            and (not declaration_id or item.get("declaration_id") == declaration_id)
        ]
        limit = _bounded_int(params, "limit", 50, 1, _MAX_PAGE_SIZE)
        return _json({"total": len(filtered), "alignments": filtered[:limit]})

    async def list_activity_windows(params: dict) -> str:
        windows = _read_array(store, "automatic-activity-windows.json")
        kind = str(params.get("kind", "")).strip().upper()
        flow_id = str(params.get("flow_id", "")).strip()
        filtered = [
            item for item in windows
            if (not kind or str(item.get("kind", "")).upper() == kind)
            and (not flow_id or flow_id in item.get("flow_ids", []))
        ]
        offset = _bounded_int(params, "offset", 0, 0, len(filtered))
        limit = _bounded_int(params, "limit", 25, 1, _MAX_PAGE_SIZE)
        return _json({
            "offset": offset,
            "limit": limit,
            "total": len(filtered),
            "windows": filtered[offset:offset + limit],
        })

    async def list_dns_correlations(params: dict) -> str:
        correlations = _read_array(store, "dns-correlations.json")
        hostname = str(params.get("hostname", "")).strip().casefold().rstrip(".")
        endpoint = str(params.get("endpoint", "")).strip()
        flow_id = str(params.get("flow_id", "")).strip()
        filtered = [
            item for item in correlations
            if (not hostname or str(item.get("hostname", "")).casefold().rstrip(".") == hostname)
            and (
                not endpoint
                or endpoint in item.get("resolved_addresses", [])
                or endpoint in item.get("observed_endpoint_addresses", [])
            )
            and (not flow_id or flow_id in item.get("flow_ids", []))
        ]
        offset = _bounded_int(params, "offset", 0, 0, len(filtered))
        limit = _bounded_int(params, "limit", 25, 1, _MAX_PAGE_SIZE)
        return _json({
            "offset": offset,
            "limit": limit,
            "total": len(filtered),
            "correlations": filtered[offset:offset + limit],
        })

    async def get_frame_details(params: dict) -> str:
        raw = params.get("frame_numbers")
        if not isinstance(raw, list):
            raise ValueError("frame_numbers 必须是整数数组")
        frame_numbers = []
        for value in raw:
            number = int(value)
            if number < 1:
                raise ValueError("frame number 必须大于 0")
            frame_numbers.append(number)
        frame_numbers = sorted(set(frame_numbers))
        if len(frame_numbers) > _MAX_FRAME_DETAILS:
            raise ValueError(f"一次最多查询 {_MAX_FRAME_DETAILS} 个 frame")
        wanted = set(frame_numbers)
        frames = [
            frame for frame in store.iter_jsonl("frames.jsonl")
            if frame.get("frame_number") in wanted
        ]
        return _json({
            "requested": frame_numbers,
            "returned": len(frames),
            "payload_included": False,
            "frames": frames,
        })

    async def get_stream_sample(params: dict) -> str:
        return _json({
            "status": "disabled",
            "flow_id": str(params.get("flow_id", "")),
            "reason": "当前 Bundle 未生成原始 Stream；默认 metadata_only 策略禁止返回 Payload",
        })

    async def try_decode_as(params: dict) -> str:
        flow_id = str(params.get("flow_id", "")).strip()
        dissector = str(params.get("dissector", "")).strip()
        if not flow_id or not dissector:
            raise ValueError("flow_id 和 dissector 不能为空")
        runner = DecodeAsRunner(workspace, tshark_path=tshark_path)
        return _json(await asyncio.to_thread(runner.run, flow_id, dissector))

    definitions = [
        ToolDef("traffic_get_inventory", "Read the bounded traffic inventory summary.", []),
        ToolDef("traffic_list_flows", "List normalized flows with bounded local filters.", [
            ToolParam("offset", "integer", "Result offset", required=False),
            ToolParam("limit", "integer", "Maximum rows, capped at 100", required=False),
            ToolParam("direction", "string", "INBOUND, OUTBOUND, LATERAL, or UNKNOWN", required=False),
            ToolParam("transport", "string", "TCP, UDP, or SCTP", required=False),
            ToolParam("endpoint", "string", "Exact observed endpoint IP", required=False),
            ToolParam("port", "integer", "Observed local or remote port", required=False),
            ToolParam("protocol", "string", "Exact protocol candidate name", required=False),
            ToolParam("encryption", "string", "Encryption classification", required=False),
            ToolParam("unknown_cluster_id", "string", "Stable unknown cluster ID", required=False),
            ToolParam("alignment_status", "string", "MATCH, MISMATCH, NOT_OBSERVED, UNDECLARED_OBSERVED, or INSUFFICIENT_EVIDENCE", required=False),
        ]),
        ToolDef("traffic_get_flow", "Read one normalized flow by stable flow_id.", [
            ToolParam("flow_id", "string", "Stable flow ID"),
        ]),
        ToolDef("traffic_list_unknown_clusters", "List unknown/private protocol clusters.", [
            ToolParam("offset", "integer", "Result offset", required=False),
            ToolParam("limit", "integer", "Maximum rows, capped at 100", required=False),
        ]),
        ToolDef("traffic_get_unknown_cluster", "Read one unknown protocol cluster.", [
            ToolParam("cluster_id", "string", "Stable unknown cluster ID"),
        ]),
        ToolDef("traffic_get_encryption_assessment", "Read one flow encryption assessment.", [
            ToolParam("flow_id", "string", "Stable flow ID"),
        ]),
        ToolDef("traffic_compare_declarations", "Read bounded IXIT-to-traffic alignment results.", [
            ToolParam("status", "string", "Optional overall alignment status", required=False),
            ToolParam("declaration_id", "string", "Optional declaration ID", required=False),
            ToolParam("limit", "integer", "Maximum rows, capped at 100", required=False),
        ]),
        ToolDef("traffic_list_activity_windows", "List automatically inferred, unlabelled traffic activity windows.", [
            ToolParam("kind", "string", "HEARTBEAT, TRANSFER, FLOW_BURST, RECONNECT, or UNATTRIBUTED_ACTIVITY", required=False),
            ToolParam("flow_id", "string", "Optional stable flow ID", required=False),
            ToolParam("offset", "integer", "Result offset", required=False),
            ToolParam("limit", "integer", "Maximum rows, capped at 100", required=False),
        ]),
        ToolDef("traffic_list_dns_correlations", "List bounded DNS answer to endpoint, Flow, and SNI correlations.", [
            ToolParam("hostname", "string", "Exact normalized hostname", required=False),
            ToolParam("endpoint", "string", "Exact resolved or observed endpoint IP", required=False),
            ToolParam("flow_id", "string", "Optional stable flow ID", required=False),
            ToolParam("offset", "integer", "Result offset", required=False),
            ToolParam("limit", "integer", "Maximum rows, capped at 100", required=False),
        ]),
        ToolDef("traffic_get_frame_details", "Read bounded metadata for up to 20 frames; never returns payload.", [
            ToolParam("frame_numbers", "array", "Frame numbers", items_type="integer"),
        ]),
        ToolDef("traffic_get_stream_sample", "Check availability of a bounded redacted stream sample.", [
            ToolParam("flow_id", "string", "Stable flow ID"),
            ToolParam("max_bytes", "integer", "Requested byte limit", required=False),
        ]),
        ToolDef("traffic_try_decode_as", "Run allowlisted TShark Decode-As on one UNKNOWN flow without rewriting original facts.", [
            ToolParam("flow_id", "string", "Stable flow ID"),
            ToolParam("dissector", "string", "Pre-approved dissector name"),
        ]),
    ]
    executors = {
        "traffic_get_inventory": get_inventory,
        "traffic_list_flows": list_flows,
        "traffic_get_flow": get_flow,
        "traffic_list_unknown_clusters": list_unknown_clusters,
        "traffic_get_unknown_cluster": get_unknown_cluster,
        "traffic_get_encryption_assessment": get_encryption_assessment,
        "traffic_compare_declarations": compare_declarations,
        "traffic_list_activity_windows": list_activity_windows,
        "traffic_list_dns_correlations": list_dns_correlations,
        "traffic_get_frame_details": get_frame_details,
        "traffic_get_stream_sample": get_stream_sample,
        "traffic_try_decode_as": try_decode_as,
    }
    registry.register(definitions)
    for definition in definitions:
        registry.set_executor(definition.name, executors[definition.name])
        registry.add_to_category(TRAFFIC_INTELLIGENCE_CATEGORY, definition.name)
