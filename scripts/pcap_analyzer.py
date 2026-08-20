#!/usr/bin/env python3
"""
pcap_analyzer.py -- ETSI TS 103701 pcap 批量分析 (v2: 合并查询 + 并行)
用法:
  python pcap_analyzer.py <pcap_path> [--dut-ip 192.0.2.54] [--out-dir pcap_analysis]

输出: pcap_analysis/ 下 22 个结构化文件 (19 JSON + 3 TXT)
  索引: _index.json, _summary.txt
"""

import subprocess
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================
# 配置
# ============================================================

# TSHARK 路径占位符 → 实际值见 ../../path-mapping.json → TOOL.TSHARK
TSHARK = r"D:\Wireshark\tshark.exe"  # ${TOOL.TSHARK}

# ---- 查询组定义 ----
# 每个 group = 一次 tshark 调用 → 产生 1~N 个输出文件
# 共享 display_filter 的查询合并为一个 group，省去重复扫包

QUERY_GROUPS = [
    # ===== Group: tls.handshake.type==2 → 3 个输出 =====
    {
        "display_filter": "tls.handshake.type==2",
        "all_fields": [
            "frame.number",
            "tcp.dstport",
            "tls.handshake.extensions.supported_version",
            "tls.handshake.ciphersuite",
            "tls.handshake.type",
        ],
        "outputs": [
            {
                "id": "5.1-3_tls_versions",
                "clause": "5.1-3",
                "description": "TLS 版本协商统计 (ServerHello)",
                "fields": ["tls.handshake.extensions.supported_version"],
                "post_process": "count_values",
                "output_format": "json",
            },
            {
                "id": "5.1-3_tls_ciphers",
                "clause": "5.1-3",
                "description": "TLS 密文套件协商统计 (ServerHello)",
                "fields": ["tls.handshake.ciphersuite"],
                "post_process": "count_values",
                "output_format": "json",
            },
            {
                "id": "5.5-1_server_hello",
                "clause": "5.5-1",
                "description": "ServerHello 逐帧: 帧号 + 端口 + TLS版本 + 密文套件 + 握手类型",
                "fields": [
                    "frame.number",
                    "tcp.dstport",
                    "tls.handshake.extensions.supported_version",
                    "tls.handshake.ciphersuite",
                    "tls.handshake.type",
                ],
                "post_process": "as_table",
                "output_format": "json",
            },
        ],
    },
    # ===== Group: tls.handshake.type==1 → 1 个输出 =====
    {
        "display_filter": "tls.handshake.type==1",
        "all_fields": [
            "frame.number",
            "tcp.dstport",
            "tls.handshake.extensions.supported_version",
            "tls.handshake.type",
        ],
        "outputs": [
            {
                "id": "5.5-1_client_hello",
                "clause": "5.5-1",
                "description": "ClientHello 逐帧: 帧号 + 端口 + TLS版本 + 握手类型",
                "fields": [
                    "frame.number",
                    "tcp.dstport",
                    "tls.handshake.extensions.supported_version",
                    "tls.handshake.type",
                ],
                "post_process": "as_table",
                "output_format": "json",
            },
        ],
    },
    # ===== Group: proto_hierarchy (-z io,phs) → 1 个输出 =====
    {
        "display_filter": None,
        "all_fields": [],
        "custom_args": ["-q", "-z", "io,phs"],
        "outputs": [
            {
                "id": "5.5-1_proto_hierarchy",
                "clause": "5.5-1",
                "description": "协议分层统计",
                "fields": [],
                "post_process": "raw_text",
                "output_format": "txt",
            },
        ],
    },
    # ===== Group: conversations (-z conv,tcp) → 1 个输出 =====
    {
        "display_filter": None,
        "all_fields": [],
        "custom_args": ["-q", "-z", "conv,tcp"],
        "outputs": [
            {
                "id": "5.5-1_conversations",
                "clause": "5.5-1",
                "description": "TCP 会话摘要",
                "fields": [],
                "post_process": "raw_text",
                "output_format": "txt",
            },
        ],
    },
    # ===== Group: http → 1 个输出 =====
    {
        "display_filter": "http",
        "all_fields": [
            "frame.number",
            "ip.src",
            "ip.dst",
            "http.request.method",
            "http.request.uri",
            "http.response.code",
        ],
        "outputs": [
            {
                "id": "5.5-1_http_check",
                "clause": "5.5-1",
                "description": "HTTP 明文帧检查 (应为空或仅重定向)",
                "fields": [
                    "frame.number",
                    "ip.src",
                    "ip.dst",
                    "http.request.method",
                    "http.request.uri",
                    "http.response.code",
                ],
                "post_process": "as_table",
                "output_format": "json",
            },
        ],
    },
    # ===== Group: http.response → 1 个输出 =====
    {
        "display_filter": "http.response",
        "all_fields": [
            "frame.number",
            "http.response.code",
            "http.content_length_header",
            "http.content_type",
        ],
        "outputs": [
            {
                "id": "5.5-1_http_responses",
                "clause": "5.5-1",
                "description": "HTTP 响应摘要: 帧号 + 状态码 + Content-Length + Content-Type",
                "fields": [
                    "frame.number",
                    "http.response.code",
                    "http.content_length_header",
                    "http.content_type",
                ],
                "post_process": "as_table",
                "output_format": "json",
            },
        ],
    },
    # ===== Group: ip.src==DUT → 2 个输出 (dut_outbound + all_destinations) =====
    {
        "display_filter": None,  # dynamic
        "dynamic_filter": "ip.src=={DUT_IP}",
        "all_fields": ["ip.dst", "tcp.dstport"],
        "outputs": [
            {
                "id": "5.5-6_dut_outbound",
                "clause": "5.5-6",
                "description": "DUT 外连目标 IP:端口 (去重计数)",
                "fields": ["ip.dst", "tcp.dstport"],
                "post_process": "count_pairs",
                "output_format": "json",
            },
            {
                "id": "5.5-7_all_destinations",
                "clause": "5.5-7",
                "description": "DUT 所有外连目标 (含测试机)",
                "fields": ["ip.dst"],
                "post_process": "unique_values",
                "output_format": "json",
            },
        ],
    },
    # ===== Group: ip.src==DUT && !tls → 1 个输出 =====
    {
        "display_filter": None,
        "dynamic_filter": "ip.src=={DUT_IP} && !tls",
        "all_fields": ["frame.number", "ip.dst", "tcp.dstport", "frame.protocols"],
        "outputs": [
            {
                "id": "5.5-6_non_tls",
                "clause": "5.5-6",
                "description": "DUT 外连非 TLS 流量 (找明文 CSP)",
                "fields": ["frame.number", "ip.dst", "tcp.dstport", "frame.protocols"],
                "post_process": "as_table",
                "output_format": "json",
            },
        ],
    },
    # ===== Group: ip.src==DUT && http → 1 个输出 =====
    {
        "display_filter": None,
        "dynamic_filter": "ip.src=={DUT_IP} && http",
        "all_fields": ["frame.number", "ip.dst", "http.request.uri"],
        "outputs": [
            {
                "id": "5.5-6_http_outbound",
                "clause": "5.5-6",
                "description": "DUT 外连 HTTP 明文 (直接 FAIL 证据)",
                "fields": ["frame.number", "ip.dst", "http.request.uri"],
                "post_process": "as_table",
                "output_format": "json",
            },
        ],
    },
    # ===== Group: ip.src==DUT && tls.record.content_type==23 → 1 个输出 =====
    {
        "display_filter": None,
        "dynamic_filter": "ip.src=={DUT_IP} && tls.record.content_type==23",
        "all_fields": ["frame.number", "ip.dst", "tcp.dstport", "tls.record.length"],
        "outputs": [
            {
                "id": "5.5-6_tls_appdata",
                "clause": "5.5-6",
                "description": "DUT 外连 TLS Application Data (CSP 实际载荷)",
                "fields": ["frame.number", "ip.dst", "tcp.dstport", "tls.record.length"],
                "post_process": "as_table",
                "output_format": "json",
            },
        ],
    },
    # ===== Group: ip.src==DUT && not ip.dst==TEST → 1 个输出 =====
    {
        "display_filter": None,
        "dynamic_filter": "ip.src=={DUT_IP} && not ip.dst=={TEST_IP}",
        "all_fields": ["ip.dst"],
        "outputs": [
            {
                "id": "5.5-7_remote_ips",
                "clause": "5.5-7",
                "description": "DUT 外连远程 IP 去重列表",
                "fields": ["ip.dst"],
                "post_process": "unique_values",
                "output_format": "json",
            },
        ],
    },
    # ===== Group: broadcast/multicast → 1 个输出 =====
    {
        "display_filter": (
            "eth.dst[0]==1 || ip.dst==255.255.255.255 "
            "|| (ip.dst>=224.0.0.0 && ip.dst<=239.255.255.255)"
        ),
        "all_fields": ["frame.number", "ip.src", "ip.dst", "frame.protocols"],
        "outputs": [
            {
                "id": "5.6-2_broadcast",
                "clause": "5.6-2",
                "description": "广播/组播流量",
                "fields": ["frame.number", "ip.src", "ip.dst", "frame.protocols"],
                "post_process": "as_table",
                "output_format": "json",
            },
        ],
    },
    # ===== Group: plaintext TCP services → 1 个输出 =====
    {
        "display_filter": (
            "tcp.payload && !tls && !http && ip.dst=={DUT_IP} && tcp.dstport!=443"
        ),
        "all_fields": ["frame.number", "tcp.dstport", "tcp.payload"],
        "outputs": [
            {
                "id": "5.6-2_plaintext_services",
                "clause": "5.6-2",
                "description": "非 TLS 非 HTTP 的 TCP payload (前80字节hex)",
                "fields": ["frame.number", "tcp.dstport", "tcp.payload"],
                "post_process": "as_table",
                "output_format": "json",
            },
        ],
    },
    # ===== Group: tcp.flags.syn==1 && tcp.flags.ack==0 → 2 个输出 =====
    {
        "display_filter": "tcp.flags.syn==1 && tcp.flags.ack==0",
        "all_fields": [
            "frame.number",
            "frame.time_relative",
            "ip.src",
            "ip.dst",
            "tcp.dstport",
        ],
        "outputs": [
            {
                "id": "5.9-3_syn_timestamps",
                "clause": "5.9-3",
                "description": "所有 SYN 包时间戳 (用于重连间隔分析)",
                "fields": [
                    "frame.number",
                    "frame.time_relative",
                    "ip.src",
                    "ip.dst",
                    "tcp.dstport",
                ],
                "post_process": "compute_intervals",
                "output_format": "json",
            },
            {
                "id": "5.9-3_syn_bursts",
                "clause": "5.9-3",
                "description": "SYN 包突发检测 (间隔<1秒的连续SYN)",
                "fields": [
                    "frame.number",
                    "frame.time_relative",
                    "ip.src",
                    "ip.dst",
                    "tcp.dstport",
                ],
                "post_process": "detect_bursts",
                "output_format": "json",
            },
        ],
    },
    # ===== Group: tcp.analysis.retransmission → 1 个输出 =====
    {
        "display_filter": "tcp.analysis.retransmission",
        "all_fields": ["frame.number", "ip.src", "tcp.dstport"],
        "outputs": [
            {
                "id": "5.9-3_retransmissions",
                "clause": "5.9-3",
                "description": "TCP 重传统计",
                "fields": ["frame.number", "ip.src", "tcp.dstport"],
                "post_process": "count_by_src",
                "output_format": "json",
            },
        ],
    },
    # ===== Group: http.request → 1 个输出 =====
    {
        "display_filter": "http.request",
        "all_fields": ["http.request.method", "http.request.uri", "ip.src"],
        "outputs": [
            {
                "id": "5.3-2_http_methods",
                "clause": "5.3-2",
                "description": "HTTP 请求方法统计 (找固件更新相关 API)",
                "fields": ["http.request.method", "http.request.uri", "ip.src"],
                "post_process": "as_table",
                "output_format": "json",
            },
        ],
    },
    # ===== Group: sensitive keywords → 1 个输出 =====
    {
        "display_filter": (
            'http contains "password" or http contains "sessionID" '
            'or http contains "token" or http contains "secret"'
        ),
        "all_fields": [
            "frame.number",
            "http.request.method",
            "http.request.uri",
            "ip.dst",
        ],
        "outputs": [
            {
                "id": "5.5-6_sensitive_keywords",
                "clause": "5.5-6",
                "description": "HTTP 请求中敏感词扫描 (password/sessionID/token/key/secret)",
                "fields": [
                    "frame.number",
                    "http.request.method",
                    "http.request.uri",
                    "ip.dst",
                ],
                "post_process": "as_table",
                "output_format": "json",
            },
        ],
    },
    # ===== Group: global summary (-z io,stat,0) → 1 个输出 =====
    {
        "display_filter": None,
        "all_fields": [],
        "custom_args": ["-q", "-z", "io,stat,0"],
        "outputs": [
            {
                "id": "_global_summary",
                "clause": "_global",
                "description": "pcap 全局摘要",
                "fields": [],
                "post_process": "raw_text",
                "output_format": "txt",
            },
        ],
    },
]


# ============================================================
# 后处理函数
# ============================================================

def count_values(rows):
    counter = Counter()
    for row in rows:
        for val in row:
            if val:
                counter[val] += 1
    return [{"value": k, "count": v} for k, v in counter.most_common()]


def count_pairs(rows):
    counter = Counter()
    for row in rows:
        if len(row) >= 2:
            counter[(row[0], row[1])] += 1
    return [{"ip": k[0], "port": k[1], "count": v} for k, v in counter.most_common()]


def unique_values(rows):
    vals = set()
    for row in rows:
        for val in row:
            if val:
                vals.add(val)
    return sorted(vals)


def count_by_src(rows):
    counter = Counter()
    for row in rows:
        if row:
            counter[row[0]] += 1
    return [{"src": k, "count": v} for k, v in counter.most_common()]


def as_table(rows):
    return {
        "total_rows": len(rows),
        "shown_rows": min(len(rows), 200),
        "columns": len(rows[0]) if rows else 0,
        "data": rows[:200],
    }


def compute_intervals(rows):
    if len(rows) < 2:
        return {"error": "not enough SYN packets for interval analysis"}

    times = []
    for row in rows:
        try:
            times.append({
                "frame": int(row[0]),
                "time": float(row[1]),
                "src": row[2],
                "dst": row[3],
                "port": row[4]
            })
        except (ValueError, IndexError):
            continue

    deltas = []
    for i in range(1, len(times)):
        delta = times[i]["time"] - times[i - 1]["time"]
        deltas.append({
            "from_frame": times[i - 1]["frame"],
            "to_frame": times[i]["frame"],
            "delta_s": round(delta, 6),
            "src": times[i]["src"],
        })

    delta_values = [d["delta_s"] for d in deltas]
    sub_second = sum(1 for d in delta_values if d < 1.0)
    sub_100ms = sum(1 for d in delta_values if d < 0.1)
    sub_10ms = sum(1 for d in delta_values if d < 0.01)

    return {
        "total_syn": len(times),
        "total_intervals": len(deltas),
        "min_delta_s": round(min(delta_values), 6) if delta_values else None,
        "max_delta_s": round(max(delta_values), 2) if delta_values else None,
        "avg_delta_s": round(sum(delta_values) / len(delta_values), 4) if delta_values else None,
        "intervals_sub_1s": sub_second,
        "intervals_sub_100ms": sub_100ms,
        "intervals_sub_10ms": sub_10ms,
        "verdict_hint": (
            "FAIL: 无退避" if sub_10ms > 5
            else "WARN: 存在亚10ms突发" if sub_10ms > 0
            else "PASS: 存在间隔"
        ),
        "sample_deltas": deltas[:30],
    }


def detect_bursts(rows):
    if len(rows) < 3:
        return {"bursts": [], "verdict": "not enough data"}

    times = []
    for row in rows:
        try:
            times.append({
                "frame": int(row[0]),
                "time": float(row[1]),
                "src": row[2],
                "dst": row[3],
                "port": row[4]
            })
        except (ValueError, IndexError):
            continue

    bursts = []
    current_burst = [times[0]]
    for i in range(1, len(times)):
        delta = times[i]["time"] - times[i - 1]["time"]
        if delta < 1.0:
            current_burst.append(times[i])
        else:
            if len(current_burst) >= 3:
                bursts.append({
                    "start_frame": current_burst[0]["frame"],
                    "end_frame": current_burst[-1]["frame"],
                    "start_time": current_burst[0]["time"],
                    "end_time": current_burst[-1]["time"],
                    "duration_s": round(current_burst[-1]["time"] - current_burst[0]["time"], 6),
                    "syn_count": len(current_burst),
                    "avg_interval_ms": round(
                        (current_burst[-1]["time"] - current_burst[0]["time"])
                        / max(len(current_burst) - 1, 1) * 1000, 3
                    ),
                    "src": current_burst[0]["src"],
                })
            current_burst = [times[i]]

    if len(current_burst) >= 3:
        bursts.append({
            "start_frame": current_burst[0]["frame"],
            "end_frame": current_burst[-1]["frame"],
            "start_time": current_burst[0]["time"],
            "end_time": current_burst[-1]["time"],
            "duration_s": round(current_burst[-1]["time"] - current_burst[0]["time"], 6),
            "syn_count": len(current_burst),
            "src": current_burst[0]["src"],
        })

    return {
        "total_bursts": len(bursts),
        "verdict_hint": (
            "FAIL: 存在密集SYN突发，无退避"
            if len(bursts) > 0 and any(b["syn_count"] > 10 for b in bursts)
            else "WARN: 存在小规模突发" if len(bursts) > 0
            else "PASS: 无明显突发"
        ),
        "bursts": bursts[:10],
    }


def raw_text(rows):
    return rows


POST_PROCESSORS = {
    "count_values": count_values,
    "count_pairs": count_pairs,
    "unique_values": unique_values,
    "count_by_src": count_by_src,
    "as_table": as_table,
    "compute_intervals": compute_intervals,
    "detect_bursts": detect_bursts,
    "raw_text": raw_text,
}


# ============================================================
# 核心逻辑
# ============================================================

def run_tshark(pcap_path, display_filter=None, fields=None, custom_args=None, timeout=120):
    """运行 tshark 返回行列表 (fields 模式) 或原始字符串 (custom_args 模式)"""
    cmd = [TSHARK, "-r", pcap_path]

    if custom_args:
        cmd.extend(custom_args)
    else:
        if display_filter:
            cmd.extend(["-Y", display_filter])
        if fields:
            cmd.append("-T")
            cmd.append("fields")
            for f in fields:
                cmd.extend(["-e", f])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        if custom_args:
            return result.stdout.strip()

        lines = result.stdout.strip().split("\n") if result.stdout.strip() else []
        rows = []
        for line in lines:
            if line.strip():
                rows.append(line.split("\t"))
        return rows

    except subprocess.TimeoutExpired:
        return "" if custom_args else []
    except Exception:
        return "" if custom_args else []


def resolve_filter(raw, dut_ip, test_ip):
    """替换 filter 中的占位符"""
    if raw:
        return raw.replace("{DUT_IP}", dut_ip).replace("{TEST_IP}", test_ip)
    return None


def process_group(group, pcap_path, dut_ip, test_ip):
    """处理一个查询组: 一次 tshark → N 个输出文件内容"""
    display_filter = resolve_filter(
        group.get("dynamic_filter") or group.get("display_filter"),
        dut_ip, test_ip,
    )
    custom_args = group.get("custom_args")
    all_fields = group.get("all_fields", [])
    outputs = group["outputs"]

    # 一次 tshark 调用
    raw = run_tshark(pcap_path, display_filter, all_fields, custom_args)

    # 对每个 output 执行后处理
    results = []
    for out in outputs:
        out_fields = out.get("fields", [])
        post_proc = out.get("post_process", "as_table")
        processor = POST_PROCESSORS.get(post_proc)

        if custom_args:
            # -z 模式: raw 是字符串，所有 output 共用同一份
            processed = processor(raw) if processor else raw
        elif out_fields and all_fields:
            # 从全量字段中提取该 output 需要的列
            field_indices = [all_fields.index(f) for f in out_fields if f in all_fields]
            sub_rows = []
            for row in raw:
                sub_rows.append([row[i] for i in field_indices if i < len(row)])
            processed = processor(sub_rows) if processor else as_table(sub_rows)
        else:
            processed = processor(raw) if processor else as_table(raw)

        results.append({
            "id": out["id"],
            "clause": out["clause"],
            "description": out["description"],
            "command_filter": display_filter,
            "command_fields": all_fields,
            "command_custom": custom_args,
            "result": processed,
            "output_format": out.get("output_format", "json"),
        })

    return results


def write_output(result, output_dir):
    """将单条结果写入文件"""
    qid = result["id"]
    fmt = result.get("output_format", "json")
    clause = result["clause"]
    desc = result["description"]

    if fmt == "json":
        out_path = os.path.join(output_dir, f"{qid}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2, default=str)
    else:
        out_path = os.path.join(output_dir, f"{qid}.txt")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(f"# clause: {clause}\n")
            f.write(f"# description: {desc}\n")
            f.write(f"# filter: {result.get('command_filter', 'N/A')}\n")
            f.write(f"# generated: {datetime.now().isoformat()}\n")
            f.write("=" * 60 + "\n")
            f.write(str(result.get("result", "")))

    return qid, out_path, fmt


def make_summary_line(result):
    """从结果生成摘要一行"""
    res = result.get("result", {})
    qid = result["id"]
    if isinstance(res, dict) and "verdict_hint" in res:
        return f"  {qid}: {res['verdict_hint']}"
    elif isinstance(res, list):
        return f"  {qid}: {len(res)} records"
    elif isinstance(res, dict) and "total_rows" in res:
        return f"  {qid}: {res['total_rows']} rows"
    elif isinstance(res, str):
        return f"  {qid}: {len(res)} chars raw"
    return f"  {qid}: OK"


def run_all(pcap_path, output_dir, dut_ip, test_ip, max_workers=6):
    """主入口: 并行处理所有查询组"""
    pcap_path = os.path.abspath(pcap_path)
    output_dir = os.path.abspath(output_dir)

    if not os.path.exists(pcap_path):
        print(f"ERROR: pcap not found: {pcap_path}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    print(f"[+] pcap: {pcap_path}")
    print(f"[+] DUT: {dut_ip}  测试机: {test_ip}")
    print(f"[+] Output: {output_dir}")
    print(f"[+] {len(QUERY_GROUPS)} query groups → {sum(len(g['outputs']) for g in QUERY_GROUPS)} output files")
    print(f"[+] Parallel workers: {max_workers}\n")

    index = {
        "pcap": pcap_path,
        "dut_ip": dut_ip,
        "test_ip": test_ip,
        "generated": datetime.now().isoformat(),
        "queries": {},
    }
    summary_lines = []

    # 并行跑各组
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_group, group, pcap_path, dut_ip, test_ip): group
            for group in QUERY_GROUPS
        }

        for future in as_completed(futures):
            group = futures[future]
            group_label = group["outputs"][0]["id"]
            try:
                results = future.result()
                for result in results:
                    qid, out_path, fmt = write_output(result, output_dir)
                    summary_lines.append(make_summary_line(result))
                    index["queries"][qid] = {
                        "clause": result["clause"],
                        "description": result["description"],
                        "file": os.path.basename(out_path),
                        "format": fmt,
                    }
                print(f"  [OK] {group_label} (+{len(results)-1} merged)")
            except Exception as e:
                print(f"  [FAIL] {group_label}: {e}")

    # 写索引
    index_path = os.path.join(output_dir, "_index.json")
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2, default=str)

    # 写摘要
    summary_path = os.path.join(output_dir, "_summary.txt")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(f"pcap: {pcap_path}\n")
        f.write(f"DUT: {dut_ip}  Test: {test_ip}\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write("=" * 60 + "\n")
        f.write("\n".join(summary_lines))

    print(f"\n[+] Done. {len(QUERY_GROUPS)} groups → {output_dir}/")
    print(f"    Index: {index_path}")
    print(f"    Summary: {summary_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ETSI pcap 批量分析")
    parser.add_argument("pcap", help="pcap 文件路径")
    parser.add_argument("--dut-ip", default="192.0.2.54", help="DUT IP（文档示例地址，运行时必须覆盖）")
    parser.add_argument("--test-ip", default="192.0.2.36", help="测试机 IP（文档示例地址，运行时必须覆盖）")
    parser.add_argument("--out-dir", default=None, help="输出目录 (默认 pcap 同目录下的 pcap_analysis/)")
    parser.add_argument("--workers", default=6, type=int, help="并行线程数 (默认 6)")

    args = parser.parse_args()

    if args.out_dir is None:
        pcap_dir = os.path.dirname(os.path.abspath(args.pcap))
        args.out_dir = os.path.join(pcap_dir, "pcap_analysis")

    # 自动检测测试机 IP
    if args.test_ip == "192.0.2.36":
        dut = args.dut_ip
        rows = run_tshark(args.pcap, "ip", ["ip.src"])
        counter = Counter()
        for row in rows:
            if row and row[0] and row[0] != dut:
                counter[row[0]] += 1
        if counter:
            detected = counter.most_common(1)[0][0]
            args.test_ip = detected
            print(f"[*] 自动检测测试机 IP: {detected}")

    run_all(args.pcap, args.out_dir, args.dut_ip, args.test_ip, max_workers=args.workers)
