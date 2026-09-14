#!/usr/bin/env python3
"""在合成或已获授权的 workspace PCAP 上生成 Direct/EasyTshark 对比报告。"""

from __future__ import annotations

import argparse
from pathlib import Path

from framework.traffic_intelligence.backend_benchmark import run_backend_benchmark
from framework.traffic_intelligence.backends.direct_tshark import DirectTsharkBackend
from framework.traffic_intelligence.backends.easytshark_batch import EasyTsharkBatchBackend


def main() -> int:
    parser = argparse.ArgumentParser(description="Traffic backend A/B benchmark（不上传、不读取原始 Payload）")
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--pcap", required=True, type=Path, help="必须位于 workspace 内")
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument("--easytshark", required=True, help="已实现 Batch CLI 的 Worker 可执行文件")
    parser.add_argument("--dut-ip", action="append", default=[], dest="dut_ips")
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    report_path, report = run_backend_benchmark(
        workspace=args.workspace,
        capture_path=args.pcap,
        tshark_path=args.tshark,
        baseline=DirectTsharkBackend(args.tshark),
        candidate=EasyTsharkBatchBackend(args.easytshark),
        dut_addresses=tuple(args.dut_ips),
        timeout_seconds=args.timeout,
    )
    print(report_path)
    print(report["comparison"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
