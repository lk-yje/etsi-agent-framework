#!/usr/bin/env python3
"""只报告公开仓库风险的位置，不回显可能敏感的原文。"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


PRIVATE_IP = re.compile(
    rb"(?<![0-9])(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3}\.)\d{1,3})(?![0-9])"
)
_BACKSLASH = re.escape(bytes([92]))
PERSONAL_PATH = re.compile(
    b"(?:[A-Za-z]:" + _BACKSLASH + b"Users" + _BACKSLASH + b"|/(?:Users|home)/)",
    re.IGNORECASE,
)
TOKEN = re.compile(rb"(?:gh[pous]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})")
FORBIDDEN_SUFFIXES = {".pcap", ".pcapng", ".sqlite", ".db", ".key", ".pem", ".p12", ".pfx"}
ALLOWED_ENV = {".env.template"}


def tracked_files(root: Path) -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True, stdout=subprocess.PIPE
    )
    return [root / item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]


def line_number(content: bytes, start: int) -> int:
    return content.count(b"\n", 0, start) + 1


def audit(root: Path) -> list[str]:
    findings: list[str] = []
    for path in tracked_files(root):
        relative = path.relative_to(root).as_posix()
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            findings.append(f"forbidden-artifact:{relative}")
        if path.name.startswith(".env") and relative not in ALLOWED_ENV:
            findings.append(f"environment-file:{relative}")
        # 模板只允许占位值；其路径示例不应触发“私人路径”误报。
        if relative in ALLOWED_ENV:
            continue
        if relative.startswith("tests/"):
            continue
        try:
            content = path.read_bytes()
        except OSError as exc:
            findings.append(f"unreadable:{relative}:{type(exc).__name__}")
            continue
        for label, pattern in (("private-ip", PRIVATE_IP), ("personal-path", PERSONAL_PATH), ("token", TOKEN)):
            for match in pattern.finditer(content):
                findings.append(f"{label}:{relative}:{line_number(content, match.start())}")
    return findings


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    findings = audit(root)
    if findings:
        print("public-release audit failed; locations only:")
        print("\n".join(findings))
        return 1
    print("public-release audit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
