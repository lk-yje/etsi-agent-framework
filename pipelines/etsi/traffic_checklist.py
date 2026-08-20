"""ETSI 阶段 3.1 流量采集 checklist 的唯一模板来源。"""

from __future__ import annotations

import json
from pathlib import Path


_CHECKLIST_PATH = Path(__file__).with_name("traffic_checklist.json")


def load_traffic_checklist() -> tuple[str, list[dict]]:
    """返回版本号与独立副本，避免 Pipeline/Web 各自硬编码清单。"""
    payload = json.loads(_CHECKLIST_PATH.read_text(encoding="utf-8"))
    version = str(payload["checklist_version"])
    items = payload["items"]
    if not isinstance(items, list) or not items:
        raise ValueError("traffic checklist 必须包含至少一个 item")
    seen: set[str] = set()
    copied: list[dict] = []
    for item in items:
        item_id = item.get("id")
        if not isinstance(item_id, str) or not item_id or item_id in seen:
            raise ValueError("traffic checklist item id 必须唯一且非空")
        if not isinstance(item.get("label"), str) or not item["label"]:
            raise ValueError(f"traffic checklist {item_id} 缺少 label")
        seen.add(item_id)
        copied.append(dict(item))
    return version, copied
