"""每节点快照 (Node Snapshot) — 断点续跑 / 幂等跳过 / 证据链追溯的统一地基。

设计见 docs/NODE_SNAPSHOT_DESIGN.md（2026-08-21 定稿）。要点:
1. 三层节点: stage/* | phase/<模块>/<相位> | clause/M0/*（P1 只落 phase 级）
2. input_digest = 任务摘录 + pool 依赖各 key digest + knowledge 文件 digest + 工具配置
   的确定性摘要; **模型名不参与**（已决策: 换模型仍复用旧 evidence, model 仅记录）
3. 匹配语义: digest 相等且产物完好 → 可复用; 不等 → 输入变了, 必须重跑
4. 原则: 保护结果, 不保护运输 — transport 暂停不落快照, 只有已成立的结果才落

存储布局:
    workspace/snapshots/
      index.json                     # node_id → {status, input_digest, attempt_id}
      phase__M1__phase_C.json        # node_id 中 '/' 转义为 '__'
"""

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

# 快照文件的 status 取值
STATUS_IN_PROGRESS = "in_progress"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"


# ============================================================
# 摘要计算
# ============================================================

def canonical_json(value: Any) -> str:
    """规范化 JSON — dict key 递归排序, 定长分隔符, 保证同语义输入同摘要。"""
    def _normalize(item: Any) -> Any:
        if isinstance(item, dict):
            return {str(k): _normalize(item[k]) for k in sorted(item, key=str)}
        if isinstance(item, (list, tuple)):
            return [_normalize(v) for v in item]
        if isinstance(item, (str, int, float, bool)) or item is None:
            return item
        return str(item)  # 兜底: 非原生 JSON 类型转字符串

    return json.dumps(
        _normalize(value),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def digest_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest_value(value: Any) -> str:
    """任意 JSON 值的确定性摘要（pool 值 / 结构化输入用）。"""
    return digest_text(canonical_json(value))


def digest_file(path: Path) -> Optional[str]:
    """文件内容摘要; 文件缺失返回 None（缺失本身就是输入变化, 会导致重跑）。"""
    path = Path(path)
    if not path.is_file():
        return None
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


def compute_input_digest(
    *,
    node_id: str,
    task_core: Dict[str, Any],
    pool_snapshot: Dict[str, Any],
    knowledge_paths: List[Path],
    tool_manifest: Optional[List[str]],
    max_tool_turns: Optional[int],
) -> str:
    """节点输入的确定性摘要 — 决定"能不能复用"。

    task_core 中不要放时间戳 / attempt 等易变字段（由调用方保证）。
    模型名不参与（2026-08-21 决策）。
    """
    payload = {
        "schema_version": SCHEMA_VERSION,
        "node_id": node_id,
        "task": task_core,
        "pool": {key: digest_value(pool_snapshot[key]) for key in sorted(pool_snapshot)},
        "knowledge": [digest_file(p) for p in knowledge_paths],
        "tools": {
            "manifest": sorted(tool_manifest or []),
            "max_tool_turns": max_tool_turns,
        },
    }
    return digest_text(canonical_json(payload))


# ============================================================
# SnapshotStore
# ============================================================

class SnapshotStore:
    """节点快照的读写与复用判定。

    用法:
        store = SnapshotStore(workspace)
        store.record({...})                          # 落快照 (原子写 + 索引)
        snap = store.find_reusable(node_id, digest)  # None 或完整快照
    """

    def __init__(self, workspace: Path):
        self.workspace = Path(workspace)
        self.root = self.workspace / "snapshots"
        self.index_path = self.root / "index.json"

    # ===== 路径 =====

    @staticmethod
    def node_id_to_filename(node_id: str) -> str:
        return node_id.replace("/", "__") + ".json"

    def snapshot_path(self, node_id: str) -> Path:
        return self.root / self.node_id_to_filename(node_id)

    # ===== 读 =====

    def load_index(self) -> Dict[str, dict]:
        if not self.index_path.exists():
            return {}
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
            return data.get("nodes", {})
        except json.JSONDecodeError as e:
            logger.warning("[SnapshotStore] index 损坏, 视为空: %s", e)
            return {}

    def get(self, node_id: str) -> Optional[dict]:
        path = self.snapshot_path(node_id)
        if not path.exists():
            return None
        try:
            snapshot = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            logger.warning("[SnapshotStore] 快照损坏 %s: %s", node_id, e)
            return None
        if snapshot.get("schema_version") != SCHEMA_VERSION:
            return None  # 版本不匹配 → 不可复用
        return snapshot

    def find_reusable(self, node_id: str, input_digest: str) -> Optional[dict]:
        """返回可复用的快照; None = 无快照 / digest 不匹配 / 产物不完好。"""
        snapshot = self.get(node_id)
        if snapshot is None:
            return None
        if snapshot.get("status") != STATUS_COMPLETED:
            return None
        if snapshot.get("input_digest") != input_digest:
            return None
        # 产物完好性: 每个 output 文件存在且内容摘要一致
        for output in snapshot.get("outputs", []):
            path = self.workspace / output.get("path", "")
            if not path.is_file():
                return None
            if digest_file(path) != output.get("digest"):
                return None  # 产物被改过 → 不可信
        return snapshot

    # ===== 写 =====

    def record(self, snapshot: dict) -> Path:
        """落快照: 原子写节点文件 + 原子更新索引。"""
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.snapshot_path(snapshot["node_id"])

        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(snapshot, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        tmp.replace(path)

        # 更新索引 (读-改-写, 单进程使用, 无并发竞争)
        index = self.load_index()
        index[snapshot["node_id"]] = {
            "status": snapshot.get("status"),
            "input_digest": snapshot.get("input_digest"),
            "attempt_id": snapshot.get("attempt_id"),
            "updated_at": snapshot.get("ended_at") or snapshot.get("started_at"),
        }
        index_tmp = self.index_path.with_suffix(".json.tmp")
        index_tmp.write_text(
            json.dumps({"schema_version": SCHEMA_VERSION, "nodes": index}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        index_tmp.replace(self.index_path)
        return path

    # ===== 便捷构造 =====

    @staticmethod
    def build_snapshot(
        *,
        node_id: str,
        kind: str,
        status: str,
        attempt_id: str,
        input_digest: str,
        outputs: Optional[List[dict]] = None,
        pool_outputs_written: Optional[List[str]] = None,
        model: Optional[str] = None,
        agent_id: Optional[str] = None,
        parent: Optional[str] = None,
        started_at: Optional[float] = None,
        error: Optional[str] = None,
    ) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "node_id": node_id,
            "kind": kind,
            "status": status,
            "attempt_id": attempt_id,
            "input_digest": input_digest,
            "outputs": outputs or [],
            "pool_outputs_written": pool_outputs_written or [],
            "model": model,
            "agent_id": agent_id,
            "parent": parent,
            "started_at": started_at,
            "ended_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "error": error,
        }
