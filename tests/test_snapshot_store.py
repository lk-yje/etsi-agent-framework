"""节点快照 (P1) — SnapshotStore + phase_engine 集成测试。

设计: docs/NODE_SNAPSHOT_DESIGN.md (2026-08-21 定稿)
决策: 模型名不参与 digest; traffic 非幂等; P1 只做 phase 级。
"""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from framework.file_bus import FileBus
from framework.context_pool import ContextPool, Scope
from framework.phase_engine import PhaseDef, PhaseExecutionEngine
from framework.snapshot_store import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    SnapshotStore,
    compute_input_digest,
    digest_value,
)


# ═══════════════════════════ 摘要计算 ═══════════════════════════

def test_digest_value_is_key_order_insensitive():
    """同语义、不同 key 顺序 → 同摘要（规范化保证）。"""
    a = digest_value({"ports": [80, 443], "host": "10.0.0.8"})
    b = digest_value({"host": "10.0.0.8", "ports": [80, 443]})
    assert a == b
    assert digest_value({"ports": [80]}) != a


def test_compute_input_digest_stable_and_sensitive(tmp_path):
    """相同输入 → 稳定; 上游 pool 值变 / knowledge 内容变 → 摘要变。"""
    knowledge = tmp_path / "kb.md"
    knowledge.write_text("v1", encoding="utf-8")

    kwargs = dict(
        node_id="phase/M1/phase_A",
        task_core={"module_id": "M1", "clause_ids": ["6.1-1"]},
        pool_snapshot={"upstream": {"ports": [80]}},
        knowledge_paths=[knowledge],
        tool_manifest=["nmap"],
        max_tool_turns=10,
    )
    d1 = compute_input_digest(**kwargs)
    assert d1 == compute_input_digest(**kwargs)  # 稳定

    changed_pool = dict(kwargs, pool_snapshot={"upstream": {"ports": [80, 443]}})
    assert compute_input_digest(**changed_pool) != d1

    knowledge.write_text("v2", encoding="utf-8")
    assert compute_input_digest(**kwargs) != d1  # 知识文件内容参与


# ═══════════════════════════ SnapshotStore ═══════════════════════════

def _record_completed(store: SnapshotStore, workspace: Path, node_id="phase/M1/phase_A"):
    relpath = "evidence/pre-M1-phase_A-evidence.json"
    path = workspace / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"clauses": []}', encoding="utf-8")
    from framework.snapshot_store import digest_file
    store.record(SnapshotStore.build_snapshot(
        node_id=node_id, kind="phase", status=STATUS_COMPLETED,
        attempt_id="run-1", input_digest="sha256:abc",
        outputs=[{"path": relpath, "digest": digest_file(path), "bytes": path.stat().st_size}],
        pool_outputs_written=["shared_key"],
    ))
    return path


def test_record_writes_snapshot_and_index(tmp_path):
    store = SnapshotStore(tmp_path)
    _record_completed(store, tmp_path)

    snap = store.get("phase/M1/phase_A")
    assert snap["status"] == STATUS_COMPLETED
    assert snap["pool_outputs_written"] == ["shared_key"]
    assert store.snapshot_path("phase/M1/phase_A").name == "phase__M1__phase_A.json"

    index = store.load_index()
    assert index["phase/M1/phase_A"]["status"] == STATUS_COMPLETED
    assert index["phase/M1/phase_A"]["attempt_id"] == "run-1"


def test_find_reusable_requires_match_and_intact_outputs(tmp_path):
    store = SnapshotStore(tmp_path)
    evidence_path = _record_completed(store, tmp_path)

    assert store.find_reusable("phase/M1/phase_A", "sha256:abc") is not None
    # digest 不匹配 → 不可复用
    assert store.find_reusable("phase/M1/phase_A", "sha256:xyz") is None
    # 产物被篡改 → 不可复用
    evidence_path.write_text('{"clauses": [], "tampered": true}', encoding="utf-8")
    assert store.find_reusable("phase/M1/phase_A", "sha256:abc") is None
    # 产物缺失 → 不可复用
    _record_completed(store, tmp_path)
    evidence_path.unlink()
    assert store.find_reusable("phase/M1/phase_A", "sha256:abc") is None


def test_find_reusable_rejects_failed_and_bad_version(tmp_path):
    store = SnapshotStore(tmp_path)
    store.record(SnapshotStore.build_snapshot(
        node_id="phase/M2/phase_B", kind="phase", status=STATUS_FAILED,
        attempt_id="run-1", input_digest="sha256:abc", error="exhausted",
    ))
    assert store.find_reusable("phase/M2/phase_B", "sha256:abc") is None

    path = store.snapshot_path("phase/M1/phase_A")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema_version": 99, "node_id": "phase/M1/phase_A"}), encoding="utf-8")
    assert store.get("phase/M1/phase_A") is None


# ═══════════════════════════ phase_engine 集成 ═══════════════════════════

class _Telemetry:
    def __init__(self):
        self.events = []

    def log_stage_event(self, *args, **kwargs):
        self.events.append((args, kwargs))


class _Runner:
    """fake runner: 返回合法 evidence JSON; calls 计数用于断言跳过。"""

    def __init__(self, raw_text=None):
        self.calls = 0
        self.raw_text = raw_text or json.dumps({
            "clauses": [{"clauseId": "6.1-1", "result": "pass"}],
            "shared_key": {"ports": [80]},
        })

    async def run(self, config, task_ctx, tools=None, output_schema=None):
        self.calls += 1
        return SimpleNamespace(raw_text=self.raw_text)


def _phase():
    return PhaseDef(
        id="phase_A", name="扫描", clauses=("6.1-1",), depends_on=(),
        wait_for_pool_keys=(), tools=("nmap",), knowledge_additions=(),
        pool_outputs=({"key": "shared_key", "scope": "PUBLIC"},),
        providers_used=(), max_tool_turns=5,
    )


def _module():
    return SimpleNamespace(
        id="M1", name="通信安全", clauses=("6.1-1",), tools=("nmap",),
        ammo_paths=(), upstream_inputs=[],
    )


def _engine(tmp_path, runner, resume=True):
    # AgentConfig.__post_init__ 要求 persona 是磁盘上真实存在的文件
    persona = tmp_path / "work-persona.md"
    if not persona.exists():
        persona.write_text("# Work Agent persona (test fixture)\n", encoding="utf-8")
    engine = PhaseExecutionEngine(
        tmp_path, ContextPool(tmp_path), runner, FileBus(tmp_path),
        _Telemetry(), SimpleNamespace(shared_knowledge=(), work_agent_persona=persona),
    )
    engine.resume = resume
    return engine


def _pipeline(runner):
    return SimpleNamespace(
        _state=SimpleNamespace(pipeline_id="snap-test"),
        runner=runner,
        tool_registry=None,
    )


def test_phase_executed_once_then_reused_on_resume(tmp_path):
    """第一次实跑落快照; 第二次 resume 且输入未变 → 不调 Agent, 直接复用。"""
    runner = _Runner()
    pipeline = _pipeline(runner)

    engine = _engine(tmp_path, runner, resume=True)
    evidence = asyncio.run(engine._execute_phase(
        _phase(), _module(), tmp_path, pipeline, engine.pipe_def, phase_idx=0,
    ))
    assert runner.calls == 1
    assert evidence["clauses"][0]["clauseId"] == "6.1-1"
    assert (tmp_path / "evidence/pre-M1-phase_A-evidence.json").exists()
    assert (tmp_path / "snapshots/phase__M1__phase_A.json").exists()
    assert ContextPool(tmp_path).get("shared_key", "M1", "phase_B") == {"ports": [80]}

    # 第二次: runner 若被调用即失败 (calls 应保持 1)
    engine2 = _engine(tmp_path, _Runner(), resume=True)
    evidence2 = asyncio.run(engine2._execute_phase(
        _phase(), _module(), tmp_path, _pipeline(runner), engine2.pipe_def, phase_idx=0,
    ))
    assert runner.calls == 1  # 没有重跑
    assert evidence2 == evidence
    assert any(
        args[2] == "phase_snapshot_reused"
        for args, _ in engine2.telemetry.events
    )
    # pool 输出被回放, 下游仍可读
    assert ContextPool(tmp_path).get("shared_key", "M3", "phase_A") == {"ports": [80]}


def test_resume_disabled_never_skips(tmp_path):
    """SNAPSHOT_RESUME 未开启: 快照照落, 但不复用。"""
    runner = _Runner()
    pipeline = _pipeline(runner)
    engine = _engine(tmp_path, runner, resume=False)
    asyncio.run(engine._execute_phase(
        _phase(), _module(), tmp_path, pipeline, engine.pipe_def, phase_idx=0,
    ))
    runner2 = _Runner()
    engine2 = _engine(tmp_path, runner2, resume=False)
    asyncio.run(engine2._execute_phase(
        _phase(), _module(), tmp_path, _pipeline(runner2), engine2.pipe_def, phase_idx=0,
    ))
    assert runner2.calls == 1  # 老老实实重跑了


def test_failed_phase_records_failed_snapshot_then_reruns_on_resume(tmp_path):
    """全部重试耗尽 → failed 快照; resume 不跳过 failed 节点。"""
    bad_runner = _Runner(raw_text="这不是 JSON")
    pipeline = _pipeline(bad_runner)
    engine = _engine(tmp_path, bad_runner, resume=True)

    # retry 退避 2s/4s 真睡会拖慢测试, 临时替换为立即返回
    import framework.phase_engine as pe
    original_sleep = pe.asyncio.sleep

    async def fast_sleep(_seconds):
        return None

    pe.asyncio.sleep = fast_sleep
    try:
        result = asyncio.run(engine._execute_phase(
            _phase(), _module(), tmp_path, pipeline, engine.pipe_def, phase_idx=0,
        ))
    finally:
        pe.asyncio.sleep = original_sleep

    assert result is None
    snap = SnapshotStore(tmp_path).get("phase/M1/phase_A")
    assert snap["status"] == STATUS_FAILED
    assert snap["error"] == "all retries exhausted without valid evidence"

    # failed 节点不跳过: 好的 runner 接手能重跑成功
    good_runner = _Runner()
    engine2 = _engine(tmp_path, good_runner, resume=True)
    evidence = asyncio.run(engine2._execute_phase(
        _phase(), _module(), tmp_path, _pipeline(good_runner), engine2.pipe_def, phase_idx=0,
    ))
    assert good_runner.calls == 1
    assert evidence["clauses"][0]["clauseId"] == "6.1-1"


def test_upstream_pool_change_invalidates_snapshot(tmp_path):
    """上游 pool 值变了 → 输入摘要不等 → 重跑 (输入变了旧结果不可信)。"""
    runner = _Runner()
    engine = _engine(tmp_path, runner, resume=True)
    asyncio.run(engine._execute_phase(
        _phase(), _module(), tmp_path, _pipeline(runner), engine.pipe_def, phase_idx=0,
    ))

    # 模拟上游写入新的公开数据
    pool = ContextPool(tmp_path)
    pool.put("upstream_findings", {"critical": 2}, Scope.PUBLIC, "M0", "concept")

    fresh_runner = _Runner()
    engine2 = _engine(tmp_path, fresh_runner, resume=True)
    evidence = asyncio.run(engine2._execute_phase(
        _phase(), _module(), tmp_path, _pipeline(fresh_runner), engine2.pipe_def, phase_idx=0,
    ))
    assert fresh_runner.calls == 1  # 输入变了 → 重跑
    assert evidence is not None
