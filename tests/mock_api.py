"""Mock Anthropic API 客户端 — 不消耗真实 API Token。

用于本地开发和测试。行为:
- mock_work_agent: 用 fixture evidence 填充并写入文件
- mock_audit_agent: 读 evidence 文件，运行 L1 风格检查，生成审计结果
"""

import json
import re
import shutil
import uuid
from pathlib import Path
from typing import Optional


def _classify_agent_type(system: str, task: str) -> str:
    """判定 Agent 类型: "audit" | "work"。

    判定只基于 task 全文 + system 的 persona 头部（前 300 字符）。

    为什么不能全文匹配 system:
      shared_knowledge 把 work 与 audit 的参考文档合并喂给所有 agent
      （registry.py: shared_knowledge = get_work_shared_knowledge() + get_audit_shared_knowledge()），
      审计文档含"审计"字样，会污染 work agent 的 system prompt。
      裸匹配 "audit" 子串会把 work persona 的 `meta.status = "pending_audit"`
      也判成审计 → 返回审计结果冒充 evidence。

    task 由不同代码路径构造，信号可靠:
      Work task (phase engine / _run_work_with_retry):
          "执行 X 检测" / "请测试 X 模块以下条款" — 不含"审计"
      Audit task (L2AuditGate.run_audit / cross-module):
          "审计模块 M1 的 evidence JSON" / "执行 Round 2 跨模块一致性审计" — 含"审计"

    system[:300] 只覆盖 persona 角色标题：
      work persona 头部无审计词，audit persona 头部为"认证检测报告审计专家"。
    """
    for text in (task, system[:300]):
        if "审计" in text or "审查" in text:
            return "audit"
        low = text.lower()
        if "audit" in low or "auditor" in low:
            return "audit"
    return "work"


def _extract_clause_ids(task: str) -> list[str]:
    """从 task 文本中提取条款 ID 列表。

    仅扫描"条款范围"或"以下条款"所在行，取该行冒号后的逗号/空格分隔项。
    避免扫描到 clause recipe 文本（recipe 也会列出条款，会导致重复/污染）。
    """
    for line in task.splitlines():
        m = re.search(r"条款范围[:：]\s*(.*)", line) or re.search(r"以下条款[:：]\s*(.*)", line)
        if m:
            raw = m.group(1)
            ids = []
            for p in re.split(r"[,，、\s]+", raw):
                p = p.strip().strip("。；;")
                if re.match(r"^[A-Za-z0-9][A-Za-z0-9\-\.]*$", p):
                    ids.append(p)
            return ids
    return []


class MockMessage:
    """模拟 Anthropic API 返回的 Message 对象"""

    class _Usage:
        def __init__(self):
            self.input_tokens = 500
            self.output_tokens = 300
            self.cache_read_input_tokens = 0
            self.cache_creation_input_tokens = 0

    class _Content:
        def __init__(self, text: str):
            self.type = "text"
            self.text = text

    def __init__(self, text: str):
        self.content = [self._Content(text)]
        self.usage = self._Usage()


class MockAPIClient:
    """Mock Anthropic API 客户端。

    不发送网络请求。用本地 fixture 数据和静态响应模拟 Agent 行为。

    用法:
        client = MockAPIClient(fixtures_dir=Path("tests/fixtures"))
        result = await client.messages.create(
            model="claude-sonnet-5",
            system="你是 ETSI 检测员...",
            messages=[{"role": "user", "content": "执行 M1 检测..."}],
        )
    """

    def __init__(self, fixtures_dir: Path):
        self.fixtures_dir = Path(fixtures_dir)
        self.call_log: list[dict] = []

    class messages:
        """模拟 anthropic.messages.create()"""

        _client = None  # 回引用到 MockAPIClient 实例

        @classmethod
        async def create(cls, **kwargs) -> MockMessage:
            client = cls._client
            client.call_log.append({
                "model": kwargs.get("model", "unknown"),
                "system_len": len(kwargs.get("system", "")),
                "task": kwargs.get("messages", [{}])[0].get("content", "")[:100],
                "timestamp": str(__import__("datetime").datetime.now()),
            })

            system = kwargs.get("system", "")
            task = kwargs.get("messages", [{}])[0].get("content", "")

            # 判断 Agent 类型 (支持中英文关键词)
            #
            # 注意: 不能裸匹配 "audit" 子串 — work-agent persona 里
            # `meta.status = "pending_audit"` 也含 "audit"，会把 Work Agent
            # 误判成 Audit Agent，导致 mock 返回审计结果冒充 evidence。
            is_audit = _classify_agent_type(system, task) == "audit"
            if is_audit:
                return cls._handle_audit(kwargs, client)
            else:
                return cls._handle_work(kwargs, client)

        @classmethod
        def _handle_work(cls, kwargs, client) -> MockMessage:
            """模拟 Work Agent：生成覆盖 task 条款范围的全部条款 evidence。

            PhaseEngine 合并时会用 module.clauses 对账
            （_merge_phase_evidences: totalExpected=len(module.clauses)），
            所以 mock 必须按 task 的"条款范围"生成全量条款，否则 L1 闸门
            报"条款数不对" → 整个 M1_M5 阶段无限重跑。
            """
            task = kwargs.get("messages", [{}])[0].get("content", "")

            # 尝试从 task 中提取模块 ID
            module_id = "M1"
            for mid in ["M0", "M1", "M2", "M3", "M4", "M5"]:
                if mid in task:
                    module_id = mid
                    break

            # 加载 sample evidence 作为模板
            sample_path = client.fixtures_dir / "sample_evidence.json"
            if sample_path.exists():
                evidence = json.loads(sample_path.read_text(encoding="utf-8"))
                evidence["meta"]["moduleId"] = module_id
            else:
                evidence = {
                    "meta": {"moduleId": module_id, "status": "pending_audit", "retryCount": 0},
                    "self_check": {"total_expected": 1, "actual_in_json": 1, "missing_clauses": [], "has_errors": False, "error_details": []},
                    "execution_trace": [{"phase": "work", "round_number": 1, "clause_ids": ["5.6-1"], "action": "mock scan", "outcome": "mock success"}],
                    "clauses": [],
                }

            # 按 task 条款范围重新生成 clauses + self_check
            clause_ids = _extract_clause_ids(task)
            sample_clauses = {
                c.get("clause_id", c.get("clauseId", "")): c
                for c in evidence.get("clauses", [])
            }
            clauses = []
            for cid in clause_ids:
                base = sample_clauses.get(cid)
                if base:
                    clause = dict(base)
                else:
                    clause = {
                        "clause_id": cid,
                        "provision_text": f"{cid} (mock provision)",
                        "ics_status": "M",
                        "ics_support": "Y",
                        "ics_detail": "mock detail",
                        "verdict": "PASS",
                        "reason": f"Mock evidence: 模拟检测 {cid} 通过",
                        "evidence": [{
                            "type": "mock",
                            "level": "L2",
                            "description": f"mock scan for {cid}",
                        }],
                    }
                clauses.append(clause)

            if clause_ids:
                evidence["clauses"] = clauses
                evidence["self_check"] = {
                    "total_expected": len(clause_ids),
                    "actual_in_json": len(clauses),
                    "missing_clauses": [],
                    "has_errors": False,
                    "error_details": [],
                }
                # 兼容 camelCase 格式
                evidence["selfCheck"] = {
                    "totalExpected": len(clause_ids),
                    "actualInJson": len(clauses),
                    "missingClauses": [],
                    "hasErrors": False,
                    "errorDetails": [],
                }
                # 补一条 work 轨迹（EvidenceManifest 要求非空）
                if not evidence.get("execution_trace"):
                    evidence["execution_trace"] = [{
                        "phase": "work", "round_number": 1,
                        "clause_ids": clause_ids,
                        "action": "mock scan",
                        "tool": "mock",
                        "outcome": "mock success",
                    }]

            return MockMessage(json.dumps(evidence, indent=2, ensure_ascii=False))

        @classmethod
        def _handle_audit(cls, kwargs, client) -> MockMessage:
            """模拟 Audit Agent：返回符合 AuditResult 嵌套 schema 的 ACCEPT 结果。

            旧 sample_audit.json 是扁平结构（顶层 verdict），
            AuditResult 要求嵌套 audit{} 字段 → 解析失败会回退 FLAGGED，
            导致管线永远拿不到 ACCEPT。这里直接产出 schema 合规的嵌套结构。
            """
            task = kwargs.get("messages", [{}])[0].get("content", "")

            # 从 task 提取模块 ID（审计 task 格式: "审计模块 M1 的 evidence JSON"）
            module_id = "M1"
            for mid in ["M0", "M1", "M2", "M3", "M4", "M5"]:
                if mid in task:
                    module_id = mid
                    break

            audit = {
                "audit": {
                    "moduleId": module_id,
                    "round": 1,
                    "retryCount": 0,
                    "auditedAt": "2026-08-06T15:35:00Z",
                    "verdict": "ACCEPT",
                    "summary": "Mock audit: all clauses triangulation-consistent, verdicts accurate",
                },
                "findings": [],
                "retryInstruction": None,
                "harnessReport": {
                    "executionTraceComplete": True,
                    "totalRoundsOk": True,
                    "preflightStepsPresent": True,
                    "allClausesTraced": True,
                    "roundsWithinBudget": True,
                    "issues": [],
                },
                "crossModuleIssues": [],
            }

            return MockMessage(json.dumps(audit, indent=2, ensure_ascii=False))


def bind_mock_client(client: MockAPIClient):
    """绑定 MockAPIClient 到 messages 内部类，使 API 调用路径工作"""
    MockAPIClient.messages._client = client
    return client
