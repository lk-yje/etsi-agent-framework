# ETSI Pipeline Agent 框架 — 架构设计文档

> **状态**: 设计阶段 | **作者**: 架构设计 | **日期**: 2026-08-06
>
> 本文档描述从"纯 Prompt Engineering"向"工程化 Agent 框架"迁移的完整架构设计。
> 设计目标：在保留 AI 审计智能性的前提下，通过物理隔离解决 Goodhart's Law 污染问题。

---

## 目录

1. [背景与动机](#1-背景与动机)
2. [设计决策记录 (ADR)](#2-设计决策记录-adr)
3. [核心抽象层](#3-核心抽象层)
4. [数据合约 (Pydantic Models)](#4-数据合约-pydantic-models)
5. [Agent Runner — 物理隔离核心](#5-agent-runner--物理隔离核心)
6. [管线状态机](#6-管线状态机)
7. [文件总线 (FileBus)](#7-文件总线-filebus)
8. [三个 Agent 的隔离设计](#8-三个-agent-的隔离设计)
9. [闸门系统 — L1 确定性 + L2 AI 离线](#9-闸门系统--l1-确定性--l2-ai-离线)
10. [技能注册表](#10-技能注册表)
11. [项目结构](#11-项目结构)
12. [可观测性](#12-可观测性)
13. [测试策略](#13-测试策略)
14. [隔离保证机制](#14-隔离保证机制)
15. [ETSI 管线具体定义](#15-etsi-管线具体定义)
16. [实施路线图](#16-实施路线图)

---

## 1. 背景与动机

### 1.1 当前架构的问题

当前系统基于 Claude Code 的 Skill 机制运行，所有 agent 共享同一上下文空间：

```
现状:
┌──────────────────────────────────────────────────┐
│              共享上下文 (Claude Code 会话)         │
│                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │
│  │ CLAUDE.md   │  │ etsi-ts     │  │ etsi-     │ │
│  │ 红队渗透     │  │ 103701-     │  │ report-   │ │
│  │ persona     │  │ report      │  │ auditor   │ │
│  │ (300行)     │  │ (287行)     │  │ (448行)    │ │
│  └─────────────┘  └─────────────┘  └───────────┘ │
│                        │               │          │
│                        ▼               ▼          │
│              工作 Agent 知道         审计 Agent    │
│              审计的存在和标准         和工作 Agent  │
│              ↓                      共享上下文     │
│          Goodhart's Law                          │
│          "做测试" → "迎合审计"                     │
└──────────────────────────────────────────────────┘
```

**问题根因（代码证据）：**

1. 工作 skill `etsi-ts103701-report/` 内嵌了审计文件：
   - `agents/etsi-auditor.md` — 审计 agent 定义寄生在工作 skill 内
   - `references/audit-agent-prompt.md` — 审计调用模板在工作 skill 内
   - `references/audit-output-schema.json` — 审计输出格式在工作 skill 内

2. 工作 agent 的 prompt 中显式告知审计的存在 (`module-split.md` L449-482)：
   ```
   "以上约束的履行情况将记录在 executionTrace 中，由审计 Agent (etsi-report-auditor)
    核实。Harness 违规 = REJECT，不计入 retry 宽容次数。"
   ```

3. 审计是管线内的阻塞闸门 (`SKILL.md` L102-104)：
   ```
   "🚪 M0 必须审计 ACCEPT，拿到 .audit_M0_ACCEPTED 令牌，方可派发 M1-M5。"
   ```

4. 打回机制让工作 agent 学习审计偏好 (`module-split.md` L138-163)：
   - 审计 REJECT → 注入审计备忘录 → 同一个 agent 重做 → agent 学会迎合

**结论：在共享上下文的条件下，"审计独立性"是逻辑矛盾。Prompt Engineering 已触及天花板。**

### 1.2 设计目标

| 目标 | 描述 |
|------|------|
| **物理隔离** | Work Agent 和 Audit Agent 的 system prompt 绝不共享任何字节 |
| **保留智能审计** | 不退化到纯机械检查，AI 审计能力完整保留 |
| **保留打回机制** | 审计发现问题 → 修正 → 再审计的闭环保留 |
| **上下文精简** | 每个 Agent 只加载它需要的知识，不背全量 skill |
| **可测试** | 框架行为可 mock 测试，管线逻辑可离线验证 |
| **可恢复** | 管线状态持久化，支持断点续跑 |
| **可扩展** | 新管线 = 写 pipeline.py + registry.py，框架不动 |

---

## 2. 设计决策记录 (ADR)

### ADR-001: 文件系统作为 Agent 间通信总线

| 选项 | 判定 |
|------|------|
| 共享上下文（现状） | ❌ Goodhart's Law 无法解决 |
| 内存消息队列（Redis/RabbitMQ） | ❌ 引入基础设施依赖，单机过重 |
| gRPC/HTTP 直连 | ❌ Agent 需要知道彼此端点，耦合 |
| **文件系统** | ✅ 免费持久化、可回放审计、零耦合、自带检查点 |

**理由：** Agent A 不需要知道 Agent B 的存在，只需要知道"往哪个路径写什么格式的文件"。
文件系统天然满足"离线审计"——审计 Agent 只读已落盘的文件，不参与管线运行时。

**关键约束：**
- 写入是原子的（先写临时文件，再 rename）
- 读取方轮询时用 `[ -s file ]` 检查文件非空
- 所有文件格式由 Pydantic model → JSON Schema 定义

### ADR-002: 每个 Agent 调用是独立 API 请求，非会话续接

| 选项 | 判定 |
|------|------|
| Claude Code Agent 子代理（现状） | ❌ 共享 CLAUDE.md persona，无法物理隔离 |
| 单一长会话 + 角色切换 | ❌ 上下文污染不可逆 |
| **独立 Anthropic API 调用** | ✅ system prompt 完全可控，隔离可验证 |

**理由：** 共享会话 = 共享上下文 = 污染。独立 API 请求确保每个 Agent 的 system prompt
完全由 `PromptCompiler` 从配置编译，不继承任何会话历史。

**代价与缓解：**
- 多一次 API 调用（毫秒级延迟增加，可接受）
- 不能利用 Claude Code 的权限管理 → 需自建工具白名单机制
- 不能利用 Claude Code 的 UI → 需自建进度展示

### ADR-003: L1 验证是确定性 Python，L2 审计是独立 AI Agent

| 检查层 | 执行者 | 时机 | 耗时 | 可阻塞管线 |
|--------|--------|------|------|:----------:|
| L1 结构校验 | `validate_evidence.py` | 文件落盘后立即 | < 1s | ✅ 是 |
| L2 语义审计 | Audit Agent（独立 API 调用） | 离线，人工触发或定时 | 30s-5min | ❌ 否 |

**L1 检查项（确定性，非 AI）：**
- JSON 可解析
- 条款总数对账（`totalExpected` vs `actualInJson`）
- 缺失条款检测
- FAIL 缺少 `expectedBehavior`
- `PENDING_MANUAL` 缺少 `manualSteps`
- `ICS=N/A` 缺少 `conceptReason`
- Evidence level L4/L5 检测
- `executionTrace` 为空检测
- 配套文件存在性

**L2 检查项（需要 AI 判断）：**
- 裁决 vs 标准结论条件的精确匹配
- escape_clause 是否正确使用
- "所有"条件是否被完整覆盖
- ICS/IXIT 矛盾是否正确处理
- 继承链一致性
- 证据外推过度检测

### ADR-004: 提示词即代码 (Prompt as Code)

**原则：**
- 所有 system prompt 从 markdown 文件编译，不硬编码字符串
- 编译时强制执行隔离检查（`forbidden_paths` 扫描）
- Prompt 模板参数化，变量由 `PromptCompiler` 注入
- Prompt 文件版本控制，变更可追溯

**反模式（禁止）：**
- 运行时字符串拼接
- Agent A 的 prompt 里出现 Agent B 的名字或职责
- 在 task 描述中告知 Agent "你正在被审计"

---

## 3. 核心抽象层

```
┌──────────────────────────────────────────────────────────────┐
│                     Application Layer                         │
│                                                               │
│  pipelines/etsi/  ──  ETSI 管线的阶段、模块、闸门定义        │
│  (唯一需要"写业务逻辑"的地方)                                  │
│                                                               │
│  未来可扩展: pipelines/iso27001/, pipelines/soc2/ 等          │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                      Framework Layer                          │
│                                                               │
│  ┌─────────┐  ┌──────────┐  ┌───────────┐  ┌────────────┐  │
│  │Pipeline │  │  Agent   │  │ FileBus   │  │GateChecker │  │
│  │ 状态机   │  │ Runner   │  │ 文件读写   │  │ L1+L2调度   │  │
│  │ 阶段跃迁 │  │ 独立API  │  │ 轮询/等待  │  │            │  │
│  │ 断点续跑 │  │ 调用     │  │ 令牌管理   │  │            │  │
│  └─────────┘  └──────────┘  └───────────┘  └────────────┘  │
│                                                               │
│  ┌──────────┐  ┌───────────┐  ┌────────────┐                │
│  │ Prompt   │  │ Telemetry │  │ RetryPolicy│                │
│  │ Compiler │  │ 追踪/日志  │  │ 退避/熔断   │                │
│  │ 编译时   │  │ token统计  │  │            │                │
│  │ 隔离检查 │  │ trace ID  │  │            │                │
│  └──────────┘  └───────────┘  └────────────┘                │
│                                                               │
│  ┌──────────┐                                                │
│  │ Registry │  Agent/Skill 注册表 + 依赖关系 + 隔离规则       │
│  └──────────┘                                                │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                     Infrastructure Layer                      │
│                                                               │
│  Anthropic SDK  │  Pydantic Models  │  Python asyncio        │
│  (API 调用)     │  (合约定义+验证)   │  (Agent 并发)          │
│                                                               │
│  structlog      │  pytest          │  watchdog              │
│  (结构化日志)    │  (测试框架)       │  (文件变更监听，可选)   │
└──────────────────────────────────────────────────────────────┘
```

### 框架层与管线层的职责边界

```
Framework/ (通用，不包含 ETSI 业务逻辑)
├── 知道"什么是 Agent"、"怎么创建和运行 Agent"
├── 知道"什么是 Pipeline"、"怎么管理阶段跃迁"
├── 知道"什么是 FileBus"、"怎么原子读写文件"
├── 知道"什么是 Gate"、"怎么跑 L1 检查+调度 L2"
├── 不知道 ETSI 条款、模块划分、ICS/IXIT 格式

Pipelines/etsi/ (ETSI 业务逻辑)
├── 知道 M0-M5 模块划分、条款分配
├── 知道每个模块需要加载哪些弹药库
├── 知道审计判断细则（仅注入 Audit Agent）
├── 知道报告模板格式
├── 不知道 HTTP 怎么发、Agent API 怎么调
```

---

## 4. 数据合约 (Pydantic Models)

> **合约优先原则**: 先定义数据结构和验证规则，再写行为逻辑。
> 所有 Agent 间通信的数据格式由 Pydantic models 定义，自动生成 JSON Schema。

### 4.1 管线状态合约

```python
# contracts/pipeline.py

from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime
from typing import Optional

class StageStatus(str, Enum):
    """管线阶段状态"""
    PENDING = "pending"           # 尚未开始
    IN_PROGRESS = "in_progress"   # 执行中
    AWAITING_GATE = "awaiting_gate"  # 已完成，等待闸门
    PASSED = "passed"             # 闸门通过
    FAILED = "failed"             # 闸门不通过
    SKIPPED = "skipped"           # 条件不满足，跳过

class ModuleVerdict(str, Enum):
    """审计裁决"""
    ACCEPT = "ACCEPT"     # 通过，证据充分
    REJECT = "REJECT"     # 不通过，需修正
    FLAGGED = "FLAGGED"   # 多次修正仍未通过，交人类裁定

class PipelineState(str, Enum):
    """管线顶层状态"""
    INIT = "init"
    ENV_CHECK = "env_check"
    ICS_PARSE = "ics_parse"
    M0_ICS_VALIDATION = "m0"
    TRAFFIC_COLLECT = "traffic"
    M1_M5_PARALLEL = "m1_m5"
    AUDIT_QUEUE = "audit"           # 离线审计
    CROSS_MODULE_AUDIT = "cross"    # 跨模块审计
    REPORT_GENERATION = "report"
    DONE = "done"
    FAILED = "failed"

class PipelineSnapshot(BaseModel):
    """管线状态快照（持久化到 pipeline_state.json）"""
    pipeline_id: str
    current_state: PipelineState
    stage_statuses: dict[str, StageStatus]  # stage_name → status
    started_at: datetime
    updated_at: datetime
    workspace_path: str
    completed_stages: list[str] = []
    failed_stages: list[str] = []
    errors: list[str] = []
```

### 4.2 工作 Agent 产出合约

```python
# contracts/evidence.py

from pydantic import BaseModel, Field, field_validator
from typing import Optional

class EvidenceLevel(str, Enum):
    """证据分级"""
    L1 = "L1"  # 完整可复现：命令+参数+完整输出+frame编号
    L2 = "L2"  # 完整，缺工具版本号
    L3 = "L3"  # 部分覆盖：有结论但缺中间步骤
    L4 = "L4"  # 仅文档引用，无实测证据
    L5 = "L5"  # 无证据，仅声称

class EvidenceItem(BaseModel):
    """单条证据"""
    type: str = Field(description="证据类型: nmap|tshark|burp|curl|ixit|playwright|python")
    path: Optional[str] = Field(None, description="证据文件路径（工作区内）")
    level: EvidenceLevel = Field(description="证据分级 L1-L5")
    description: str = Field(
        description="证据描述，必须含 frame 编号/Burp 序号/命令+参数，第三者可直接索引"
    )
    expected_vs_actual: Optional[str] = Field(
        None, description="预期 vs 实际对照（FAIL 时必填）"
    )

    @field_validator("description")
    @classmethod
    def description_not_empty(cls, v: str) -> str:
        assert len(v.strip()) >= 10, "证据描述至少 10 字符，包含可索引信息"
        return v

class ClauseResult(BaseModel):
    """单条款的测试结果"""
    clause_id: str = Field(description="条款 ID，如 5.6-1")
    provision_text: str = Field(description="条款原文")
    ics_status: str = Field(description="ICS 状态: M|R|M C(...)|R C(...)")
    ics_support: str = Field(description="ICS 声明: Y|N|N/A")
    ics_detail: Optional[str] = Field(None, description="供应商的 Detail/Justification")
    verdict: str = Field(description="综合裁决: PASS|FAIL|NA|INCONCLUSIVE|PENDING_MANUAL")
    reason: str = Field(description="完整推理链：概念分析 + 功能验证")
    expected_behavior: Optional[str] = Field(None, description="预期行为（FAIL 时必填）")
    actual_behavior: Optional[str] = Field(None, description="实际行为（FAIL 时必填）")
    evidence: list[EvidenceItem] = Field(default_factory=list)
    ixit_references: list[str] = Field(default_factory=list, description="引用的 IXIT 表名")
    tags: list[str] = Field(default_factory=list, description="标签: escape-clause|all-conditions|inherited")
    warnings: list[str] = Field(default_factory=list)
    manual_steps: Optional[str] = Field(None, description="手工测试步骤（PENDING_MANUAL 时必填）")
    retry_history: list[dict] = Field(default_factory=list)

class ExecutionStep(BaseModel):
    """执行轨迹中的单步"""
    phase: str = Field(description="preflight | work | delivery")
    round_number: int
    clause_ids: list[str] = Field(description="本步涉及的条款")
    action: str = Field(description="执行的动作描述")
    tool: Optional[str] = Field(None, description="使用的工具")
    outcome: str = Field(description="结果摘要")

class SelfCheck(BaseModel):
    """Agent 自检结果"""
    total_expected: int = Field(description="应覆盖的条款总数")
    actual_in_json: int = Field(description="JSON 中实际条目数")
    missing_clauses: list[str] = Field(default_factory=list)
    has_errors: bool = False
    error_details: list[str] = Field(default_factory=list)

class EvidenceManifest(BaseModel):
    """工作 Agent 产出的完整 evidence JSON"""
    meta: dict = Field(description="元数据: moduleId, status, retryCount, timestamp")
    self_check: SelfCheck
    execution_trace: list[ExecutionStep] = Field(
        default_factory=list, description="完整执行轨迹，每步含条款+工具+结果"
    )
    clauses: list[ClauseResult] = Field(description="逐条款测试结果")

    @field_validator("execution_trace")
    @classmethod
    def trace_not_empty(cls, v: list) -> list:
        assert len(v) > 0, "execution_trace 不能为空（无轨迹 = 无法审计过程）"
        return v
```

### 4.3 审计 Agent 产出合约

```python
# contracts/audit.py

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional

class TriangulationResult(BaseModel):
    """三角对照结果"""
    standard_vs_ixit: str = Field(description="标准 vs IXIT: OK | MISMATCH: <具体描述>")
    standard_vs_evidence: str = Field(description="标准 vs 证据")
    ixit_vs_evidence: str = Field(description="IXIT vs 证据")

class AuditFinding(BaseModel):
    """单条审计发现"""
    clause_id: str
    severity: str = Field(description="CRITICAL | HIGH | MEDIUM | LOW")
    category: str = Field(
        description="evidence_insufficient | verdict_error | escape_clause_missed | "
                    "all_conditions_relaxed | ics_ixit_misjudged | inheritance_broken | "
                    "evidence_overreach | na_circular | harness_violation"
    )
    triangulation: TriangulationResult
    description: str = Field(description="问题一句话描述")
    fix: str = Field(description="修正建议")
    affected_fields: list[str] = Field(description="涉及的 JSON 字段路径")

class RetryInstruction(BaseModel):
    """修正任务指令（可注入 Fix Agent prompt）"""
    target_clause_ids: list[str]
    memo: str = Field(description="可直接注入修正 Agent prompt 的任务描述")

class HarnessReport(BaseModel):
    """Harness 合规报告"""
    execution_trace_complete: bool
    total_rounds_ok: bool
    preflight_steps_present: bool
    all_clauses_traced: bool
    rounds_within_budget: bool
    issues: list[str] = Field(default_factory=list)

class AuditResult(BaseModel):
    """审计 Agent 的完整输出"""
    module_id: str
    round_number: int = Field(description="1=单模块, 2=跨模块")
    retry_count: int
    audited_at: datetime = Field(default_factory=datetime.now)
    verdict: str = Field(description="ACCEPT | REJECT | FLAGGED")
    summary: str = Field(description="一句话总结")
    findings: list[AuditFinding] = Field(default_factory=list)
    retry_instruction: Optional[RetryInstruction] = None
    harness_report: Optional[HarnessReport] = None
    cross_module_issues: list[dict] = Field(default_factory=list)  # Round 2 专用
```

### 4.4 Agent 运行结果合约

```python
# contracts/agent_result.py

from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class TokenUsage(BaseModel):
    """Token 用量统计"""
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

class AgentTrace(BaseModel):
    """Agent 执行完整 trace"""
    trace_id: str
    agent_id: str
    agent_type: str  # work | audit | fix
    started_at: datetime
    ended_at: datetime
    duration_ms: int
    model: str
    token_usage: TokenUsage
    tool_calls_count: int = 0
    tools_used: list[str] = []
    outcome: str  # success | validation_error | api_error | timeout
    error_message: Optional[str] = None
    output_file_path: Optional[str] = None  # 产出的文件路径

class AgentResult(BaseModel):
    """Agent 运行完整结果"""
    trace: AgentTrace
    output: Optional[dict] = None  # 结构化输出（如果有 schema）
    raw_text: Optional[str] = None  # 原始文本（如果没有 schema）
```

---

## 5. Agent Runner — 物理隔离核心

### 5.1 设计原理

`AgentRunner` 是框架的心脏。每创建一个 Agent，保证：
1. System prompt 仅从 `AgentConfig` 编译，不继承任何会话上下文
2. API 调用与所有其他 Agent 完全隔离
3. 编译时强制执行 `forbidden_paths` 扫描
4. 返回结构化结果 + 完整 trace

### 5.2 核心类设计

```python
# framework/agent_runner.py

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable
import asyncio

@dataclass(frozen=True)  # 不可变 — 创建后无法修改，防止意外污染
class AgentConfig:
    """
    每个 Agent 实例的不可变配置。
    
    这是隔离保证的核心——一个 AgentConfig 定义一个 Agent 的完整
    上下文边界。创建后不可修改，防止运行时意外注入。
    """
    agent_id: str                         # 唯一 ID，用于追踪
    agent_type: str                       # "work" | "audit" | "fix"
    
    # Prompt 编译材料
    persona_path: Path                    # 角色定义 markdown
    knowledge_paths: tuple[Path, ...]     # 知识库文件（不可变元组）
    tool_manifest: tuple[str, ...]        # 允许的工具列表（不可变元组）
    
    # ⚠️ 隔离约束：这些模式绝对不能出现在编译后的 system prompt 中
    forbidden_patterns: tuple[str, ...] = field(default_factory=tuple)
    
    # API 配置
    model: str = "claude-sonnet-5"
    max_tokens: int = 32000
    temperature: float = 0.1
    
    def __post_init__(self):
        """构造后立即验证配置合法性"""
        assert self.persona_path.exists(), f"Persona 文件不存在: {self.persona_path}"
        for kp in self.knowledge_paths:
            assert kp.exists(), f"知识库文件不存在: {kp}"


class IsolationViolation(Exception):
    """编译时隔离违规 — 拒绝创建 Agent"""
    def __init__(self, agent_id: str, pattern: str, source_file: str):
        self.agent_id = agent_id
        self.pattern = pattern
        self.source_file = source_file
        super().__init__(
            f"隔离违规: Agent '{agent_id}' 的 prompt 中包含禁止模式 "
            f"'{pattern}' (来源: {source_file})。"
            f"这会导致 Goodhart's Law 污染。"
        )


class PromptCompiler:
    """
    Agent system prompt 编译器。
    
    职责:
    1. 从 AgentConfig 编译完整的 system prompt 字符串
    2. 编译时强制执行 forbidden_patterns 扫描
    3. 注入任务上下文和输出合约
    4. 返回编译后的 prompt（一次性字符串，调用后不保留）
    """
    
    # 默认禁止模式（所有非 Audit Agent 强制应用）
    DEFAULT_FORBIDDEN = (
        "审计 Agent",
        "审计 agent",
        "etsi-report-auditor",
        "Harness 违规",
        "Harness违规",
        "audit-checklist",
        "common-errors",
        "evidence-standards",
        "audit-result",
        "审计结果",
        "审计备忘录",
        "retryInstruction",
    )
    
    @classmethod
    def compile(
        cls,
        config: AgentConfig,
        task_context: dict,
    ) -> str:
        """
        编译 system prompt。
        
        Args:
            config: Agent 配置（不可变）
            task_context: 任务上下文（task, workspace, inputs, output_schema）
        
        Returns:
            编译后的 system prompt 字符串
        
        Raises:
            IsolationViolation: 编译时发现禁止模式
        """
        # Step 1: 编译时隔离检查
        cls._enforce_isolation(config)
        
        # Step 2: 构建 prompt
        parts = []
        
        # 2a. 角色定义
        persona = config.persona_path.read_text(encoding="utf-8")
        parts.append(persona)
        
        # 2b. 知识库（按需注入，不全量）
        for kp in config.knowledge_paths:
            content = kp.read_text(encoding="utf-8")
            parts.append(f"\n---\n## 参考: {kp.stem}\n{content}")
        
        # 2c. 工具清单
        if config.tool_manifest:
            parts.append(f"\n## 可用工具\n{', '.join(config.tool_manifest)}")
        
        # 2d. 当前任务
        parts.append(f"\n---\n## 当前任务\n{task_context['task']}")
        parts.append(f"\n### 工作区\n{task_context['workspace']}")
        
        if task_context.get("inputs"):
            parts.append(f"\n### 输入文件")
            for inp in task_context["inputs"]:
                parts.append(f"- {inp}")
        
        # 2e. 输出合约
        if task_context.get("output_schema"):
            parts.append(f"\n## 输出格式要求\n{task_context['output_schema']}")
        
        return "\n".join(parts)
    
    @classmethod
    def _enforce_isolation(cls, config: AgentConfig):
        """
        编译时隔离检查。
        
        扫所有注入到 system prompt 的文件内容，
        检查是否包含 forbidden_patterns 中的任何模式。
        
        违规 → 抛 IsolationViolation，拒绝创建 Agent。
        """
        # 收集所有将注入 prompt 的文本
        all_content = config.persona_path.read_text(encoding="utf-8")
        for kp in config.knowledge_paths:
            all_content += "\n" + kp.read_text(encoding="utf-8")
        
        # 应用默认禁止模式 + 自定义禁止模式
        all_forbidden = set(cls.DEFAULT_FORBIDDEN) | set(config.forbidden_patterns)
        
        # 逐模式扫描
        for pattern in all_forbidden:
            if pattern.lower() in all_content.lower():
                # 定位来源文件
                source = cls._find_pattern_source(pattern, config)
                raise IsolationViolation(config.agent_id, pattern, source)
    
    @classmethod
    def _find_pattern_source(cls, pattern: str, config: AgentConfig) -> str:
        """定位禁止模式的来源文件"""
        for kp in [config.persona_path] + list(config.knowledge_paths):
            content = kp.read_text(encoding="utf-8")
            if pattern.lower() in content.lower():
                return str(kp)
        return "unknown"


class AgentRunner:
    """
    Agent 运行器。
    
    每个 Agent 是一次独立的 Anthropic API 调用。
    不保留 Agent 之间的任何共享状态。
    
    用法:
        runner = AgentRunner(api_client, telemetry)
        result = await runner.run(work_config, task_ctx, tools=[...])
        # result 是 AgentResult，含结构化输出 + 完整 trace
    """
    
    def __init__(self, api_client, telemetry: "Telemetry"):
        self.api = api_client
        self.telemetry = telemetry
    
    async def run(
        self,
        config: AgentConfig,
        task_context: dict,
        tools: Optional[list] = None,
        output_schema: Optional[dict] = None,
    ) -> "AgentResult":
        """
        启动一个独立 Agent 调用。
        
        保证:
        1. system prompt 仅从 config 编译
        2. 编译时通过隔离检查
        3. 与所有其他 Agent 完全隔离
        4. 结构化输出自动验证（如果有 schema）
        """
        trace_id = self.telemetry.start_trace(
            agent_id=config.agent_id,
            agent_type=config.agent_type,
        )
        
        try:
            # 编译 system prompt（含隔离检查）
            system_prompt = PromptCompiler.compile(config, task_context)
            
            # 构建 API 参数
            api_params = {
                "model": config.model,
                "max_tokens": config.max_tokens,
                "temperature": config.temperature,
                "system": system_prompt,
                "messages": [{"role": "user", "content": task_context["task"]}],
            }
            
            if tools:
                api_params["tools"] = tools
            
            # 独立 API 调用
            start = asyncio.get_event_loop().time()
            response = await self.api.messages.create(**api_params)
            duration_ms = int((asyncio.get_event_loop().time() - start) * 1000)
            
            # 提取结构化输出或文本
            if output_schema and hasattr(response, "structured_output"):
                output = response.structured_output
                raw_text = None
            else:
                output = None
                raw_text = response.content[0].text
            
            trace = AgentTrace(
                trace_id=trace_id,
                agent_id=config.agent_id,
                agent_type=config.agent_type,
                started_at=...,  # 从 telemetry 取
                ended_at=...,
                duration_ms=duration_ms,
                model=config.model,
                token_usage=TokenUsage(
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                ),
                tool_calls_count=...,  # 从 response 提取
                tools_used=...,
                outcome="success",
            )
            
            result = AgentResult(trace=trace, output=output, raw_text=raw_text)
            self.telemetry.end_trace(trace_id, result)
            return result
            
        except IsolationViolation:
            raise  # 编译时隔离违规，直接上抛
        except Exception as e:
            self.telemetry.end_trace(trace_id, None, error=str(e))
            raise
```

### 5.3 使用示例

```python
# 创建 Work Agent（M1 模块）
work_config = AgentConfig(
    agent_id="M1_attack_surface_v1",
    agent_type="work",
    persona_path=Path("skills/etsi-ts103701-report/SKILL.md"),
    knowledge_paths=(
        Path("skills/etsi-ts103701-report/references/clause-reference.md"),
        Path("skills/etsi-ts103701-report/references/verdict-criteria.md"),
        # 注意：不包含任何 audit- 开头的文件
    ),
    tool_manifest=("bash", "burp_mcp", "playwright_mcp"),
    forbidden_patterns=(),  # 默认禁止模式已包含审计相关
)

task = {
    "task": "执行 M1 攻击面与端口模块的检测...",
    "workspace": "/workspace/20260806_143000/",
    "inputs": ["nmap_tcp.txt", "ixit.json"],
    "output_schema": "按 evidence-schema.json 输出 pre-M1-evidence-x0.json",
}

result = await runner.run(work_config, task, tools=[...])
```

---

## 6. 管线状态机

### 6.1 阶段跃迁图

```
                    ┌──────────┐
                    │   INIT   │
                    └────┬─────┘
                         │
                    ┌────▼─────┐
                    │ENV_CHECK │──FAIL──→ FAILED
                    └────┬─────┘
                         │ PASS
                    ┌────▼─────┐
                    │ICS_PARSE │──FAIL──→ FAILED
                    └────┬─────┘
                         │ PASS
                    ┌────▼─────┐
                    │    M0    │──FAIL──→ (retry M0)
                    └────┬─────┘
                         │ L1 PASS
                    ┌────▼─────┐
                    │ TRAFFIC  │ (等待用户操作)
                    └────┬─────┘
                         │ 用户确认
                    ┌────▼─────┐
                    │ M1_M5    │ 5 个 Work Agent 并行
                    └────┬─────┘
                         │ 全部 L1 PASS
                    ┌────▼─────┐
                    │  AUDIT   │ 离线审计队列 (不阻塞)
                    └────┬─────┘
                         │ 审计完成
                    ┌────▼─────┐
                    │  CROSS   │ 跨模块审计
                    └────┬─────┘
                         │ PASS
                    ┌────▼─────┐
                    │  REPORT  │
                    └────┬─────┘
                         │
                    ┌────▼─────┐
                    │   DONE   │
                    └──────────┘
```

### 6.2 状态机实现

```python
# framework/pipeline.py

from abc import ABC, abstractmethod
from typing import Callable, Awaitable

class StageTransition:
    """阶段跃迁定义"""
    from_state: PipelineState
    to_state: PipelineState
    gate: Optional["GateChecker"] = None  # None = 无闸门，直接跃迁
    on_failure: PipelineState = PipelineState.FAILED

class Pipeline(ABC):
    """
    管线基类 — 所有管线继承此类。
    
    提供:
    - 状态机推进
    - 闸门调度
    - 状态持久化（断点续跑）
    - 阶段 hook（before/after）
    """
    
    def __init__(self, workspace: Path, registry: "AgentRegistry"):
        self.workspace = workspace
        self.registry = registry
        self.state_file = workspace / "pipeline_state.json"
        self._state: Optional[PipelineSnapshot] = None
    
    @property
    @abstractmethod
    def stages(self) -> dict[PipelineState, "Stage"]:
        """子类定义管线的阶段集合"""
        ...
    
    @property
    @abstractmethod
    def transitions(self) -> list[StageTransition]:
        """子类定义阶段跃迁规则"""
        ...
    
    async def run(self):
        """驱动管线到完成"""
        self._load_or_init_state()
        
        while self._state.current_state not in (PipelineState.DONE, PipelineState.FAILED):
            await self._advance_one_stage()
            self._save_state()
    
    async def _advance_one_stage(self):
        """推进一个阶段"""
        current = self._state.current_state
        stage = self.stages[current]
        
        # 1. 执行阶段
        self._state.stage_statuses[current.value] = StageStatus.IN_PROGRESS
        self._save_state()
        
        try:
            await stage.execute(self.workspace, self.registry, self)
            self._state.stage_statuses[current.value] = StageStatus.AWAITING_GATE
        except Exception as e:
            self._state.errors.append(f"{current.value}: {e}")
            self._state.stage_statuses[current.value] = StageStatus.FAILED
            self._save_state()
            return
        
        # 2. 跑闸门
        transition = self._find_transition(current)
        if transition and transition.gate:
            gate_passed = await transition.gate.check(self.workspace)
            if gate_passed:
                self._state.completed_stages.append(current.value)
                self._state.current_state = transition.to_state
            else:
                self._state.stage_statuses[current.value] = StageStatus.FAILED
                self._state.current_state = transition.on_failure
        else:
            self._state.completed_stages.append(current.value)
            self._state.current_state = transition.to_state if transition else PipelineState.DONE
        
        self._save_state()
    
    def _save_state(self):
        """持久化管线状态到 JSON（支持断点续跑）"""
        self._state.updated_at = datetime.now()
        self.state_file.write_text(
            self._state.model_dump_json(indent=2), encoding="utf-8"
        )
    
    def _load_or_init_state(self):
        """从文件恢复管线状态，或创建新状态"""
        if self.state_file.exists():
            self._state = PipelineSnapshot.model_validate_json(
                self.state_file.read_text(encoding="utf-8")
            )
        else:
            self._state = PipelineSnapshot(
                pipeline_id=str(uuid.uuid4())[:8],
                current_state=PipelineState.INIT,
                stage_statuses={},
                started_at=datetime.now(),
                updated_at=datetime.now(),
                workspace_path=str(self.workspace),
            )
```

---

## 7. 文件总线 (FileBus)

### 7.1 设计理念

FileBus 是 Agent 间唯一的通信通道。Agent 不直接知道彼此的存在，
只通过"写文件到约定路径 + 等待约定路径出现文件"来协作。

### 7.2 核心设计

```python
# framework/file_bus.py

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Optional, Callable, TypeVar

T = TypeVar("T")

class FileBus:
    """
    文件总线 — Agent 间通信的唯一通道。
    
    设计保证:
    1. 写入原子化（临时文件 + rename）
    2. 读取方轮询等待文件就绪
    3. 所有路径从 workspace 派生，不跨 workspace 通信
    4. 结构化数据自动 JSON Schema 验证
    """
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
        # 子目录约定
        self.evidence_dir = workspace / "evidence"
        self.audit_dir = workspace / "audit-results"
        self.token_dir = workspace / "tokens"
        self.log_dir = workspace / "logs"
        
        for d in [self.evidence_dir, self.audit_dir, self.token_dir, self.log_dir]:
            d.mkdir(parents=True, exist_ok=True)
    
    # ===== 写入方法 =====
    
    def write_atomic(self, path: Path, content: str) -> Path:
        """
        原子写入 — 先写临时文件，再 rename。
        防止读取方读到半成品文件。
        """
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)  # 原子 rename
        return path
    
    def write_json(
        self, relative_path: str, data: dict, schema: Optional[type] = None
    ) -> Path:
        """写入 JSON 文件（含 schema 验证）"""
        if schema:
            data = schema(**data).model_dump()  # Pydantic 验证
        path = self.workspace / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        return self.write_atomic(path, json.dumps(data, indent=2, ensure_ascii=False))
    
    def write_evidence(self, module_id: str, evidence: EvidenceManifest) -> Path:
        """写入模块 evidence JSON"""
        return self.write_json(
            f"evidence/pre-{module_id}-evidence.json",
            evidence.model_dump(),
            schema=EvidenceManifest,
        )
    
    def write_audit_result(self, module_id: str, result: AuditResult) -> Path:
        """写入审计结果 JSON"""
        return self.write_json(
            f"audit-results/audit-result_{module_id}.json",
            result.model_dump(),
            schema=AuditResult,
        )
    
    def touch_token(self, token_name: str) -> Path:
        """发行通行令牌（空文件，存在 = 通过）"""
        token = self.token_dir / token_name
        token.touch()
        return token
    
    # ===== 读取方法 =====
    
    def read_json(self, relative_path: str, schema: Optional[type] = None) -> dict:
        """读取 JSON 文件（含 schema 验证）"""
        path = self.workspace / relative_path
        data = json.loads(path.read_text(encoding="utf-8"))
        if schema:
            return schema(**data).model_dump()
        return data
    
    async def wait_for_file(
        self,
        relative_path: str,
        timeout_seconds: int = 300,
        poll_interval: float = 5.0,
    ) -> Optional[Path]:
        """
        轮询等待文件就绪（存在且非空）。
        
        用于 Agent 间同步——一个 Agent 等待另一个 Agent 产出文件。
        超时返回 None。
        """
        path = self.workspace / relative_path
        elapsed = 0.0
        while elapsed < timeout_seconds:
            if path.exists() and path.stat().st_size > 0:
                return path
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
        return None
    
    def has_token(self, token_name: str) -> bool:
        """检查通行令牌是否存在"""
        return (self.token_dir / token_name).exists()
    
    # ===== 查询方法 =====
    
    def list_evidence_files(self) -> list[Path]:
        """列出所有 evidence JSON 文件"""
        return sorted(self.evidence_dir.glob("*.json"))
    
    def list_audit_results(self) -> list[Path]:
        """列出所有审计结果 JSON 文件"""
        return sorted(self.audit_dir.glob("*.json"))
    
    def missing_tokens(self, required: list[str]) -> list[str]:
        """返回缺失的令牌列表"""
        return [t for t in required if not self.has_token(t)]
```

---

## 8. 三个 Agent 的隔离设计

### 8.1 隔离矩阵

```
               ┌──────────────┬──────────────┬──────────────┐
               │  Work Agent  │ Audit Agent  │  Fix Agent   │
┌──────────────┼──────────────┼──────────────┼──────────────┤
│ 角色          │ ETSI 检测员  │ 独立审计员    │ 问题修正员    │
│ 触发方式      │ 管线自动     │ 离线/人工     │ 审计后人工    │
│ 知道审计存在? │ ❌ 不知道    │ —            │ ❌ 不知道    │
│ 知道工作细节? │ —            │ 只读文件      │ 仅知修正任务  │
│ 有工具?       │ ✅ Bash+Burp │ ❌ 只读文件   │ ✅ 按需给     │
│ 输出          │ evidence JSON│ audit JSON   │ 新 evidence   │
│ 加载审计标准? │ ❌ 不加载     │ ✅ 加载       │ ❌ 不加载     │
│ 加载弹药库?   │ ✅ 按模块     │ ❌ 不需要     │ ✅ 按需       │
│ 可发 API 调用?│ ✅ 是        │ ✅ 是         │ ✅ 是         │
└──────────────┴──────────────┴──────────────┴──────────────┘
```

### 8.2 Work Agent 配置

```python
# pipelines/etsi/work_agent_prompt.py

WORK_AGENT_BASE = AgentConfig(
    agent_id="work_{module_id}",  # 运行时填充
    agent_type="work",
    persona_path=Path("skills/etsi-ts103701-report/SKILL.md"),  # 去审计引用版
    knowledge_paths=(),
    tool_manifest=(),
    forbidden_patterns=(
        # 确保工作 Agent 永远不会看到审计相关概念
        "etsi-report-auditor",
        "audit-checklist",
        "common-errors",
        "evidence-standards",
        "Harness 违规",
        "审计 Agent",
    ),
)

def build_work_config(module: ModuleDef) -> AgentConfig:
    """为指定模块构建 Work Agent 配置"""
    return AgentConfig(
        agent_id=f"work_{module.id}_v1",
        agent_type="work",
        persona_path=WORK_AGENT_BASE.persona_path,
        knowledge_paths=(
            # 公共知识（所有模块共享）
            Path("skills/etsi-ts103701-report/references/clause-reference.md"),
            Path("skills/etsi-ts103701-report/references/verdict-criteria.md"),
            Path("skills/etsi-ts103701-report/references/tool-error-kb.json"),
            # 模块专属弹药库
            *module.ammo_paths,
        ),
        tool_manifest=WORK_AGENT_BASE.tool_manifest,
        forbidden_patterns=WORK_AGENT_BASE.forbidden_patterns,
    )
```

### 8.3 Audit Agent 配置

```python
# pipelines/etsi/audit_agent_prompt.py

AUDIT_AGENT_BASE = AgentConfig(
    agent_id="audit_{module_id}",
    agent_type="audit",
    persona_path=Path("skills/etsi-report-auditor/SKILL.md"),
    knowledge_paths=(
        # ⚠️ 这些文件只给 Audit Agent — Work Agent 永远不会看到
        Path("skills/etsi-report-auditor/references/audit-checklist.md"),
        Path("skills/etsi-report-auditor/references/common-errors.md"),
        Path("skills/etsi-report-auditor/references/evidence-standards.md"),
        # 共享参考（Work Agent 也读，但审计视角不同）
        Path("skills/etsi-ts103701-report/references/verdict-criteria.md"),
    ),
    tool_manifest=(),  # 审计 Agent 无工具
    forbidden_patterns=(),  # 审计 Agent 不需要弹药库
)
```

### 8.4 Fix Agent 配置

```python
# pipelines/etsi/fix_agent_prompt.py

def build_fix_config(
    module: ModuleDef,
    retry_instruction: RetryInstruction,
) -> AgentConfig:
    """
    为修正任务构建 Fix Agent 配置。
    
    关键: Fix Agent 的 prompt 中只有具体修正指令，
    没有审计框架、没有评判标准、不知道"为什么这算问题"。
    """
    return AgentConfig(
        agent_id=f"fix_{module.id}_r{retry_instruction.target_clause_ids}",
        agent_type="fix",
        persona_path=Path("skills/etsi-ts103701-report/SKILL.md"),
        knowledge_paths=(
            Path("skills/etsi-ts103701-report/references/clause-reference.md"),
            Path("skills/etsi-ts103701-report/references/verdict-criteria.md"),
            *module.ammo_paths,
        ),
        tool_manifest=module.tools,
        # ⚠️ 同样强制隔离 — Fix Agent 也不应该知道审计框架
        forbidden_patterns=WORK_AGENT_BASE.forbidden_patterns,
    )
```

---

## 9. 闸门系统 — L1 确定性 + L2 AI 离线

### 9.1 设计原理

```
┌──────────────────────────────────────────────────────────────┐
│                    闸门系统                                    │
│                                                               │
│  L1 确定性闸门 (在线，< 1s)                                    │
│  ┌─────────────────────────────────────────────────────┐     │
│  │ validate_evidence.py ── Python 脚本                   │     │
│  │ ✅ 确定性计算，0 误判                                  │     │
│  │ ✅ 可被 CI 直接调用                                   │     │
│  │ ✅ 管线阻塞（L1 不通过 → 打回）                        │     │
│  │ 检查: JSON 结构、字段齐全、条款数对账、L4/L5 证据      │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                               │
│  L2 AI 审计闸门 (离线，30s-5min)                               │
│  ┌─────────────────────────────────────────────────────┐     │
│  │ Audit Agent ── 独立 API 调用                           │     │
│  │ ✅ 语义理解，检测逻辑错误                               │     │
│  │ ✅ 不阻塞管线（离线运行）                               │     │
│  │ ✅ 结果反馈给人，不注入工作 Agent                       │     │
│  │ 检查: 裁决正确性、escape_clause、证据外推、继承链       │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                               │
│  ⛔ Phase Gate (整体闸门，< 1s)                                │
│  ┌─────────────────────────────────────────────────────┐     │
│  │ pipeline_phase_gate.py ── Python 脚本                 │     │
│  │ ✅ 检查: 所有令牌就绪、所有 evidence 文件存在           │     │
│  │ ✅ 不通过 → 禁止进入下一阶段                           │     │
│  └─────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────┘
```

### 9.2 实现

```python
# framework/gate_checker.py

from abc import ABC, abstractmethod
from enum import Enum

class GateResult(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"  # 通过但有警告

class GateChecker(ABC):
    """闸门检查器基类"""
    
    @abstractmethod
    async def check(self, workspace: Path) -> GateResult:
        ...
    
    @abstractmethod
    def describe(self) -> str:
        """人类可读的检查描述"""
        ...

class L1StructuralGate(GateChecker):
    """
    L1 确定性闸门 — 调用 validate_evidence.py 脚本。
    非 AI，确定性计算，毫秒级。
    """
    def __init__(self, evidence_path: str):
        self.evidence_path = evidence_path
    
    async def check(self, workspace: Path) -> GateResult:
        evidence_file = workspace / self.evidence_path
        
        # 运行 L1 验证脚本
        proc = await asyncio.create_subprocess_exec(
            "python", "scripts/validate_evidence.py", str(evidence_file),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode == 0:
            return GateResult.PASS
        else:
            # 将脚本输出的具体错误信息写入工作区
            (workspace / f"l1_errors_{evidence_file.stem}.txt").write_text(
                stdout.decode()
            )
            return GateResult.FAIL
    
    def describe(self) -> str:
        return f"L1 结构校验: {self.evidence_path}"

class L2AuditGate(GateChecker):
    """
    L2 AI 审计闸门 — 调度 Audit Agent。
    
    关键: 此闸门不阻塞管线。它在后台触发审计 agent，
    管线继续推进到下一阶段。审计结果后续异步处理。
    """
    def __init__(self, module_id: str, audit_config: AgentConfig):
        self.module_id = module_id
        self.audit_config = audit_config
    
    async def check(self, workspace: Path) -> GateResult:
        # L2 审计不阻塞管线 — 总是返回 PASS
        # 审计结果异步写入 audit-results/，后续处理
        return GateResult.PASS
    
    async def run_audit(
        self, workspace: Path, runner: AgentRunner
    ) -> AuditResult:
        """异步运行审计（由管线调度器在后台调用）"""
        evidence_path = workspace / f"evidence/evidence_{self.module_id}_*.json"
        
        task = {
            "task": f"审计模块 {self.module_id} 的 evidence JSON",
            "workspace": str(workspace),
            "inputs": [str(evidence_path), f"{workspace}/ixit.json"],
            "output_schema": "按 audit-output-schema.json 输出 AuditResult JSON",
        }
        
        result = await runner.run(self.audit_config, task, tools=[])
        
        if result.output:
            audit_result = AuditResult(**result.output)
            # 写入审计结果文件
            FileBus(workspace).write_audit_result(self.module_id, audit_result)
            return audit_result
        raise ValueError(f"Audit Agent 未产出结构化输出: {result.trace.error_message}")

class PhaseGate(GateChecker):
    """
    阶段闸门 — 调用 pipeline_phase_gate.py 脚本。
    检查所有令牌就绪、所有文件存在。
    不通过 → 抛出 PhaseGateBlocked，管线停在当前阶段。
    """
    def __init__(self, phase: str, required_tokens: list[str]):
        self.phase = phase
        self.required_tokens = required_tokens
    
    async def check(self, workspace: Path) -> GateResult:
        proc = await asyncio.create_subprocess_exec(
            "python", "scripts/pipeline_phase_gate.py", str(workspace),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode == 0:
            return GateResult.PASS
        else:
            return GateResult.FAIL
    
    def describe(self) -> str:
        return f"阶段闸门: {self.phase} (令牌: {self.required_tokens})"
```

---

## 10. 技能注册表

### 10.1 四层分类

```
┌─────────────────────────────────────────────────────────────┐
│ 第一层: Agent Skills — 变成独立 API 调用的智能体             │
│                                                              │
│  etsi-ts103701-report  →  Work Agent (有工具，不知道审计)    │
│  etsi-report-auditor   →  Audit Agent (无工具，只读文件)     │
│  exploit               →  弹药库 (不独立调用，注入 Work)      │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ 第二层: Tool Provider Skills — 被 Orchestrator 或 Agent 调用 │
│                                                              │
│  browser-automation    →  Playwright MCP                     │
│  document-skills:xlsx  →  ICS/IXIT 表格解析                  │
│  document-skills:docx  →  Word 文档解析                       │
│  document-skills:pdf   →  PDF 标准文档解析                    │
│  etsi-env-check        →  环境验证                            │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ 第三层: Reference Knowledge — 注入 Agent system prompt       │
│                                                              │
│  公开知识 (Work + Audit 都可读):                              │
│    clause-reference.md, verdict-criteria.md                  │
│                                                              │
│  Work Agent 专属 (弹药库):                                    │
│    web-sqli.md, web-xss.md, web-rce.md, web-traversal.md,   │
│    web-logic-auth.md, web-upload.md, web-ssrf-misc.md       │
│                                                              │
│  Audit Agent 专属 (审计标准):                                 │
│    audit-checklist.md, common-errors.md, evidence-standards.md│
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ 第四层: Meta/DevOps Skills — 不进入运行时管线                │
│                                                              │
│  skill-creator, superpowers, claude-api, update-config,     │
│  simplify, security-review                                   │
└─────────────────────────────────────────────────────────────┘
```

### 10.2 注册表实现

```python
# framework/registry.py

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

@dataclass
class ModuleDef:
    """单个测试模块定义"""
    id: str
    name: str
    clauses: list[str]
    ammo_paths: tuple[Path, ...]
    tools: tuple[str, ...]
    depends_on: Optional[str] = None  # 依赖的模块 ID

@dataclass
class PipelineDef:
    """管线定义"""
    name: str
    modules: list[ModuleDef]
    work_agent_base: AgentConfig
    audit_agent_base: AgentConfig
    required_tokens: list[str]
    phase_gate_script: Path

class AgentRegistry:
    """
    Agent/Skill 注册表。
    
    启动时加载，验证隔离约束，提供配置查询。
    """
    
    def __init__(self, skills_root: Path):
        self.skills_root = skills_root
        self._pipelines: dict[str, PipelineDef] = {}
        self._verified = False
    
    def register_pipeline(self, name: str, pipeline: PipelineDef):
        """注册一个管线"""
        self._pipelines[name] = pipeline
    
    def verify_isolation(self) -> list[str]:
        """
        启动时验证所有已注册管线的隔离约束。
        
        检查:
        1. 审计专用文件不出现在任何 Work Agent 的 knowledge_paths 中
        2. 弹药库不出现在任何 Audit Agent 的 knowledge_paths 中
        3. Work Agent 的 persona 文件中不包含审计相关模式
        
        返回违规列表（空列表 = 全部通过）。
        """
        violations = []
        
        for name, pipeline in self._pipelines.items():
            audit_knowledge = set(
                f.name for f in pipeline.audit_agent_base.knowledge_paths
            )
            
            for module in pipeline.modules:
                work_config = build_work_config(module)
                work_knowledge = set(
                    f.name for f in work_config.knowledge_paths
                )
                
                # 违规: 审计文件出现在 Work Agent 知识库
                overlap = audit_knowledge & work_knowledge
                if overlap:
                    violations.append(
                        f"[{name}/{module.id}] 审计专用文件出现在 Work Agent: {overlap}"
                    )
            
            # 违规: Work Agent persona 包含审计模式
            work_persona = pipeline.work_agent_base.persona_path.read_text()
            for pattern in PromptCompiler.DEFAULT_FORBIDDEN:
                if pattern.lower() in work_persona.lower():
                    violations.append(
                        f"[{name}] Work Agent persona 包含禁止模式: '{pattern}'"
                    )
        
        self._verified = len(violations) == 0
        return violations
```

---

## 11. 项目结构

```
<repo-root>/
├── CLAUDE.md                          # 红队渗透 persona (保持，手工渗透用)
├── skills/                            # 现有 skill (不动，供 Claude Code 直接对话)
│   ├── etsi-ts103701-report/          # 工作 skill
│   ├── etsi-report-auditor/           # 审计 skill
│   ├── exploit/                       # 弹药库
│   ├── etsi-env-check/                # 环境检查
│   ├── document-skills:xlsx|docx|pdf  # 文档解析
│   ├── browser-automation/            # 浏览器自动化
│   └── ...
│
├── agent_framework/                   # 🆕 编排框架
│   ├── pyproject.toml                 # Python 项目定义
│   ├── README.md                      # 框架文档
│   │
│   ├── contracts/                     # 数据合约 (Pydantic models)
│   │   ├── __init__.py                # 导出所有 models
│   │   ├── pipeline.py                # PipelineState, StageStatus, PipelineSnapshot
│   │   ├── evidence.py                # EvidenceManifest, ClauseResult, EvidenceItem
│   │   ├── audit.py                   # AuditResult, AuditFinding, TriangulationResult
│   │   ├── agent_result.py            # AgentResult, AgentTrace, TokenUsage
│   │   └── module.py                  # ModuleDef, PipelineDef
│   │
│   ├── framework/                     # 通用框架层 (与 ETSI 无关)
│   │   ├── __init__.py
│   │   ├── agent_runner.py            # AgentRunner, AgentConfig, PromptCompiler
│   │   ├── file_bus.py                # FileBus: 原子读写、轮询、令牌管理
│   │   ├── pipeline.py                # Pipeline 基类、Stage、StageTransition
│   │   ├── gate_checker.py            # L1StructuralGate, L2AuditGate, PhaseGate
│   │   ├── telemetry.py               # 结构化日志、trace、token 统计
│   │   ├── retry.py                   # 指数退避、熔断器
│   │   └── registry.py                # AgentRegistry, 隔离验证
│   │
│   ├── pipelines/                     # 🆕 具体管线定义 (ETSI 业务逻辑)
│   │   ├── __init__.py
│   │   └── etsi/                      # ETSI TS 103 701 管线
│   │       ├── __init__.py
│   │       ├── pipeline.py            # ETSIPipeline(Pipeline): 阶段定义
│   │       ├── modules.py             # M0-M5 模块定义、条款分配表
│   │       ├── work_agent.py          # build_work_config(), WORK_AGENT_BASE
│   │       ├── audit_agent.py         # AUDIT_AGENT_BASE
│   │       ├── fix_agent.py           # build_fix_config()
│   │       └── registry.py            # ETSI 管线的 Agent/知识库注册
│   │
│   ├── scripts/                       # 确定性脚本 (从 skills 迁移)
│   │   ├── validate_evidence.py       # L1 证据结构校验
│   │   ├── pipeline_phase_gate.py     # 阶段闸门
│   │   ├── pcap_analyzer.py           # pcap 批量分析
│   │   ├── preprocess_m4_ixit.py      # M4 IXIT 预处理
│   │   └── evidence_to_md.py          # Evidence JSON → Markdown
│   │
│   ├── tests/                         # 测试
│   │   ├── conftest.py                # 共享 fixture
│   │   ├── test_prompt_compiler.py    # 隔离约束编译时测试
│   │   ├── test_agent_runner.py       # Agent 运行器 mock 测试
│   │   ├── test_file_bus.py           # 文件总线测试
│   │   ├── test_gate_checker.py       # L1 闸门确定性测试
│   │   ├── test_pipeline.py           # 管线状态机测试
│   │   ├── test_registry.py           # 注册表隔离验证测试
│   │   └── fixtures/                  # 测试用 fixture
│   │       ├── sample_evidence.json   # 合法 evidence
│   │       ├── bad_evidence.json      # 非法 evidence (缺字段)
│   │       ├── sample_audit.json      # 合法审计结果
│   │       └── mini_ixit.json         # 最小 IXIT 样例
│   │
│   └── docs/                          # 文档
│       ├── ARCHITECTURE.md            # 本文档
│       └── GETTING_STARTED.md         # 快速开始指南
```

---

## 12. 可观测性

### 12.1 三层遥测

```
┌─────────────────────────────────────────────────────────┐
│ 第一层: Trace (每次 Agent API 调用)                       │
│                                                          │
│  trace_id: "wf_abc123_M1_v1"                             │
│  agent_id: "work_M1_v1"                                  │
│  agent_type: "work"                                      │
│  started_at: 2026-08-06T14:30:00Z                        │
│  duration_ms: 45230                                       │
│  model: claude-sonnet-5                                  │
│  token_usage: {input: 28500, output: 4200, cache: 12000} │
│  tools_called: [bash, burp_mcp, bash, bash]              │
│  tool_calls_count: 12                                     │
│  outcome: success                                         │
│  output_file: evidence/pre-M1-evidence-x0.json            │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 第二层: Stage (每个管线阶段)                               │
│                                                          │
│  pipeline_id: "run_20260806_001"                          │
│  stage: M1_M5_PARALLEL                                    │
│  started_at: ...  ended_at: ...  duration_s: 387          │
│  agents_spawned: 5                                        │
│  agents_succeeded: 4                                      │
│  agents_failed: 1  (M4: timeout)                          │
│  l1_gate: PASS (5/5)                                     │
│  artifacts: [evidence_M1..M5.json]                        │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 第三层: Pipeline Run (整次运行)                            │
│                                                          │
│  pipeline: etsi-ts103701                                  │
│  run_id: "run_20260806_001"                               │
│  started_at: ...  ended_at: ...  total_duration: 2h13m   │
│  total_agents: 8 (M0+M1..M5+audit+cross)                  │
│  total_tokens: 485000                                     │
│  total_api_cost: $3.82                                    │
│  final_report: reports/认证检测报告_DS-2CD2XXX_20260806.md│
│  verdict: PASS (32/35 clauses, 3 PENDING_MANUAL)         │
└─────────────────────────────────────────────────────────┘
```

### 12.2 实现

```python
# framework/telemetry.py

import structlog
from datetime import datetime
from typing import Optional

logger = structlog.get_logger()

class Telemetry:
    """
    遥测系统。
    
    提供:
    - 结构化日志 (structlog → JSON lines)
    - Trace ID 贯穿 Agent → Stage → Pipeline 三层的追踪
    - Token 用量累计
    - 每次 API 调用的完整审计日志
    """
    
    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._active_traces: dict[str, dict] = {}
    
    def start_trace(self, agent_id: str, agent_type: str) -> str:
        """开始一次 Agent 调用的 trace"""
        trace_id = f"{agent_id}_{datetime.now().strftime('%H%M%S')}"
        self._active_traces[trace_id] = {
            "trace_id": trace_id,
            "agent_id": agent_id,
            "agent_type": agent_type,
            "started_at": datetime.now(),
        }
        logger.info("agent_trace_started", trace_id=trace_id, agent_id=agent_id)
        return trace_id
    
    def end_trace(
        self, trace_id: str, result: Optional[AgentResult], error: Optional[str] = None
    ):
        """结束一次 Agent 调用的 trace"""
        trace = self._active_traces.pop(trace_id, {})
        trace["ended_at"] = datetime.now()
        trace["outcome"] = "error" if error else "success"
        trace["error"] = error
        
        if result:
            trace["token_usage"] = result.trace.token_usage.model_dump()
            trace["duration_ms"] = result.trace.duration_ms
        
        # 写入结构化日志
        log_file = self.log_dir / f"trace_{trace_id}.json"
        log_file.write_text(json.dumps(trace, indent=2, default=str))
        
        logger.info("agent_trace_ended", **trace)
    
    def log_stage_event(
        self, pipeline_id: str, stage: str, event: str, details: dict
    ):
        """记录阶段级事件"""
        logger.info(
            "stage_event",
            pipeline_id=pipeline_id,
            stage=stage,
            event=event,
            **details,
        )
    
    def get_run_summary(self, pipeline_id: str) -> dict:
        """汇总本次运行的统计数据"""
        # 从日志文件中聚合 token 用量、耗时、成功率
        ...
```

---

## 13. 测试策略

### 13.1 测试金字塔

```
           ┌──────────┐
           │  E2E     │  完整管线 + 真实 API (少, 贵)
           │  Tests   │
           └──────────┘
        ┌──────────────┐
        │ Integration  │  Mock API + 真实文件总线
        │ Tests        │
        └──────────────┘
     ┌───────────────────┐
     │  Unit Tests       │  隔离检查、闸门脚本、合约验证
     │  (多, 快, 便宜)    │
     └───────────────────┘
```

### 13.2 关键测试用例

```python
# tests/test_prompt_compiler.py

class TestIsolationEnforcement:
    """隔离约束的编译时测试 — 框架的核心质量保证"""
    
    def test_work_agent_rejects_audit_files(self):
        """Work Agent 配置包含审计文件 → 抛出 IsolationViolation"""
        config = AgentConfig(
            agent_id="test",
            agent_type="work",
            persona_path=PERSONA_CLEAN,
            knowledge_paths=(
                AUDIT_CHECKLIST,  # 审计专用文件
            ),
            tool_manifest=(),
        )
        
        with pytest.raises(IsolationViolation) as exc:
            PromptCompiler.compile(config, {"task": "test", "workspace": "/tmp"})
        
        assert "审计" in str(exc.value)
    
    def test_work_agent_rejects_forbidden_pattern_in_persona(self):
        """Work Agent persona 包含 '审计 Agent' → 抛异常"""
        persona_with_audit_ref = write_temp_file(
            "## 角色\n完成后等待审计 Agent 审查\n"
        )
        config = AgentConfig(
            agent_id="test",
            agent_type="work",
            persona_path=persona_with_audit_ref,
            knowledge_paths=(),
            tool_manifest=(),
        )
        
        with pytest.raises(IsolationViolation):
            PromptCompiler.compile(config, {"task": "test", "workspace": "/tmp"})
    
    def test_audit_agent_allows_audit_files(self):
        """Audit Agent 可以加载审计专用文件（不抛异常）"""
        config = AgentConfig(
            agent_id="test_auditor",
            agent_type="audit",
            persona_path=AUDIT_PERSONA,
            knowledge_paths=(AUDIT_CHECKLIST, COMMON_ERRORS),
            tool_manifest=(),
        )
        
        # 不应抛异常
        prompt = PromptCompiler.compile(config, {"task": "test", "workspace": "/tmp"})
        assert len(prompt) > 0


# tests/test_gate_checker.py

class TestL1StructuralGate:
    """L1 确定性闸门测试 — 必须 100% 确定"""
    
    def test_valid_evidence_passes(self, workspace):
        """合法 evidence JSON → L1 PASS"""
        FileBus(workspace).write_evidence("M1", VALID_EVIDENCE)
        gate = L1StructuralGate("evidence/pre-M1-evidence.json")
        result = asyncio.run(gate.check(workspace))
        assert result == GateResult.PASS
    
    def test_missing_clause_fails(self, workspace):
        """缺失条款 → L1 FAIL"""
        FileBus(workspace).write_json(
            "evidence/pre-M1-evidence.json",
            EVIDENCE_MISSING_CLAUSE,
        )
        gate = L1StructuralGate("evidence/pre-M1-evidence.json")
        result = asyncio.run(gate.check(workspace))
        assert result == GateResult.FAIL
    
    def test_empty_trace_fails(self, workspace):
        """execution_trace 为空 → L1 FAIL"""
        FileBus(workspace).write_json(
            "evidence/pre-M1-evidence.json",
            EVIDENCE_EMPTY_TRACE,
        )
        gate = L1StructuralGate("evidence/pre-M1-evidence.json")
        result = asyncio.run(gate.check(workspace))
        assert result == GateResult.FAIL


# tests/test_registry.py

class TestRegistryIsolation:
    """注册表隔离验证 — 启动时运行"""
    
    def test_verify_isolation_clean_pipeline(self, registry):
        """干净的管线 → 零违规"""
        violations = registry.verify_isolation()
        assert len(violations) == 0, f"隔离违规: {violations}"
    
    def test_verify_isolation_detects_contamination(self, registry):
        """审计文件出现在 Work Agent 知识库 → 检测到违规"""
        # 构造一个被污染的管线
        contaminated_pipeline = PipelineDef(
            name="contaminated",
            modules=[
                ModuleDef(
                    id="M1", name="test", clauses=["5.6-1"],
                    ammo_paths=(),
                    tools=(),
                )
            ],
            work_agent_base=AgentConfig(
                agent_id="work", agent_type="work",
                persona_path=PERSONA_CLEAN,
                knowledge_paths=(AUDIT_CHECKLIST,),  # ← 污染!
                tool_manifest=(),
            ),
            audit_agent_base=AUDIT_BASE,
            required_tokens=[],
            phase_gate_script=Path("dummy.py"),
        )
        registry.register_pipeline("contaminated", contaminated_pipeline)
        violations = registry.verify_isolation()
        assert len(violations) > 0
```

---

## 14. 隔离保证机制

### 14.1 三层防护

```
┌─────────────────────────────────────────────────────────────┐
│ 第一层: 编译时 (PromptCompiler)                               │
│                                                              │
│  时机: 每次 Agent 创建时                                      │
│  机制: 扫所有注入文件 → 匹配 forbidden_patterns → 违规则抛异常│
│  保证: 任何包含审计模式的 prompt 无法被编译                     │
│  成本: ~10ms (纯文本扫描)                                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 第二层: 启动时 (AgentRegistry.verify_isolation)               │
│                                                              │
│  时机: 框架启动时运行一次                                      │
│  机制: 扫所有已注册管线的 AgentConfig → 检查审计文件交叉引用    │
│  保证: 整体架构层面的隔离约束一次验证                          │
│  成本: ~50ms                                                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 第三层: 运行时 (独立 API 调用)                                │
│                                                              │
│  时机: 每次 Agent 调用时                                       │
│  机制: 每个 Agent = 一次独立 API 调用 = 独立 system prompt     │
│  保证: Agent 之间无共享内存、无共享上下文、无共享会话           │
│  成本: ~50ms (API 握手延迟)                                   │
└─────────────────────────────────────────────────────────────┘
```

### 14.2 不可绕过的隔离检查流程

```python
# 在任何 Agent 被创建之前，必须通过以下流程:

def create_agent(config: AgentConfig, task: dict) -> AgentResult:
    """
    创建 Agent 的唯一入口。
    无法绕过隔离检查 — 这是创建 Agent 的唯一函数。
    """
    # 1. 编译时检查（不可跳过）
    #    PromptCompiler.compile() 内部强制执行
    #    任何 forbidden pattern → IsolationViolation
    system_prompt = PromptCompiler.compile(config, task)
    
    # 2. 独立 API 调用（物理隔离）
    #    不共享会话、不共享上下文、不共享内存
    response = anthropic_client.messages.create(
        model=config.model,
        system=system_prompt,  # 一次性字符串
        messages=[{"role": "user", "content": task["task"]}],
        tools=config.tool_manifest,
    )
    
    # 3. 结构化输出验证
    #    输出合约由 Pydantic model 强制执行
    if task.get("output_schema"):
        validated = output_schema(**response.structured_output)
    
    return AgentResult(...)
```

---

## 15. ETSI 管线具体定义

### 15.1 模块与弹药库映射

```python
# pipelines/etsi/modules.py

ETSI_MODULES = [
    ModuleDef(
        id="M0",
        name="ICS 逻辑验证",
        clauses=["5.1-1", "5.1-2", ...],  # ICS 全量条款
        ammo_paths=(),  # M0 不需要弹药库
        tools=("bash",),
    ),
    ModuleDef(
        id="M1",
        name="攻击面与端口",
        clauses=["5.5-2", "5.5-4", "5.5-5", "5.6-1", "5.6-2",
                 "5.6-3", "5.6-4", "5.6-5", "5.6-6", "5.6-7",
                 "5.6-8", "5.6-9"],
        ammo_paths=(
            Path("skills/etsi-ts103701-report/references/auth-diff-workflow.md"),
        ),
        tools=("bash", "burp_mcp"),
    ),
    ModuleDef(
        id="M2",
        name="认证与口令",
        clauses=["5.1-1", "5.1-2", "5.1-3", "5.1-4", "5.1-5"],
        ammo_paths=(
            Path("skills/exploit/references/web-logic-auth.md"),
        ),
        tools=("bash", "burp_mcp", "playwright_mcp"),
    ),
    ModuleDef(
        id="M3",
        name="通信加密",
        clauses=["5.5-1", "5.5-3", "5.5-6", "5.5-7", "5.5-8",
                 "5.8-1", "5.8-2"],
        ammo_paths=(),  # M3 为加密分析，不需要注入弹药库
        tools=("bash", "burp_mcp"),
        depends_on="M2",  # 需要 M2 的前端加密分析结果
    ),
    ModuleDef(
        id="M4",
        name="更新与完整性",
        clauses=["5.3-1", "5.3-2", "5.3-3", "5.3-4", "5.3-5",
                 "5.3-6", "5.3-7", "5.3-8", "5.3-9", "5.3-10",
                 "5.3-11", "5.3-12", "5.3-13", "5.3-14", "5.3-15",
                 "5.3-16", "5.4-1", "5.4-2", "5.4-3", "5.4-4",
                 "5.7-1", "5.7-2"],
        ammo_paths=(),  # M4 为 IXIT 分析，不需要注入弹药库
        tools=("bash", "burp_mcp", "playwright_mcp"),
    ),
    ModuleDef(
        id="M5",
        name="输入验证与数据保护",
        clauses=["5.2-1", "5.2-2", "5.2-3", "5.8-3", "5.9-1",
                 "5.9-2", "5.9-3", "5.10", "5.11-1", "5.11-2",
                 "5.11-3", "5.11-4", "5.12-1", "5.12-2", "5.12-3",
                 "5.13-1", "6-1", "6-2", "6-3", "6-4", "6-5"],
        ammo_paths=(  # 注入类测试强制加载弹药库
            Path("skills/exploit/references/web-sqli.md"),
            Path("skills/exploit/references/web-xss.md"),
            Path("skills/exploit/references/web-rce.md"),
            Path("skills/exploit/references/web-traversal.md"),
        ),
        tools=("bash", "burp_mcp", "playwright_mcp"),
    ),
]
```

### 15.2 ETSI 管线定义

```python
# pipelines/etsi/pipeline.py

class ETSIPipeline(Pipeline):
    """ETSI TS 103 701 认证检测管线"""
    
    @property
    def stages(self) -> dict:
        return {
            PipelineState.INIT: InitStage(),
            PipelineState.ENV_CHECK: EnvCheckStage(),
            PipelineState.ICS_PARSE: IcsParseStage(),
            PipelineState.M0_ICS_VALIDATION: M0Stage(),
            PipelineState.TRAFFIC_COLLECT: TrafficCollectStage(),
            PipelineState.M1_M5_PARALLEL: M1M5ParallelStage(ETSI_MODULES),
            PipelineState.AUDIT_QUEUE: AuditQueueStage(),
            PipelineState.CROSS_MODULE_AUDIT: CrossModuleAuditStage(),
            PipelineState.REPORT_GENERATION: ReportGenerationStage(),
        }
    
    @property
    def transitions(self) -> list:
        return [
            StageTransition(
                from_state=PipelineState.INIT,
                to_state=PipelineState.ENV_CHECK,
                gate=None,  # 无闸门
            ),
            StageTransition(
                from_state=PipelineState.ENV_CHECK,
                to_state=PipelineState.ICS_PARSE,
                gate=PhaseGate("env_check", []),
                on_failure=PipelineState.FAILED,
            ),
            # ... 其余跃迁
            StageTransition(
                from_state=PipelineState.M1_M5_PARALLEL,
                to_state=PipelineState.AUDIT_QUEUE,
                gate=PhaseGate("m1_m5_done", [
                    ".evidence_M1_complete",
                    ".evidence_M2_complete",
                    ".evidence_M3_complete",
                    ".evidence_M4_complete",
                    ".evidence_M5_complete",
                ]),
                on_failure=PipelineState.M1_M5_PARALLEL,  # 留在当前阶段重试
            ),
            # ...
        ]
```

---

## 16. 实施路线图

### Phase 1: 基础设施 (3-5 天)

```
Day 1-2: contracts/ + framework/agent_runner.py
  ├── 实现所有 Pydantic models (contracts/)
  ├── 实现 PromptCompiler + 编译时隔离检查
  ├── 实现 AgentRunner
  ├── 实现 AgentConfig (不可变 dataclass)
  └── 单元测试 (隔离检查、合约验证)

Day 3: framework/file_bus.py + framework/gate_checker.py
  ├── 实现 FileBus (原子读写、轮询、令牌)
  ├── 实现 L1StructuralGate, L2AuditGate, PhaseGate
  └── 集成测试 (文件总线 + 闸门)

Day 4-5: framework/pipeline.py + framework/registry.py
  ├── 实现 Pipeline 基类 + 状态机
  ├── 实现 AgentRegistry + verify_isolation()
  ├── 实现 Telemetry
  └── 集成测试 (完整管线骨架)
```

### Phase 2: ETSI 管线适配 (3-4 天)

```
Day 6-7: pipelines/etsi/
  ├── 定义 ETSI_MODULES (从 module-split.md 迁移)
  ├── 定义 Work/Audit/Fix Agent 配置
  ├── 清理 etsi-ts103701-report/SKILL.md (去审计引用)
  ├── 清理 etsi-report-auditor/SKILL.md (去 Pipeline 模式)
  └── 注册表隔离验证测试

Day 8-9: 端到端集成
  ├── 迁移 scripts/ (validate_evidence.py 等)
  ├── E2E 测试 (标靶设备 + 真实 API)
  ├── 修复集成问题
  └── 文档完善
```

### Phase 3: 过渡与并存 (2-3 天)

```
Day 10-11: 双轨运行
  ├── 框架 + Claude Code 直接对话并存
  ├── skills/ 原样保留不修改
  ├── 框架从 skills/ 读取 prompt 文件
  ├── Claude Code 手工渗透不受影响
  └── 用户手册 + 快速开始指南
```

### Phase 4: 进阶特性 (按需)

```
- 文件变更监听 (watchdog) 代替轮询
- Dashboard (Streamlit) 展示管线进度
- 多 DUT 并行检测
- Prompt 版本管理与 A/B 测试
- 审计结果统计分析 (常见误判趋势)
```

---

## 附录 A: 关键设计模式参考

| 模式 | 应用位置 | 目的 |
|------|---------|------|
| **不可变配置** | `AgentConfig` (@dataclass frozen) | 防止运行时意外修改污染 |
| **编译时检查** | `PromptCompiler._enforce_isolation()` | 在 Agent 创建前阻止隔离违规 |
| **原子写入** | `FileBus.write_atomic()` | 防止读取方读到半成品文件 |
| **门面模式** | `FileBus` | 统一文件系统访问，隐藏路径细节 |
| **模板方法** | `Pipeline` 基类 | 管线状态机骨架，子类定义具体阶段 |
| **策略模式** | `GateChecker` 子类 | 不同闸门策略可插拔 |
| **工厂函数** | `build_work_config()` | 从 ModuleDef 构建 AgentConfig |
| **合约优先** | Pydantic models → JSON Schema | 数据结构先于行为逻辑 |

---

## 附录 B: 现有资产迁移清单

| 现有位置 | 迁移目标 | 修改内容 |
|---------|---------|---------|
| `skills/etsi-ts103701-report/SKILL.md` | 保持原位，去审计引用 | 删除 L102-104 (M0 审计闸门)、L133-136 (审计队列调用) |
| `skills/etsi-ts103701-report/agents/etsi-auditor.md` | `skills/etsi-report-auditor/agents/module-auditor.md` | 迁出工作区 |
| `skills/etsi-ts103701-report/references/audit-agent-prompt.md` | `skills/etsi-report-auditor/references/pipeline-call-template.md` | 迁出工作区 |
| `skills/etsi-ts103701-report/references/audit-output-schema.json` | `agent_framework/contracts/schemas/audit.schema.json` | 以 Pydantic model 为准 |
| `skills/etsi-ts103701-report/references/module-split.md` | `agent_framework/pipelines/etsi/modules.py` | 代码化模块定义 |
| `skills/etsi-ts103701-report/references/harness-config.json` | `agent_framework/pipelines/etsi/harness.py` | 代码化 harness 配置 |
| `skills/etsi-ts103701-report/scripts/*` | `agent_framework/scripts/` | 路径调整 |
| `skills/etsi-report-auditor/SKILL.md` | 保持原位，去 Pipeline 模式 | 删除 Pipeline 模式章节 |
