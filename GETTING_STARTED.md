# ETSI Agent Framework — 快速开始指南

> 适用于 ETSI TS 103 701 认证检测管线的工程化 Agent 编排框架。

## 5 分钟快速启动

### 前置条件

- Python >= 3.11
- Node.js >= 18（仅 Playwright MCP 本地运行时需要）
- Git Bash (Windows) 或 Bash (Linux/macOS)
- Anthropic 兼容 API Key (DeepSeek / 官方 Anthropic)
- 可选: Burp Suite Pro + MCP 扩展、Wireshark/tshark、nmap

### 1. 创建环境并安装依赖

```powershell
# 若系统没有 `py` launcher，改为已安装 Python 的绝对路径执行同一命令。
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[web,dev]"

# 安装锁定版本的 Playwright MCP 运行时（不会写入 Git）
Push-Location tools/playwright-mcp
npm ci
Pop-Location
```

### 2. 配置环境

```powershell
Copy-Item .env.template .env
# 编辑 .env 填入 API Key:
#   ANTHROPIC_API_KEY=YOUR_KEY_HERE
#   ANTHROPIC_MODEL=deepseek-v4-pro[1m]
```

`.env` 会在运行入口自动加载（`load_dotenv()`）；也可直接 `export ANTHROPIC_API_KEY=...` 注入环境变量。

### 3. 运行管线

```powershell
# 指定工作区
etsi-framework run --workspace D:/ETSI/runs/my_test_run

# 断点续跑 (使用已有工作区)
etsi-framework run --workspace D:/ETSI/runs/my_test_run

# Web 控制台
python web/server.py --port 8001
```

## 架构概览

```
run_pipeline.py          ← 入口
    ↓
AgentOrchestrator        ← 组装组件，动态解析管线类
    ↓
AgentRegistry            ← 启动时隔离验证
    ↓
ETSIPipeline             ← 9 阶段状态机
    ├── InitStage        ← 创建工作区
    ├── EnvCheckStage    ← 验证 ixidoc + 工具可用性
    ├── IcsParseStage    ← 解析 ICS/IXIT JSON
    ├── M0Stage          ← ICS 逻辑验证
    ├── TrafficCollect   ← tshark + xray + Burp
    ├── M1M5Parallel     ← 5 个 Work Agent 并行 (按依赖分批)
    ├── AuditQueue       ← Audit Agent 离线审计
    ├── CrossModuleAudit ← 跨模块一致性审计
    └── ReportGen        ← 汇总生成报告
```

## 双轨并存模式

框架 (`run_pipeline.py`) 和 Claude Code 直接对话 (`/etsi-ts103701-report`) 可以共存：

```
┌─────────────────────────────────────────────────────┐
│                   skills/ 目录 (共享知识源)          │
│                                                      │
│  etsi-ts103701-report/     etsi-report-auditor/      │
│  ├── references/           ├── references/           │
│  │   ├── clause-ref.md     │   ├── audit-checklist   │
│  │   ├── verdict-criteria  │   ├── common-errors     │
│  │   └── tool-error-kb     │   └── evidence-standards│
│  └── SKILL.md (原始)       └── SKILL.md (原始)        │
│                                                      │
│  exploit/references/  ← 弹药库                       │
└─────────────────────┬───────────────────────────────┘
                      │
          ┌───────────┴───────────┐
          │                       │
    框架读取知识文件        Claude Code 加载 SKILL.md
    (干净 persona)          (含审计引用的原始 prompt)
          │                       │
    独立 API 调用            共享会话上下文
    物理隔离保证             手工渗透灵活性
```

**关键规则**：
- 框架使用 `pipelines/etsi/personas/` 下的干净 persona（无审计引用）
- 框架从 `skills/` 读取参考知识文件（条款参考、裁决标准、弹药库）
- Claude Code 手工渗透使用原始 `SKILL.md`（保持不变）
- 两者不冲突 — 框架不修改 skills/ 目录

## 隔离保证 (三层防护)

```
Layer 1: 编译时 — PromptCompiler 扫所有注入文件
         → 含禁止模式 → IsolationViolation (拒绝创建 Agent)

Layer 2: 启动时 — AgentRegistry.verify_isolation()
         → 审计文件交叉引用检查

Layer 3: 运行时 — 每个 Agent = 独立 API 调用
         → 无共享上下文、无共享内存
```

## 项目结构

```
agent_framework/
├── contracts/          # Pydantic 数据合约
│   ├── pipeline.py     # PipelineState, StageStatus
│   ├── evidence.py     # EvidenceManifest, ClauseResult
│   ├── audit.py        # AuditResult, AuditFinding
│   ├── agent_result.py # AgentResult, AgentTrace
│   └── module.py       # ModuleDef, PipelineDef
│
├── framework/          # 通用框架 (ETSI-agnostic)
│   ├── agent_runner.py # AgentRunner + PromptCompiler
│   ├── pipeline.py     # Pipeline 状态机基类
│   ├── file_bus.py     # 文件系统通信总线
│   ├── gate_checker.py # L1/L2/Phase 闸门
│   ├── registry.py     # AgentRegistry + 隔离验证
│   ├── telemetry.py    # Trace/Stage/Pipeline 追踪
│   ├── retry.py        # 指数退避 + 熔断器
│   ├── tools.py        # ToolDef/ToolRegistry
│   └── orchestrator.py # AgentOrchestrator
│
│   ├── traffic_intelligence/ # PCAP 主分析：完整性 Bundle、Direct Tshark、可选 Batch Worker
│
├── pipelines/etsi/     # ETSI 业务逻辑
│   ├── pipeline.py     # ETSIPipeline (9 个 Stage)
│   ├── modules.py      # M0-M5 模块定义
│   ├── agents.py       # Work/Audit Agent 工厂函数
│   ├── registry.py     # 管线注册
│   └── personas/       # 干净 persona 文件
│       ├── work-agent.md
│       └── audit-agent.md
│
├── scripts/            # 确定性脚本
│   ├── validate_evidence.py   # L1 证据校验
│   ├── pipeline_phase_gate.py # 阶段闸门
│   ├── pcap_analyzer.py       # 旧 tshark 条款输出兼容层（非主分析入口）
│   ├── preprocess_m4_ixit.py  # M4 IXIT 预处理
│   └── evidence_to_md.py      # Evidence JSON → MD
│
├── tests/              # 测试
│   ├── fixtures/       # 测试数据
│   └── mock_api.py     # Mock API 客户端
│
├── run_pipeline.py     # 入口
├── ARCHITECTURE.md     # 完整架构设计文档
└── .env.template       # 环境配置模板
```

## 开发指南

### 运行测试

```bash
# 全部测试
python -m pytest tests/ -v

# 单文件
python -m pytest tests/test_prompt_compiler.py -v

# 含覆盖率
python -m pytest tests/ --cov=. --cov-report=html
```

### 添加新管线

```python
# 1. 定义 Pipeline 子类
class MyPipeline(Pipeline):
    @property
    def stages(self): ...
    @property
    def transitions(self): ...

# 2. 创建 PipelineDef 并注册
pipeline_def = PipelineDef(
    name="my-pipeline",
    pipeline_class="my_package.MyPipeline",
    ...
)
registry.register_pipeline("my-pipeline", pipeline_def)

# 3. 运行
await orchestrator.run_pipeline("my-pipeline")
```

### 切换第三方 API

框架通过 `ANTHROPIC_BASE_URL` 支持任何 Anthropic 兼容端点：

```env
# DeepSeek
ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic
ANTHROPIC_MODEL=deepseek-v4-pro[1m]

# 官方 Anthropic
ANTHROPIC_BASE_URL=https://api.anthropic.com
ANTHROPIC_MODEL=claude-sonnet-5-20251001

# 自定义代理
ANTHROPIC_BASE_URL=http://localhost:9000/v1
ANTHROPIC_MODEL=local-model
```
