# ETSI Skill 资产消费台账

> 更新：2026-08-19。此台账把 `skills/` 中每份资料映射到明确消费者。
> “不进入某个 Agent Prompt”不等于无用；资料可服务于运行时、编排、审计、
> 环境准备或回归。除已退役的 M6 派发模板外，未删除任何已有知识资产。

## 消费原则

1. Work Agent 只读取检测所需的中性执行知识；不得读取 Audit 的对抗规则。
2. Audit Agent 独立读取审计知识与证据标准；不得依赖 Work Agent 自述作为事实。
3. `capability-matrix.md` 是“已允许能力与产物”的合同，不能只停留在说明文档。
4. 每个 Phase 只挂载其条款需要的附加资料；全量 skill 不一次性塞入 Prompt。
5. exploit 资料不扩展 ETSI 的测试范围。已经存在的 M2/M5 受限绑定保留；其他
   exploit 资料均不进入 ETSI 自动编排，除非用户单独授权具体攻击面。

状态说明：**已绑定**=当前代码实际会消费；**条件绑定**=已配置，按 Phase 执行时消费；
**编排/契约**=供 Pipeline、测试或生成器使用，不进 Agent Prompt；**保留待接线**=有明确
用途但当前没有代码消费者；**排除**=不属于 ETSI 本次自动化范围；**退役**=被新实现替代。

## 部署与环境 skill

| 资产 | 状态 | 消费者 / 边界 |
|---|---|---|
| `skills/path-mapping.json` | 部署模板 | 部署维护者据此创建仓库外的私有 mapping；`PathResolver` 只读取显式 `PATH_MAPPING`，不会自动加载本文件。浏览器与 Agent Prompt 均不可写入。本文件不改动。 |
| `etsi-env-check/SKILL.md` | 编排/契约 | Preflight 的检查顺序、MCP/工具/固件前提的权威说明；后续由 `framework/preflight.py` 输出同等快照。 |
| `playwright-mcp-launch.cjs` | 保留待接线 | Playwright 的离线缓存启动器；应作为部署 MCP 配置入口，不应由 Work Agent 临时下载或改写。 |
| `tamper_firmware.py` | 编排/工具 | 固件篡改产物的确定性生成器；仅在 5.3-9 具备用户提供的 `new/` 固件时由 Preflight/Traffic 准备阶段调用。 |

## ETSI 检测 skill

| 资产 | 状态 | 消费者 / 边界 |
|---|---|---|
| `etsi-ts103701-report/SKILL.md` | 编排/契约 | 定义 M0、Traffic、模块、报告的总流程；不直接整篇注入任何 Agent。 |
| `clause-reference.md` | 已绑定 | Work Agent 公共知识：逐条款测试方法与概念性三问法。 |
| `capability-matrix.md` | 已绑定 | Work Agent 公共知识：工具、命令、前置条件、预期产物；后续 Catalog 校验以它为能力源。 |
| `verdict-criteria.md` | 已绑定 | Work/Audit 共用的裁决条件速查；报告输出也应记录引用版本。 |
| `tool-error-kb.json` | 已绑定 | Work Agent 公共知识：Burp/Playwright/本地工具的已知参数与故障处理。 |
| `auth-diff-workflow.md` | 已绑定 | M1/M5 的模块 ammo：认证差异与越权验证工作流。 |
| `frontend-encryption-check.md` | 条件绑定 | M2 phase_A、M3 phase_B：仅在需要浏览器加密验证时提供。 |
| `pcap-analyzer-reference.md` | 条件绑定 | M3 phase_A/B、M4 phase_A、M5 phase_C：将 `pcap_analysis/` 文件映射回条款裁决。Pipeline 已实际调用 `pcap_analyzer.py`。 |
| `vm-methods.md` | 条件绑定 | M1 phase_A：端口发现阶段可按目标部署方式采用 VM 减法扫描。 |
| `module-split.md` | 编排/契约 | `modules.py`、Phase 定义和并行边界的设计来源；不作为单个 Agent 的大 Prompt。 |
| `evidence-schema.json` | 编排/契约 | `contracts/evidence.py`、模板生成与 L1 校验必须与其保持字段语义一致。 |
| `report-template.md` | 编排/契约 | `ReportGenerationStage` 的报告结构与手工复现要求来源。 |
| `test-workspace.md` | 编排/契约 | 工作区目录、产物保留与报告索引约定。 |
| `harness-config.json` | 保留待接线 | 审计 Harness 预算/约束的配置来源；接入 L1/L2 前不得声称已强制执行。 |
| `fallback-decider.md` | 保留待接线 | 工具异常的降级决策来源；应由 orchestrator 决策，不应交给模型自由选择。 |
| `fc-loop-spec.md` | 编排/契约 | Agent Tool-Use 循环的设计依据；实现主体是 `framework/agent_runner.py`。 |
| `pending-issues.md` | 编排/契约 | 已知缺口与优先级台账，不作为检测或裁决输入。 |
| `qbfw_parsed.json` | 回归样例 | 解析器/条款上下文的非生产样本，禁止当成任何 DUT 的 IXIT 证据。 |
| `smoke-test-5.5.5.2-20260727.md` | 回归样例 | 5.5-5-2 的历史回归样例，禁止写进正式报告。 |
| `m6-agent-prompt.md` | 退役 | 已由 `etsi-report-auditor`、`audit-agent.md`、`contracts/audit.py` 取代；文件仅保留迁移背景，不允许新 Pipeline 引用。 |

## 独立审计 skill

| 资产 | 状态 | 消费者 / 边界 |
|---|---|---|
| `etsi-report-auditor/SKILL.md` | 编排/契约 | 定义独立对抗审计、Round 1/2 和三角对照的职责边界。 |
| `audit-checklist.md` | 已绑定 | Audit Agent 专用知识；Work Agent 的隔离检查禁止其加载。 |
| `common-errors.md` | 已绑定 | Audit Agent 专用误判模式库。 |
| `evidence-standards.md` | 已绑定 | Audit Agent 专用证据充分性与索引要求。 |
| `audit-output-schema.json` | 编排/契约 | `contracts/audit.py` 和 L2 结果解析必须保持兼容。 |
| `pipeline-output-format.md` | 保留待接线 | 历史输出格式参考；若与 `contracts/audit.py` 冲突，以后者为准，接入前先做 schema diff。 |

## exploit skill 的处理结论

本项目的 ETSI Pipeline 不自动加载 `exploit/SKILL.md`，也不因发现新攻击面自动扩大
测试。该 skill 的高自主、链式利用和后渗透规则不适合认证流水线的固定条款边界。

| 资产 | 状态 | 消费者 / 边界 |
|---|---|---|
| `web-logic-auth.md` | 已有受限绑定 | 仅 M2 认证/会话相关条款；不扩展为通用攻击链。 |
| `web-sqli.md` | 已有受限绑定 | 仅 M5 的 5.13-1，且由现有 recipe、授权范围和安全策略约束。 |
| `web-xss.md`、`web-rce.md`、`web-traversal.md` | 已有受限绑定 | 当前 M5 ammo 的既有依赖；不得新增利用目标或后渗透动作。 |
| `web-upload.md`、`web-deser.md`、`web-ssrf-misc.md`、`web-xxe.md` | 排除 | 当前 ETSI 条款 Catalog 无明确自动化绑定；需用户单独授权后才可设计接线。 |
| `web-leak.md`、`web-modern-protocols.md`、`web-deployment-security.md` | 排除 | 不自动扩展认证测试范围；可作为人工专项测试资料保留。 |
| `testing-methodology.md`、`lessons.md`、`GAP-ANALYSIS.md` | 编排/参考 | 可用于设计审查与回归复盘，不进入运行时 Prompt。 |
| `exploit/SKILL.md` | 排除 | 不能作为 ETSI Work Agent 的主 persona 或自动推进策略。 |

## 立即接线与后续验收

本次已接通：能力矩阵的 Work 公共加载，以及 `knowledge_additions` 的受限解析；M1、M2、M3、M4、M5 的相关 Phase 已各自挂载 VM、前端加密或 pcap 查询资料。

后续每一个条款必须完成以下检查才能标为“能力已落地”：

```text
clause-reference 测试策略
→ capability-matrix 已准许的工具/前提
→ Phase 工具白名单与 ToolRegistry 实际可调用
→ IXIT 多表输入 + 原始工具产物
→ evidence 可索引指针
→ verdict-criteria 的 PASS/FAIL/UNCERTAIN 条件
→ Audit 独立三角对照
```
