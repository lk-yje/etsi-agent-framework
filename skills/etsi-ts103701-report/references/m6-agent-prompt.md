# M6 审计 Agent 派发说明

> **状态：已退役，仅保留作历史迁移参考。** 当前框架不再派发名为 M6 的
> Agent；`etsi-report-auditor` skill、`pipelines/etsi/personas/audit-agent.md` 与
> `contracts/audit.py` 共同定义独立审计 Agent 的输入、输出和闸门行为。
> 新增或修改 Pipeline 审计逻辑时不得再引用本文件。

> 主线程用此文件派发 M6。M6 的完整审计方法论在 `etsi-report-auditor` skill 中，本文件仅负责派发。

---

## 主线程派发方式

M6 与 M1-M5 同批派发（阶段 3.2，一条消息 6 个 `Agent` 调用，`run_in_background: true`）。

```
Agent(
  subagent_type: "general-purpose",
  description: "M6 audit",
  prompt: <按下方的 Prompt 模板填入 {placeholder} 后派发>,
  run_in_background: true
)
```

> 用 `Agent` 工具而非 `Skill` 工具——`Skill` 会把 auditor SKILL.md 加载到主线程上下文，利益不隔离。

### 主线程注入参数

主线程派发前从 `harness-config.json` 提取本模块的 guard 数值：

| 占位符 | 来源 | 用途 |
|--------|------|------|
| `{max_llm_rounds}` | `modules.{module_id}.guard.maxLlmRounds` | Step 1 轮次预算 |
| `{timeout_minutes}` | `modules.{module_id}.guard.timeoutMinutes` | 超时参考 |

---

## M6 Prompt 模板

主线程填入 `{placeholder}` 后作为 `Agent` 的 `prompt` 参数：

```markdown
## 第一件事

**立即 Read `${DIR.SKILLS}\etsi-report-auditor\SKILL.md`**。那是你的完整执行手册——身份、铁律、审计流程、三角对照法、误判模式、输出格式都在里面。读完之前不做任何判断。

随后加载：
- `${DIR.SKILLS}\etsi-report-auditor\references\evidence-standards.md`
- `${DIR.SKILLS}\etsi-report-auditor\references\common-errors.md`
- `${DIR.SKILLS}\etsi-report-auditor\references\audit-checklist.md`
- `${DIR.SKILLS}\etsi-report-auditor\references\audit-output-schema.json`

以上全部来自 `etsi-report-auditor` skill。不要加载 verdict-criteria.md（那是 work-agent 的裁决速查表）。

{tool_paths}

## 输入

- 模块 ID: `{module_id}`
- Pre-Evidence JSON: `{pre_evidence_json_path}`
- IXIT JSON: `{ixit_json_path}`
- 派发次数: `{retry_count}`
- 上一轮 audit-result JSON: `{prev_audit_result_json_path}` (retry_count > 0 时)
- Harness 轮次上限: `{max_llm_rounds}`

## 条款清单

```
{clause_table}
```

## 执行

按 auditor/SKILL.md 的 4 步执行（Harness → 三角对照 → Frame 索引 → 误判扫描）。`stepAudit` 字段如实填写每一步的执行状态。

## 输出

写入 `{workspace_path}/audit-result_{module_id}.json` (纯 JSON，格式见 audit-output-schema.json)。

## 约束

- retestInstruction 只写维度缺口，不写工具/参数/审计依据
- retry_count = 2 且仍有缺口 → FLAGGED
- harnessReport.issues 非空 → 直接 FLAGGED
```

---

## Round 2 派发

全部 M1-M5 GOOD 后，主线程单独派发 M6 Round 2：

```
Agent(
  subagent_type: "general-purpose",
  description: "M6 audit round2",
  prompt: <按下方的 Round 2 Prompt 模板填入>,
  run_in_background: true
)
```

```markdown
## 第一件事

**立即 Read `${DIR.SKILLS}\etsi-report-auditor\SKILL.md`**。

## 身份

M6 对抗性审计 agent — Round 2 跨模块模式。找出不同模块 evidence 之间的矛盾。

## 输入

- 工作区: `{workspace_path}` (含全部 evidence JSON: M0 + M1~M5)
- IXIT JSON: `{ixit_json_path}`

## 执行

1. 加载全部 evidence JSON 的 `clauses[]`
2. 逐对跨模块检查: M2↔M3 (加密一致性) / M1↔M3 (端口-TLS) / M4↔M5 (更新链路) / M0↔M1~M5 (疑点闭环)
3. 继承链一致性: 5.5-1 → 5.8-1/5.8-2
4. 裁决: GOOD (无矛盾) / NEEDS (有矛盾，给出 analysis + recommendation)

## 输出

写入 `{workspace_path}/audit-result_round2.json` (纯 JSON)。
```

---

## 主线程反橡皮图章检查清单

收到 M6 的 audit-result JSON 后，先检查再接受：

```
□ stepAudit.step1_harness == "EXECUTED"?
□ stepAudit.step2_triangulation == "EXECUTED"?
□ stepAudit.step3_frame_indexability == "EXECUTED"?
□ stepAudit.step4_misjudgment_scan == "EXECUTED"?
□ stepAudit.totalClausesAudited == 模块条款总数?
□ audit.result 是 GOOD/NEEDS/FLAGGED 三选一?
```

**任一不满足 → 审计无效，丢弃，重新派发 M6。**
