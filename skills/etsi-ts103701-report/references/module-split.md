# 模块切分方案（阶段 3 并行执行）

> 阶段 3 把 ETSI 测试情景切成 5 个模块，主线程并行派发子 agent 执行。本文件是切分模板——下次检测直接照此派发，不用重新设计。

## 为什么切分

单线程跑时，Burp 历史搜索（~180KB）、passive_intel（~66KB）、IXIT JSON（8MB+）等原始输出全堆在主上下文，报告生成时还得反复读，撑爆上下文。切分后每个子 agent 把原始输出留在**自己**的上下文，只往工作区写一份 distilled evidence 文件 + 回传简短摘要，主线程最后只读 evidence 汇总。

## 主线程职责

按 SKILL.md §阶段 3 的门控流程执行（此处仅列阶段 3 相关的 agent 派发与审计，完整步骤见 SKILL.md）：

1. 阶段 1：建工作区、解析 ICS/IXIT 为 JSON
2. 阶段 2：写 `pre-M0-evidence-x0.json` (ICS 验证) → L1 脚本 → **M0 必须审计通过 (audit.result=GOOD) 拿到 `.audit_M0_ACCEPTED` 令牌，方可派发 M1-M5**
3. **阶段 2.5：M4 IXIT 预处理** — `python scripts/preprocess_m4_ixit.py <ixit.json> <工作区>/m4_preprocessed.json`
4. 阶段 3.1：启动 tshark + xray → 用户流量采集 → 等用户确认「完成」
5. 阶段 3.2：停 xray → 停 tshark（拿到完整 pcap）→ 权限预授权 → **并行派发 M1–M5 Work Agent**（M4 额外传 `m4_preprocessed.json`）。
6. 阶段 3.3：**审计队列 Round 1**（见下方 §审计编排）— Mx Work Agent 写完 `pre-evidence_Mx_*.json` (status=pending_audit) → 主线程跑 L1 → L1 PASS → 调度独立 Audit Agent → 输出 `audit-result_Mx.json` → `result: ACCEPT` 后签发令牌；`result: REJECT` 则重新派发 Work Agent 补齐。
7. 阶段 3.4：**跨模块审计 Round 2** — 全部 Mx 的 Round 1 `audit.result=ACCEPT` 后，调用独立 Audit Agent 的 Round 2 模式，输入全部 evidence JSON，检查跨模块矛盾 + 继承链一致性，输出 `audit-result_round2.json`。
8. **阶段 4 硬闸门**：`python scripts/pipeline_phase_gate.py <工作区>` — exit 0 方可进入阶段 4 汇总报告。exit 1 则打印缺失清单，禁止进入阶段 4。

## 5 模块划分

| 模块 | 覆盖条款 | 数据来源 | 主要工具 |
|------|---------|---------|---------|
| **M1 攻击面与端口** | 5.5-2, 5.5-4, 5.5-5, 5.6-1, 5.6-2, 5.6-3, 5.6-4, 5.6-5, 5.6-6, 5.6-7, 5.6-8, 5.6-9 | nmap 结果 + IXIT 15-Intf/13-SoftServ/16-CodeMin/17-PrivlCtrl/18-AccCtrl/19-SecDev | 读文件 + curl 未认证探测 |
| **M2 认证与口令** | 5.1-1~5.1-5 | IXIT 1-AuthMech + 前端加密采集结果 | curl + Burp MCP + playwright MCP |
| **M3 通信加密** | 5.5-1, 5.5-3, 5.5-6, 5.5-7, 5.5-8, 5.8-1, 5.8-2 | TLS 扫描结果 + IXIT 11-ComMech/6-SoftComp + M2 前端加密结果 | tshark + Burp MCP |
| **M4 更新与完整性（功能性执行面）** | 5.3-1, 5.3-2, 5.3-6, 5.3-10, 5.3-13~5.3-16, 5.4-1~5.4-3, 5.7-1, 5.7-2 | IXIT 6/7/8/10 + Burp HTTP/WS history（5.3-2 固件上传流量） | IXIT 分析 + Burp MCP |
| **M5 输入验证与数据保护** | 5.2-1, 5.2-2, 5.2-3, 5.13-1, 5.8-3, 5.9-1, 5.9-2, 5.9-3, 5.10, 5.11-1~4, 5.12-1~3, 6-1~6-5 | IXIT + 注入探针 | sqlmap_bridge_run/sqlmap_batch_run/sqlmap_bypass_retry/dir_brute_force.py/curl |

> 划分依据：按 ETSI 测试情景聚类。

> 执行面边界：上表的 M1–M5 是功能性执行面，对应 QBFW 中含“功能性”测试案例的 47 条。其余 21 条映射由 M0 概念性执行面处理，不能因 recipe 中列有 Burp 工具而被当成已实际调用的功能测试。特别是 5.3-3、5.3-4、5.3-5、5.3-7、5.3-8、5.3-9、5.3-11、5.3-12 均属于 M0 概念性测试；其中的 Burp/Playwright 描述是辅助取证条件，不是 M4 Work Agent 的调用授权。

---

## 审计编排

Audit Agent 由 L2AuditGate 在每个模块 L1 通过后调度。每个 Mx Work Agent 写完 pre-evidence JSON → 主线程跑 L1 → L1 PASS → 将路径交给 Audit Agent → 等待结构化审计结果。

### 管线状态跃迁

> **核心设计决策**：审计不是主线程内联操作，而是由 **独立 Audit Agent** 执行。主线程只做 L1 机械化验证 + 调度与消费审计结论。Audit Agent 不通过 → 禁止进入下一阶段；其内部方法（三角对照、误判扫描等）对 Work Agent 不可见。

```
pre-evidence_Mx_*.json (status=pending_audit)     ← Mx agent 产出
         │
         ▼  validate_evidence.py (L1)
         │
    ┌────┼────────────────────┐
    │ L1 PASS                │ L1 FAIL → 重派 work-agent (不计派发次数)
    ▼                         │
  主线程传 evidence 路径给 Audit Agent │
  → audit-result_Mx.json     │
    │                         │
    ├── result: GOOD ─────────────────────────────────┐
    │   → meta.status 改写为 accepted                │
    │   → 文件重命名: pre-evidence → evidence         │
    │   → evidence_to_md.py 生成 MD                   │
    │   → touch .audit_Mx_ACCEPTED 令牌               │
    │   → 标记 confirmed，等待全部 GOOD 后 Round 2    │
    │                                                  │
    ├── result: NEEDS ──────────────────────────────┐  │
    │   → 派发次数 < 2?                             │  │
    │     YES: 从 audit-result JSON 提取             │  │
    │          retestInstruction(仅维度)——           │  │
    │          重新派发全新 work-agent，派发次数++    │  │
    │     NO: → FLAGGED → 主线程最终裁定            │  │
    │                                                │  │
    └── FLAGGED → 主线程最终裁定                    │  │
                                                     │  │
  全部 Mx audit.result=GOOD ───────────────────────┘  │
         │                                              │
         ▼                                              │
  Round 2: 调度 Audit Agent (round2 模式)               │
  → audit-result_round2.json                            │
         │                                              │
         ▼                                              │
   pipeline_phase_gate.py <workspace>                  │
    exit 0 → 阶段 4 生成报告                             │
    exit 1 → 打印缺失清单，禁止进入                       │
```

### 队列驱动逻辑 (主线程执行)

> **角色边界**：主线程 = L1 机械化验证 + 调度/管理 Agent + 消费结构化审计结论。Audit Agent = 独立审计（内部方法对 Work Agent 不可见，主线程只消费其 ACCEPT/REJECT/FLAGGED 结论）。主线程不参与实质审计判断。

```
while 有待审计的 Mx:

    Mx work-agent 完成通知到达 → 主线程确认 pre-evidence_Mx_*.json 存在
         │
         ▼
    Step A: L1 机械化验证
    ┌──────────────────────────────────────────────────┐
    │ python scripts/validate_evidence.py               │
    │        pre-evidence_Mx_*.json                     │
    │                                                    │
    │ exit 0 → 打印条款摘要表 → 进入 Step B               │
    │ exit 1 → 打印逐条错误 → 注入修正清单 → 重派 work-agent │
    └──────────────────────────────────────────────────┘
         │
    ┌────┼────────────────────┐
    │ L1 PASS                │ L1 FAIL → 重派 work-agent (不计派发次数)
    ▼                        │
  Step B: 主线程把 evidence 文件路径交给独立 Audit Agent，等待结构化审计结果
  输入: pre-evidence JSON 路径 + IXIT JSON 路径 + module_id + retry_count (+ 上一轮 audit-result JSON)
  输出: audit-result_Mx.json (按 audit-output-schema.json)
  调用方式: L2AuditGate 调度 Audit Agent；审计 persona、知识与输出契约由 etsi-report-auditor skill 定义
    │
    ├── result: GOOD →
    │     主线程校验审计输出 schema 与 required stepAudit 字段 →
    │     通过后: python 改写 status=accepted → 重命名为 evidence_Mx_*.json → evidence_to_md.py → touch 令牌
    │
    ├── result: NEEDS →
    │     派发次数 < 2?
    │     YES: 从 audit-result JSON 取 retestInstruction (仅维度缺口，不含审计依据)
    │          重新派发全新 work-agent (见下方 §审计 NEEDS 补证)，派发次数++
    │     NO: → FLAGGED → 主线程最终裁定
    │
    └── FLAGGED → 主线程最终裁定
```

**FLAGGED 处置**：审计 agent 在以下情况输出 FLAGGED：
- NEEDS 重派已达 2 次上限，仍有缺口
- harnessReport.issues 非空（Harness 违规）

主线程收到 FLAGGED 后：
1. 依据现有知识（IXIT、其他模块 evidence、标准原文）做出判断
2. 该模块 evidence 直接接受（status → accepted），不阻断管线
3. 在最终报告中对该模块标注 `[需用户分析]`，附审计 findings 和主线程判断理由，由用户最终确认

> FLAGGED 不阻断阶段闸门。该模块令牌正常发行，pipeline_phase_gate.py 不因 FLAGGED 而 exit 1。

### L1 修正：主线程将错误清单转为修正指令

L1 脚本 (`validate_evidence.py`) 的逐条错误已经精确到条款号+缺失字段：

```
X L1 FAILED — 5 个错误:
  - X 条款数不对: selfCheck.totalExpected=17, selfCheck.actualInJson=15, clauses 数组实际长度=15
  - X 缺失条款 (2 条): ['5.6-3', '5.6-4']
  - X 5.5-1: verdict=FAIL 但缺少 expectedBehavior
  - X 5.4-1: verdict=PENDING_MANUAL 但 manualSteps 为空
  - X executionTrace 未覆盖条款 (2 条): ['5.6-3', '5.6-4'] — 这些条款无执行轨迹支撑 (Harness 违规)

 修正以上错误后重新运行 L1 验证。Harness/L1 违规不计入派发次数。
```

主线程把这些错误原样注入新派发 work-agent 的「修正清单」区域，work-agent 逐条执行。不需要人工解读——错误本身已经是操作指令。L1 修正也只给『错在哪』，不给审计原因。

### 审计 NEEDS 补证：只传维度缺口，重新派发全新 work-agent

审计 agent 输出 `result: NEEDS` 时，`audit-result_Mx.json` 含 `retestInstruction`（targetClauseIds + requiredDimensions）。主线程据此**重新派发一个全新的 work-agent**（同一模板），指令只到『补什么维度』：

```markdown
## 主线程补充任务

以下条款需要补充/重新核实（来自质量复查，不提供原因）：

- {retestInstruction.requiredDimensions 逐条列出}

### 执行要求
1. **仅处理 targetClauseIds 中列出的条款**。其余条款维持原 evidence JSON 的裁决，不要重新测试。
2. 需要哪个工具、什么参数，**自己查询** capability-matrix.md / clause-reference.md 决定。
3. 补齐后在 evidence JSON 对应 clause 追加:
   ```json
   "retryHistory": [{ "retryCount": {N}, "memo": "{补充了什么维度/数据}", "changesMade": "{具体做了什么}" }]
   ```
4. 若该维度确实无法在本环境执行（工具不可用/数据缺失），该条款标 INCONCLUSIVE 并在 reason 中说明。
5. 其他输入参数（工作区、DUT IP、IXIT JSON、已有产物）不变。
6. 输出覆盖原 `pre-evidence_Mx_*.json`，meta.retryCount 设为 {N}，meta.status 保持 `pending_audit`。

### 原始输入 (不变)
- 工作区: {workspace_path}
- DUT IP: {dut_ip}
- IXIT JSON: {workspace_path}/ixit.json
- ... (其余同首次派发)
```

**补充派发关键约束**：
- 被补充派发的 work-agent 是**全新派发**（非 resume 原 agent），独立上下文，**不感知审计存在**
- work-agent **只处理被指出的条款**，不重测已通过的
- `retryCount` 由主线程追踪，写入 evidence JSON 的 `meta.retryCount`
- **Harness 违规** (L1 修正、trace 缺失) → 不计入派发次数，agent 没完成契约不能靠补充派发弥补
- **审计 NEEDS** → 计入派发次数，最多 2 次，超过 → FLAGGED
- **隔离铁律**：传给 work-agent 的只有 `retestInstruction.requiredDimensions`（补什么维度）。工具/参数由 work-agent 自己查 capability-matrix.md / clause-reference.md。绝不传审计依据、审计标准、findings。

### 审计 agent 的『已补证』再查

审计 agent 在 `retryCount > 0` 时：
- 仅审查 `clauses[]` 中有 `retryHistory` 的条款 + 验证上次 `retestInstruction.requiredDimensions` 是否已补齐
- 未补齐 → 再次 `result: NEEDS`（派发次数递增）
- 已补齐且裁决成立 → `result: GOOD`

审计 agent 输入含: pre-evidence JSON (当前) + 上一轮 audit-result JSON (如有)。
详见 `etsi-report-auditor/SKILL.md`、`audit-output-schema.json` 与 `pipeline-output-format.md`。

### Round 2: 跨模块一致性审计

全部 Mx 的 Round 1 audit.result = ACCEPT 后，主线程调用独立 Audit Agent 的 Round 2 跨模块审计模式：

```markdown
## 模式: Pipeline — Round 2 跨模块审计

输入:
- 工作区: {workspace_path} (含全部 evidence JSON: M0 + M1~M5)
- IXIT JSON: {ixit_json_path}

执行:
1. 加载全部 evidence JSON
2. 逐对检查跨模块矛盾:
   - M2 (认证加密) ↔ M3 (通信加密)
   - M1 (端口) ↔ M3 (TLS)
   - M4 (固件签名) ↔ M5 (更新流量)
   - M0 (ICS 疑点) ↔ M1~M5 (疑点闭环)
3. 继承链一致性:
   - 5.5-1 → 5.8-1, 5.8-2
4. 输出: audit-result_round2.json (result: GOOD / NEEDS)
```

**Round 2 NEEDS 的处置流程**：矛盾涉及多个模块，无法自动补证。审计 agent 在 `audit-result_round2.json` 中对每个矛盾给出专业判断（整合分析 + 判断理由 + 建议以哪方为准），主线程将矛盾清单连同审计师建议一并呈现给用户。用户仅做最终裁定（确认或调整建议），主线程据此调整最终报告。

---

## 子 agent 输入契约（每个子 agent 都需要）

派发时给每个子 agent 传：
- **工作区路径**（Git Bash 路径，如 `${DIR.WORKSPACE}/<时间戳>/`）
- **目标 DUT IP**
- **IXIT JSON 路径**（工作区内，用 python 按需提取 sheet，勿整体读入 8MB 文件）
- **认证会话**（Cookie + SessionTag，若已登录）
- **已有产物**（工作区内 nmap/TLS 等文件，避免重复扫描）
- **它负责的条款范围**
- **关键已知事实**（主线程已探测的结论，避免子 agent 重复劳动）

## 子 agent 输出契约

每个子 agent 产出 **一份文件**：

### 结构化 JSON — `pre-evidence_Mx_<name>.json`

按 [evidence-schema.json](evidence-schema.json) 的 schema 写出。这是**强制且唯一**的输出——agent **不写 MD**。MD 在审计 GOOD 后由 `evidence_to_md.py` 脚本确定性生成。

JSON 的核心价值：
- **L1 验证从 LLM 操作降级为脚本执行** — 主线程在审计队列中跑 `python validate_evidence.py pre-evidence_M1_*.json`，秒出对账结果
- **审计 agent 统一消费** — 所有 Mx 使用同一 schema，审计 agent 不做格式适配
- **跨模块依赖解析** — M3 需要 M2 的条款结论时，直接 `jq '.clauses[] | select(.clauseId=="5.1-3")' pre-evidence_M2_*.json`
- **MD 确定性生成** — evidence_to_md.py 从 accepted JSON 生成格式统一的 markdown

###  JSON 内联示例（agent 照此格式输出）

以下是 `clauses` 数组中**一条完整的条款记录**。agent 按此结构填写每个条款：

```json
{
  "clauseId": "5.6-1",
  "provisionText": "All network and logical interfaces shall be documented in IXIT 15-Intf",
  "icsStatus": "M",
  "icsSupport": "Y",
  "icsDetail": "IXIT 15-Intf 仅登记 Intf-SSH 22 一条接口。IXIT 13-SoftServ 定义了 11 个软件服务。",
  "verdict": "FAIL",
  "reason": "IXIT 15-Intf 仅登记 1 条接口，但 nmap 发现 5 个开放端口 (80/443/554/8000/8443)。标准要求所有网络和逻辑接口均应记录在 15-Intf 中，与 13-SoftServ 形成交叉引用。实测端口与 IXIT 登记严重不一致 → FAIL。",
  "expectedBehavior": "IXIT 15-Intf 应列出所有网络接口（含端口、类型、默认状态），与 nmap 实测结果一致",
  "actualBehavior": "IXIT 15-Intf 仅登记 Intf-SSH 22 (Disabled)，缺失 5 个开放端口的接口登记",
  "evidence": [
    {
      "type": "nmap",
      "path": "nmap_tcp.txt",
      "level": "L1",
      "description": "nmap -sS -sV --top-ports 2000 10.19.199.26: 开放端口 80/443/554/8000/8443",
      "expectedVsActual": "预期: 15-Intf 登记全部开放端口 | 实际: 15-Intf 仅登记 SSH 22"
    },
    {
      "type": "ixit",
      "path": null,
      "level": "L3",
      "description": "IXIT 15-Intf: 仅 Intf-SSH 22 一条 (Disabled by default, Network+Logic, Debug)"
    }
  ],
  "ixitReferences": ["15-Intf", "13-SoftServ"],
  "tags": ["all-conditions"],
  "warnings": ["IXIT 13-SoftServ 与 15-Intf 之间存在交叉引用缺口"],
  "manualSteps": null,
  "retryHistory": []
}
```

> 警告: **关键规则**：
> - `verdict` 是**单一综合裁决** (PASS/FAIL/NA/INCONCLUSIVE/PENDING_MANUAL)，不是三个分离的裁决
> - `reason` 承载**完整推理链**：概念分析 (IXIT 是否逻辑自洽) + 功能验证 (实际测试)
> - `expectedBehavior` + `actualBehavior` 仅在 verdict=FAIL 时填写
> - `manualSteps` 仅在 verdict=PENDING_MANUAL 时填写
> - `evidence[].level` 每条必标 L1-L5。L4/L5 → L1 脚本直接打回
> - `evidence[].description` 必须含 frame 编号 / Burp 请求序号 / 命令+参数 — 第三者可直接索引
> - `retryHistory` 首次执行时为空数组 `[]`

### 回传**简短摘要**（≤300 字）

每条款裁决 + 一句话理由 + evidence 路径。不要回传大段日志/工具输出。

### **原始工具输出重定向写入工作区文件**

（如 `sqlmap_output.txt`、`fuzz_dir_*.json`），不回传大段输出。

---

### evidence 文件自检表（每条 evidence 末尾强制包含）

```markdown
## 自检清单

| 条款 | 概念性裁决 | 功能性裁决 | 状态 |
|------|:---------:|:---------:|:----:|
| 5.X-1 | PASS/FAIL/NA/UNCERTAIN | PASS/FAIL/NA/INCONCLUSIVE | OK / WARN / FAIL |
| ... | ... | ... | ... |

> 本模块共 N 条款，已裁决 N 条，遗漏 0 条。
> 警告: 需用户确认: [列出 UNCERTAIN 条目及具体疑问]
```

**状态说明：**
- OK = 两条均有裁决（含 NA），可交付
- WARN = 有 UNCERTAIN，需用户介入
- FAIL = 缺失裁决，不可交付

agent 写完 evidence 后自检：条款数是否对、每个是否至少一项裁决——少一项就不算完成，不得回传摘要。**JSON 的 `selfCheck` 是机器消费版本 —— 两者的条款数、裁决数必须一致。**

## evidence 文件命名与通行令牌

Mx work-agent 产出 **pre-Mx-evidence-xN.json** (N=派发代数)。审计 `result: GOOD` 后主线程发**通行令牌** (`.audit_Mx_ACCEPTED`) + 改写为最终 evidence JSON + 生成 MD。

### 文件生命周期

| 阶段 | 文件名 | 令牌 | status |
|------|--------|:--:|--------|
| agent 首次完成 | `pre-M1-evidence-x0.json` | — | `pending_audit` |
| 第1次补充派发 | `pre-M1-evidence-x1.json` | — | `pending_audit` |
| 审计 GOOD → JSON | `evidence_M1_attack_surface.json` | `.audit_M1_ACCEPTED` | `accepted` |
| 审计 GOOD → MD | `evidence_M1_attack_surface.md` | — | — |

### 通行令牌清单与阻断点

| 令牌 | 阻断什么 | 发行时机 |
|------|---------|---------|
| `.audit_M0_ACCEPTED` | [阻断] 禁止派发 M1-M5 | Phase 2 结束，M0 审计 GOOD |
| `.audit_M1_ACCEPTED` | — | Phase 3.3，M1 审计 GOOD |
| `.audit_M2_ACCEPTED` | — | Phase 3.3，M2 审计 GOOD |
| `.audit_M3_ACCEPTED` | — | Phase 3.3，M3 审计 GOOD |
| `.audit_M4_ACCEPTED` | — | Phase 3.3，M4 审计 GOOD |
| `.audit_M5_ACCEPTED` | — | Phase 3.3，M5 审计 GOOD |
| `.audit_ROUND2_ACCEPTED` | [阻断] 禁止进入 Phase 4 | Phase 3.4 结束，Round 2 GOOD |

> M1-M5 审计全部 GOOD 后才触发 Round 2。Round 2 GOOD 后才 touch `.audit_ROUND2_ACCEPTED`。
> [阻断] **Phase 4 硬闸门**：`pipeline_phase_gate.py` 检查全部 7 枚令牌，缺任意一枚 → exit 1 → 禁止进入阶段 4。

### 各模块文件名

| 模块 | 首次产出 | GOOD 后 |
|------|---------|-----------|
| M0 | `pre-M0-evidence-x0.json` | `evidence_M0_ics_validation.json` |
| M1 | `pre-M1-evidence-x0.json` | `evidence_M1_attack_surface.json` |
| M2 | `pre-M2-evidence-x0.json` | `evidence_M2_auth_password.json` |
| M3 | `pre-M3-evidence-x0.json` | `evidence_M3_comm_crypto.json` |
| M4 | `pre-M4-evidence-x0.json` | `evidence_M4_update_integrity.json` |
| M5 | `pre-M5-evidence-x0.json` | `evidence_M5_input_dataprotection.json` |

## 跨 Agent 数据传递

并行派发下，若 Agent A 的某条款依赖 Agent B 的 evidence 产出，按以下通用范式处理：

**前提：** 按输出契约，每个 agent 写完 evidence JSON + markdown + 自检表才回传摘要，因此 evidence 文件落盘 = 产出方已收工，文件内容完整，不存在半成品。

**处理范式：**

1. **先跑不依赖的部分** — Agent A 先执行所有不依赖 B 的条款
2. **不依赖条款全部完成后，Bash 轮询 B 的 evidence JSON：**

   ```bash
   for i in 1 2 3 4 5 6; do
     if [ -s "{workspace_path}/evidence_M{B}_*.json" ]; then
       # JSON 存在 → L1 对账
       python -c "
   import json, sys
   with open('{workspace_path}/evidence_M{B}_*.json') as f:
       d = json.load(f)
   sc = d['selfCheck']
   ok = (sc['totalExpected'] == sc['actualInJson']
         and len(sc['missingClauses']) == 0
         and not sc['hasErrors'])
   sys.exit(0 if ok else 1)
   " && echo "READY:L1_PASS" || echo "READY:L1_FAIL"
       exit 0
     fi
     echo "attempt $i: M{B} evidence JSON not ready, waiting 30s"
     sleep 30
   done
   echo "TIMEOUT"
   exit 1
   ```

3. **分支处理：**
   - `READY:L1_PASS` → 用 python 从 JSON 提取所需字段 (`jq '.clauses[] | select(.clauseId=="5.X-X")'`)，引用完成裁决
   - `READY:L1_FAIL` → JSON 存在但 L1 不通过 → INCONCLUSIVE，理由「M{B} evidence JSON L1 验证不通过，等待主线程介入」
   - `TIMEOUT` → INCONCLUSIVE，理由「M{B} evidence JSON 超时 3 分钟未就绪」

**设计意图：** "先跑不依赖的部分"耗时 ≈ 依赖方产出 evidence 的耗时。轮询是终末缓冲，不是空转——绝大多数情况下第一次读就已就绪。

**已知依赖关系：**

| 依赖方 | 被依赖方 | 依赖内容 | 涉及条款 |
|--------|---------|---------|---------|
| M3 | M2 | 前端加密分析（登录接口是否明文/编码/哈希传输密码） | 5.5-1 |

> 派发时，主线程将存在依赖关系的 agent 的 `{pre_discovered_facts}` 中注明：「你依赖 M{B} 的 XXX 结论。先执行不依赖 M{B} 的条款，全部完成后按『跨 Agent 数据传递』范式等待并读取 M{B} evidence。」

## Burp/MCP 与 tshark 的工具分工

两者是同一套 M1-M5 多 Agent 架构里的**互补工具**，不是两套并行系统。抓同一条流量，从不同层取水，喂给不同条款：

| 工具 | 抓什么层 | 管哪些条款 | 怎么读数据 |
|------|---------|-----------|-----------|
| **Burp/MCP** | 应用层 HTTP（经浏览器代理 8080） | 5.1-5 爆破、5.5-4 未认证、5.5-5 越权、5.6-2 Banner、5.13-1 注入 | MCP 工具直接读 `proxy_history` |
| **tshark** | 传输层全协议（网卡监听，含非 HTTP） | 5.1.3.2 认证算法、5.3.2.2 固件更新、5.5.1 全协议加密、5.5.6/7 CSP 传输、5.9.3 重连 | 主线程跑 `pcap_analyzer.py` → agent 读 `pcap_analysis/` JSON/TXT |
| **sqlmap_bridge_run / sqlmap_batch_run / sqlmap_bypass_retry / dir_brute_force.py** | 应用层主动探测 | 5.13-1 输入验证（SQLi 经 MCP 桥同步跑 sqlmap + 日志四态；三工具内置认证刷新+批量升级+WAF 绕过链；路径爆破经 http_fuzz，主流程） | sqlmap_* 读桥返回 JSON（status+四态 triage+injected_parameter+payload）+ sqlmap `--output-dir` 日志 + `sqlmap/block_ledger.jsonl`（bypass 每次尝试入账）；dir_brute_force.py 读 `fuzz_dir_*.json`（hits + next_round） |

**Burp vs tshark 能力边界**：
- Burp 只抓过它代理的 HTTP/HTTPS；tshark 抓网卡全协议（RTSP/SDK/TLS 握手/重连包/设备外连）
- Burp 能发包（重放/爆破/注入）；tshark 只读不能发包
- TLS 握手细节、固件大文件、断网重连、远程外连 → 必须 tshark
- 越权重放、爆破、注入、读 HTTP 历史 → Burp/MCP 更方便

**xray 定位**：被动扫描工具，与 sqlmap/dir_brute_force.py/Burp http_fuzz 并列。主线程在阶段 3.1 启动 xray（`webscan --listen 127.0.0.1:7778 --json-output xray_report.json --html-output xray_report.html > xray_run.log 2>&1`），代理链路 `浏览器 → Burp:8080 → xray:7778 → DUT`，用户操作产生流量时 xray 被动分析。**无漏洞时仅出 log**（含端点覆盖数+探针数），**发现漏洞时额外产出 JSON/HTML 含完整 payload**。M5 agent 读 xray_run.log 做广度复核：端点数是否符合预期、探针覆盖了哪些注入类型。xray JSON/HTML 存在时附带漏洞 payload。

## 关键约束

1. **不触发认证锁定**：M2 的爆破锁定测试不能真触发（如 7 次失败锁 30 分钟会废掉其他模块的认证会话）。改为 IXIT 策略分析 + 1-2 次失败探针确认机制，完整锁定测试标 `[需手工测试]`。
2. **原始工具输出写入工作区文件，不回传**：子 agent 不把 Burp 历史、passive_intel、nmap 全输出、tshark 原始提取等大块数据回传给主线程，而是重定向写入工作区文件（如 `sqlmap_output.txt`），只写 evidence 文件 + 简短摘要。主线程核验时只确认文件存在且非空，不读入上下文。
3. **IXIT JSON 按需提取**：8MB+ 的 JSON 不整体读入，用 python 脚本按 sheet 名提取所需表格。
4. **不编造结果**：未测的写"待测试"，FAIL 必须附证据，证据路径指向工作区内文件。
5. **不破坏性操作**：注入探针用认证会话，但不真删数据/真改配置/真触发锁定。
6. **抓包通道并行**：阶段 3.1 主线程启动 tshark（后台抓包）+ xray（Python subprocess 被动扫描），Burp 代理由用户准备阶段挂好。双通道收同一条流量，互不干扰。xray 与 tshark 同为必备通道，流量采集结束后均由主线程自动停止并验证产出（capture.pcap + xray_run.log）。

## 派发模板

主线程在一条消息内放 5 个 Agent 调用（`run_in_background: true`，`subagent_type: general-purpose`），每个 agent 的 prompt 按以下模板填入参数后派发。子 agent 完成后自动通知主线程，主线程收齐 5 份 evidence 后按下方核验流程逐份检查，最后读入 6 份（M0+M1~M5）汇总。

### 主线程派发前准备

**权限预授权：** 5 个 agent 并行跑时会密集调用 Bash 和 MCP 工具。派发前一次性告知用户即将使用的工具集，让用户提前批准；若未预授权，5 个 agent 同时弹权限请求会导致批不过来。

```markdown
## 警告: 即将并行启动 5 个检测 agent，以下工具会被密集调用：

| Agent | Bash 工具 | Burp MCP 工具 | Playwright MCP 工具 |
|-------|----------|-------------|-----------------|
| M1 攻击面 | nmap, curl, netstat | sitemap_query, proxy_history, proxy_history_search, passive_intel, auth_diff | — |
| M2 认证 | curl, nmap | proxy_history, http_send_request | playwright (browser_navigate, browser_snapshot, browser_fill_form, browser_click, browser_network_requests, browser_network_request, browser_evaluate) |
| M3 通信加密 | tshark, nmap, curl | proxy_history_search | —（前端加密结果从 M2 获取） |
| M4 更新完整性 | python (preprocess_m4_ixit.py 预处理脚本，不是 M4 agent 自己读) | proxy_history, websocket_list, websocket_get_messages, burp_import_project_config (TLS降级) | playwright (browser_navigate, browser_snapshot, browser_evaluate) — 5.3-6-2 固件升级页 + 5.3-16-2 系统信息页 |
| M5 注入与数据 | dir_brute_force.py (python), curl, tshark, python (xray runner) | http_fuzz, sqlmap_bridge_run, sqlmap_batch_run, sqlmap_bypass_retry, sitemap_query, proxy_history | playwright (browser_navigate, browser_snapshot, browser_click, browser_evaluate) — 5.12-1-2 Configuration Wizard 决策检查 |

> 所有调用均为只读/探测操作，无写操作。请批准后续工具调用。
```

### Harness 注入（主线程派发前执行）

派发每个 Mx agent 前，主线程从 `references/harness-config.json` 读取该模块的 GuardConfig，用以下 python one-liner 生成 harness 约束文本，填入 prompt 中的 `{harness_constraints}` 占位符：

```bash
python -c "
import json, os
from pathlib import Path
skills_root = Path(os.environ.get('SKILLS_ROOT', 'skills'))
with (skills_root / 'etsi-ts103701-report' / 'references' / 'harness-config.json').open(encoding='utf-8') as f:
    h = json.load(f)
m = h['modules']['{module_id}']
g = m['guard']
qg = m.get('qualityGates', {})
d = h['defaults']
gates = [v for k,v in qg.items() if isinstance(v, str) and not k.startswith('description')]
print(f'''## 警告: Harness 约束 (来自 harness-config.json)

你是 **{m['name']}** 模块 agent。以下约束定义了你的行为契约：

### 资源预算
- 最大推理轮次: **{g['maxLlmRounds']}** 轮。每 {d['selfMonitoring']['roundCheckInterval']} 轮自检一次进度。超出 → 已完成的正常交付，未完成的标 INCONCLUSIVE 并注明「轮次预算不足」。
- 时间限制: **{g['timeoutMinutes']}** 分钟。

### 质量门禁 (交付前必须逐项确认)
{chr(10).join(f'{i+1}. {v}' for i, v in enumerate(gates))}

### 自监控规则
{d['selfMonitoring']['roundCheckInstruction']}

### 交付清单 (preDeliveryChecklist)
{chr(10).join(f'- [ ] {c}' for c in d['preDeliveryChecklist'])}

以上约束是你的交付契约。违反任意一条 → 本次交付无效，不计入重试宽容次数。''')
"
```

> 主线程为每个模块运行一次上述命令，将输出粘贴到对应 agent prompt 的 `{harness_constraints}` 处。

### 工具路径注入（主线程派发前执行，M1-M5 Work Agent 通用）

`${TOOL.XXX}` 占位符仅在主线程的 skill 上下文中解析。通过 `Agent` 工具派发的子 agent 收到的是字面字符串，无法定位工具。派发前主线程必须将路径解析后注入：

```bash
python -c "
import json, os
from pathlib import Path
mapping_path = os.environ.get('PATH_MAPPING')
if not mapping_path:
    raise SystemExit('PATH_MAPPING 未配置；请指向本机私有 path-mapping JSON')
with Path(mapping_path).open(encoding='utf-8') as f:
    pm = json.load(f)
p = pm['paths']
tools = [
    ('nmap', 'TOOL.NMAP'),
    ('tshark', 'TOOL.TSHARK'),
    ('sqlmap', 'TOOL.SQLMAP'),
    ('xray', 'TOOL.XRAY'),
    ('python3', 'TOOL.PYTHON3'),
]
dirs = [
    ('Skills 仓库', 'DIR.SKILLS'),
    ('工作区根', 'DIR.WORKSPACE'),
    ('固件目录', 'DIR.FIRMWARE'),
]
print('## 工具路径映射 (主线程注入)')
print()
print('| 工具 | 路径 |')
print('|------|------|')
for label, key in tools:
    print(f'| {label} | {p[key][\"windows\"]} |')
print()
print('| 目录 | 路径 |')
print('|------|------|')
for label, key in dirs:
    print(f'| {label} | {p[key][\"windows\"]} |')
"
```

> 将输出粘贴到 Work Agent prompt 的 `{tool_paths}` 处。Audit Agent 只读 evidence/IXIT，不接收工具路径注入。

### Schema 枚举注入（主线程派发前执行，M1-M5 Work Agent 通用）

Agent 经常不读 `evidence-schema.json`，自行发明枚举值（`burp_proxy`、`conceptual`、`N/A` 等），导致 L1 打回。派发前从 schema **动态提取**所有枚举约束注入 prompt，agent 无需跨文件查找。

```bash
python -c "
import json, os
from pathlib import Path
skills_root = Path(os.environ.get('SKILLS_ROOT', 'skills'))
with (skills_root / 'etsi-ts103701-report' / 'references' / 'evidence-schema.json').open(encoding='utf-8') as f:
    s = json.load(f)

# 从 schema 动态提取（非手写，schema 更新时自动同步）
clause = s['properties']['clauses']['items']['properties']
evidence_item = clause['evidence']['items']['properties']

types = evidence_item['type']['enum']
tags = clause['tags']['items']['enum']
verdicts = clause['verdict']['enum']
levels = evidence_item['level']['enum']
support = clause['icsSupport']['enum']

print(f'''## ⚠️ JSON 字段约束 (动态提取自 evidence-schema.json，违反任一 → L1 打回)

| 字段 | 合法值 |
|------|--------|
| evidence[].type | {' | '.join(types)} |
| tags[] | {' | '.join(tags)} |
| verdict | {' | '.join(verdicts)} |
| icsSupport | {' | '.join(support)} |
| evidence[].level | {' | '.join(levels)} |
| meta.status | pending_audit (agent 永远写此值，禁止 completed/done) |

### executionTrace.steps[] 必须为对象
每步含 seq(整数) + phase(preflight|tool_call|reasoning|pivot|self_check|delivery) + summary(字符串)。
**禁止写裸字符串。** 无 preflight 步骤 → Harness 违规 → 直接 FLAGGED。

### FAIL 条款强制字段
expectedBehavior + actualBehavior 缺一不可。
evidence[] 中每条 FAIL 必须含 expectedVsActual。

### 交付前必须运行 preflight (见下方 §输出) — exit 1 不得回传。
''')
"
```

> 将输出粘贴到 agent prompt 的 `{schema_enums}` 处。与 harness_constraints / tool_paths 并列，三者均在派发前注入。

### Agent prompt 模板

```markdown
##  唯一任务

**你的唯一任务：在 evidence 模板上填写测试结果。不要分析管线状态、不要总结审计结论、不要做任何与写 evidence JSON 无关的事。**

### 模板文件

主线程已用 `generate_evidence_template.py` 生成了模板：`{template_json_path}`。**你必须在这个文件上编辑，不要从零创建 JSON。** 模板中 meta/selfCheck/executionTrace 骨架和所有枚举值已预填正确 —— 你只需：

1. 读入模板 JSON
2. 逐条款填写 `verdict` / `reason` / `evidence[]` / `expectedBehavior` / `actualBehavior` / `manualSteps` / `ixitReferences` / `tags`
3. 追加 `executionTrace.steps[]`
4. 更新 `selfCheck` 反映实际裁决
5. 写回同名文件（或 retry 时改名 x0→x1→x2）

>  ⚠️ **禁止修改已预填的字段名和枚举值。** meta.* / icsSupport / evidence[].type / evidence[].level 已正确，改动它们 = L1 打回。

{harness_constraints}

{tool_paths}

{schema_enums}

## 角色
你是 ETSI TS 103701 认证检测的 **{Mx 模块名}** 执行 agent。你的上下文独立于其他 agent，原始工具输出留你自己这里，只往工作区写 distilled evidence。

## 前置准备（开始测试前必须完成）

**1. 弹药库加载（涉及注入/攻击类测试的模块强制）：**
{exploit_loading_instructions}
> 路径: `${DIR.SKILLS}\exploit\references\<file>.md`
> 这是硬约束——不加载弹药库不得发送任何注入 payload。加载后用 `[ref: file.md §X]` 标记 payload 来源。

**2. 抓包通道确认（涉及传输层分析的模块强制）：**
{tshark_verification}
> 若 pcap 不存在或为空（<1KB），不要开始测试——在主线程消息中报告「capture.pcap 不可用，等待主线程启动 tshark」。

**3. Burp 代理确认（涉及 HTTP 测试的模块强制）：**
{burp_verification}
> 调用 `mcp__burp__proxy_history` (limit=1) 确认 MCP 通道正常。若失败，报告主线程。

**4. Playwright MCP 确认（M2 前端 JS 分析强制）：**
{playwright_verification}
> 调用 `mcp__playwright__browser_tabs` (action=list) 确认浏览器可控。若不可用 → `report_to_main`（暂停主流程，playwright 就绪前不裁决 5.1-3/5.5-1 及所有依赖 playwright 的条款）。禁止降级为 Burp 密文格式分析或手工 DevTools 替代。

**5. 错误知识库加载（全部模块强制）：**
Read `${DIR.SKILLS}\etsi-ts103701-report\references\tool-error-kb.json` — 一次性加载到上下文。你的 FC-Loop 执行过程中，工具调用失败时按 [fallback-decider.md](fallback-decider.md) 的决策流程处理：识别签名 → 查 KB → 执行决策 → 记录 pivot 到 executionTrace。禁止不做错误分析直接重试，禁止重试超过 2 次。

**6. FC-Loop 规范（全部模块强制）：**
你的执行遵循 [fc-loop-spec.md](fc-loop-spec.md)：PREFLIGHT → WORK (round-by-round) → DELIVERY。每轮追加 executionTrace.steps。按 harness 约束中的 roundCheckInterval 执行 self_check。停滞检测 + 降级决策 + 交付条件均见该规范。

**7. 认证预检门禁（M5 强制，M2 按需）：**
{auth_precheck_gate}
> 此门禁针对 **http_fuzz / dir_brute_force.py**（sqlmap 三工具已内置自动刷新：`auth_refresh=true` 时 401/403 信号触发 proxy_latest_auth 重取头 → 重写 .req → 重跑，无需手工预检）。http_fuzz 在认证过期时不会报错（路径全 404/空，hits=0），静默产出假阴性。调用前必须执行预检，auth_ok=false 时禁止继续。

## 输入
- 工作区: {workspace_path}
- DUT IP: {dut_ip}
- IXIT JSON: {workspace_path}/ixit.json（用 python 按 sheet 名提取，勿整体读入 8MB 文件）
- 认证会话: {cookie_session_or_"无"}
- 已有产物: {workspace_path}/nmap_tcp.txt, {workspace_path}/nmap_udp.txt
- 已知事实: {pre_discovered_facts}
- 跨 agent 依赖: {cross_agent_dependency}

## 你的条款
{clause_table_with_provision_text_and_test_methods}

## 每条执行两步骤

**步骤 1 — 概念性测试 (X.X.X.1):**
1. 从 IXIT JSON 提取本条款相关字段
2. 按 [clause-reference.md §概念性测试通用判定框架](clause-reference.md) 的三问法判定：逻辑自洽？内部矛盾？信息充足？
3. 裁决: PASS / FAIL / UNCERTAIN
4. UNCERTAIN 必须写出具体缺失信息 + 用户需确认的具体问题
5. 记录 IXIT 引用（哪个 sheet 哪行）
6. 若条款属于"不需要单独做概念性测试"的情况，直接标 NA 并注明理由

**步骤 2 — 功能性测试 (X.X.X.2):**
1. 按 clause-reference 的测试方法执行（shell 命令或 MCP 工具调用）
2. **注入类测试必须先完成前置准备 §1 弹药库加载**，payload 加 `[ref: ...]` 标记
3. **工具调用失败时**：执行 §前置准备 §5-6 的 FC-Loop 降级决策流程。不要直接重试——先识别 error signature → 查 tool-error-kb.json → 执行决策 → 追加 pivot 步骤到 executionTrace
4. 收集原始证据，写入工作区文件
5. 裁决: PASS / FAIL / INCONCLUSIVE
6. FAIL 必须附预期行为 vs 实际行为的对照

## 输出

写 **一份文件** 到 `{workspace_path}/`：

**`pre-{Mx}-evidence-x{retry_count}.json`** — 按 [evidence-schema.json](evidence-schema.json) + 下方内联示例输出。这是**强制且唯一**的输出。

>  警告: **不写 MD。** MD 由主线程在 evidence 确认通过后自动生成。

### 写入方式（从模板编辑）

模板已预生成在 `{template_json_path}`。编辑流程：

```bash
# 1. 读入模板 (agent 内部操作)
# 2. 填写 verdict/reason/evidence/executionTrace
# 3. 写回 (同路径，或 retry 时改为 x1/x2)
python -c "
import json
with open('{template_json_path}', encoding='utf-8') as f:
    data = json.load(f)
# ... agent fills in clauses ...
with open('{template_json_path}', 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
"
```

### 交付前自检 (强制 — 不通过不得回传，违者交付无效)

```bash
python {DIR_SKILLS}/etsi-ts103701-report/scripts/agent_preflight_check.py {template_json_path}
```

> **exit 0** → 可以回传摘要。
> **exit 1** → 逐字段报错（精确到条款号+字段名+违规值），修正后重跑 preflight，直到 exit 0。
> **exit 2** → JSON 损坏或文件不存在，修复后重跑。
>
> ⚠️ **这是硬闸门。** preflight exit ≠ 0 时回传摘要 → 视为未完成，主线程丢弃并重派。本会话 4 个 agent 因跳过此步骤导致 L1 打回，不得重犯。

> `retryCount` 从 meta 字段取值，确保每次重派写入不同文件名（x0 → x1 → x2），不覆盖上一代。JSON 写入后**必须用 `json.load` 回读验证**——验证失败 = 文件不完整 = 禁止交付。

JSON 核心字段:
- `meta.status` = `"pending_audit"` (固定值)
- `meta.retryCount` = 主线程分配值
- `clauses[]` 每条必填: clauseId, provisionText, icsStatus, icsSupport, verdict, reason
- FAIL 必填: expectedBehavior + actualBehavior
- PENDING_MANUAL 必填: manualSteps
- **每条 evidence 必标 level (L1-L5)**。必须为 L1-L3，L4/L5 视为无效交付
- `selfCheck.hasErrors` = false
- **`executionTrace` (强制)** — 无轨迹或 totalRounds=0 视为未完成交付

 **内联示例** — 见本文件上方 §子 agent 输出契约 → JSON 内联示例。照此格式逐条款填写。

## 回传摘要（≤300 字）
每条款裁决 + 一句话理由 + evidence 路径。不要回传大段日志/工具输出。

## 约束
- 不破坏性操作: 不删数据/不改配置/不触发认证锁定（M2 只做 1-2 次失败探针）
- 不编造: 未测写 INCONCLUSIVE，FAIL 必有证据
- **X手工 条款处理**：策略为 X手工 的条款（如 5.4-1~4, 5.7-1/2, 5.6-3/4, 5.9-1/2, 5.11 全系等），不执行工具调用，但必须：
  1. 阅读 IXIT 相关字段
  2. 写出具体的**手工测试步骤指引**（操作者照做就能测）
  3. 概念性测试照常执行（IXIT 分析）
  4. 功能性裁决标 `警告: 待手工测试`，附指引
  5. 手工条款不得跳过——不写指引视同遗漏
- 原始输出留在自己上下文，不回传
- 若代理已配 Burp（127.0.0.1:8080），HTTP 测试经代理发以留历史
```

### 模块前置准备配置（主线程派发时按表填入模板占位符）

| 模块 | `{exploit_loading_instructions}` | `{tshark_verification}` | `{burp_verification}` | `{playwright_verification}` | `{auth_precheck_gate}` |
|------|--------------------------------|------------------------|----------------------|------------------------|---------------------|
| **M1** 攻击面 | Read `${DIR.SKILLS}\etsi-ts103701-report\references\auth-diff-workflow.md` — 5.5-5 越权测试 (证据 A: API 全端点 auth_diff) | `ls -la {workspace_path}/capture.pcap` 确认文件存在 | `mcp__burp__proxy_history` + `mcp__burp__auth_diff` 确认可用 | 无需 Playwright MCP | 无需 (M1 的 auth_diff 自行做预检) |
| **M2** 认证 | Read `${DIR.SKILLS}\exploit\references\web-logic-auth.md` — 5.1-5 爆破和认证绕过靠它 | `ls -la {workspace_path}/capture.pcap \|\| echo "CAPTURE_MISSING"` — 5.1.3.2 认证加密分析依赖 pcap | `mcp__burp__proxy_history` 确认有登录流量 | `mcp__playwright__browser_tabs` (action=list) → 若可用按 `frontend-encryption-check.md` 流程执行；不可用 → `report_to_main`（禁止降级） | 无需 |
| **M3** 通信加密 | 无需加载（M3 为 TLS/加密分析，不发注入 payload） | **强制**: `ls -la {workspace_path}/pcap_analysis/_index.json` → 若缺失，报告主线程「pcap_analysis/ 不可用，请先跑 pcap_analyzer.py」。M3 的 5.5-1/5.5-6/5.5-7/5.8-2 读 `pcap_analysis/` 对应 JSON/TXT，不再自己跑 tshark 命令 | `mcp__burp__proxy_history_search` 确认可搜索 | —（前端加密结果从 M2 evidence 获取，走 §跨 Agent 数据传递范式） | 无需 |
| **M4** 更新完整性 | 无需加载（M4 为 IXIT 分析+固件升级流量审查） | `ls -la {workspace_path}/m4_preprocessed.json` 确认预处理完成。M4 **不读** 8MB ixit.json，改为读此 ~10KB 预处理文件。若缺失，报告主线程「m4_preprocessed.json 不可用，请先运行 preprocess_m4_ixit.py」 | `mcp__burp__proxy_history` + `mcp__burp__websocket_list` + `mcp__burp__websocket_get_messages` + `mcp__burp__burp_import_project_config` — 5.3-2 TLS 降级: import 设 `custom_tls_protocols=["TLSv1","TLSv1.1"]` → 触发DUT更新 → 观察是否接受弱TLS → 恢复配置。固件上传走 WebSocket：查 `server_to_client` 状态帧（`direction=server_to_client`+`max_results≤20`，禁全量拉取） | `mcp__playwright__browser_tabs` (action=list) → 若可用: 5.3-6-2 browser_navigate→browser_snapshot 读自动更新开关状态；5.3-16-2 browser_navigate→browser_snapshot 提取设备型号。警告: 弹窗按钮 click 超时→降级 browser_evaluate click | 无需 |
| **M5** 注入验证 | **强制**: Read `${DIR.SKILLS}\exploit\references\web-sqli.md` → Read `web-xss.md` → Read `web-rce.md` → Read `web-traversal.md`。5.13-1 注入探针的 payload 必须来自这些弹药库，带 `[ref: ...]` 标记 | `ls -la {workspace_path}/pcap_analysis/5.9-3_syn_bursts.json` 确认存在（5.9-3 重连分析读 `pcap_analysis/5.9-3_*.json`） | `mcp__burp__http_fuzz` + `mcp__burp__sqlmap_bridge_run` 确认可用 | `mcp__playwright__browser_tabs` (action=list) → 若可用: 5.12-1-2 browser_navigate 登录→browser_click Configuration Wizard→逐页 browser_snapshot 提取决策点。警告: 弹窗按钮 click 超时→降级 browser_evaluate click | **强制 — 调用 http_fuzz/dir_brute_force.py 前执行**（sqlmap_bridge_run/sqlmap_batch_run/sqlmap_bypass_retry 内置 `auth_refresh=true` 自动刷新，无需预检）: `mcp__burp__proxy_latest_auth{host:<DUT_IP>}` 一步拿最新认证头（扩展内真频率分析选帧 + 同帧提取 Cookie/SessionTag/Authorization + live GET 验活，verify.valid=true 即有效；不再用 session_ensure.py 两步法）。status:ok + verify.valid:true → 取 tokens.cookie/session_tag 注入 sqlmap_targets 的 auth_headers 与后续请求；expired/no_auth/no_traffic → 提示用户经 Burp 代理刷新 DUT 页面后重调。禁止跳过验活直接跑这两个工具。 |

### 主线程派发前覆盖检查

对照 module 划分表，确认全部 ICS=Y 条款均已分配。当前分配覆盖如下：

| 模块 | 条款数 | 条款列表 |
|------|:---:|------|
| M1 攻击面 | 12 | 5.5-2, 5.5-4, 5.5-5, 5.6-1~9 |
| M2 认证 | 5 | 5.1-1~5 |
| M3 通信加密 | 7 | 5.5-1, 5.5-3, 5.5-6~8, 5.8-1, 5.8-2 |
| M4 更新完整性 | 22 | 5.3-1~16, 5.4-1~4, 5.7-1, 5.7-2 |
| M5 数据保护 | 17 | 5.2-1~3, 5.8-3, 5.9-1~3, 5.10, 5.11-1~4, 5.12-1~3, 5.13-1, 6-1~5 |
| **合计** | **63** | (不含 ICS=N/A 的条款) |

> 派发前逐条勾选 ICS=Y 条款确认全覆盖。

M1-M5 完成后，evidence 由独立 Audit Agent 审查 (见上方 §审计编排)。不再由主线程手工核验。

## 何时不用并行

- **单条款快速复测**：只复核一个条款时，直接主线程跑，不必派 5 个 agent。
- **设备不可达/无认证会话**：多数模块依赖认证会话与网络可达，若设备离线则退化为纯 IXIT 文档分析（主线程单线程即可）。
- **上下文充足**：若检测规模小（如只测 5.1 一个情景），单线程更简单，并行协调成本不划算。

##  已知反模式（禁止行为，来自真实翻车记录）

以下行为已被证实导致报告质量断崖式下降，**任何时候都禁止**：

### 反模式 1：Agent 降级为 Shell 执行器

| 禁止 | 必须 |
|---------|---------|
| agent prompt = "Run sqlmap, save output to file" | agent prompt 按 §派发模板完整填写，含 IXIT JSON 路径、条款表、概念+功能双步骤 |
| agent 只回传命令输出的 tail -20 | agent 写入成对的 `evidence_Mx_*.json` + `evidence_Mx_*.md`，JSON 按 evidence-schema.json 输出 |
| 主线程不读 evidence 直接汇总 | 主线程驱动审计队列：L1 脚本 → L1 PASS → 调度 Audit Agent → Round 1 ACCEPT → Round 2 跨模块审计 → 阶段 4 |
| 用 4 个工具 agent 代替 5 个模块 agent | 严格按 M1-M5 模块划分，一个模块一个 agent |
| 只产 markdown 不产 JSON | **JSON 是强制输出** — 审计 Agent 不读 markdown，只消费 JSON。无 JSON == 未完成 |

### 反模式 2：跳过 pcap 深度分析

| 禁止 | 必须 |
|---------|---------|
| pcap 只跑 `io,phs` 聚合统计就写报告 | 主线程必须先跑 `pcap_analyzer.py` → 生成 `pcap_analysis/` → agent 逐条款读对应的 JSON/TXT |
| 报告中没有 frame 编号引用 | 每条 FAIL/PASS 至少引用 1 个 pcap frame 编号 |
| TLS 握手分析只依赖 nmap | 读 `pcap_analysis/5.5-1_server_hello.json` 取实际协商的 cipher suite + TLS 版本（nmap 只能扫支持的，不能证实际用的） |
| 不分析 DUT 出站连接 | 读 `pcap_analysis/5.5-6_dut_outbound.json` + `pcap_analysis/5.5-7_all_destinations.json` 核验 DUT 是否主动外连远程 CSP |
| 5.9-3 不做 SYN 间隔分析 | 读 `pcap_analysis/5.9-3_syn_bursts.json` 的 `verdict_hint` + `bursts[]` |

### 反模式 3：证据没有 frame 级引用

| 禁止 | 必须 |
|---------|---------|
| "登录请求走 HTTP" | "frame 91: POST /ISAPI/Security/sessionLogin HTTP/1.1，XML body 含 `<password>` 64hex 字段" |
| 裁决没有原始数据支撑 | FAIL 必附 frame 号 + 预期 vs 实际对照；PASS 必附 pcap 或 Burp 响应片段 |

### 反模式 4：M0 疑点列而不追踪

| 禁止 | 必须 |
|---------|---------|
| M0 列出 4 个 ICS 矛盾但报告中没有闭环 | 每个 M0 疑点对应一个实测核对条目，标注"成立"或"不成立"或"修改建议" |
| 疑点核对放在报告外 | M0 核对结论写入报告 §检测总览，作为 ICS 质量的正式裁定 |

##  Evidence 深度最低标准

已内置在主线程审计队列的 Step A (L1 机械化验证，`validate_evidence.py`) 和 `etsi-report-auditor` skill 的 Step 2 (三角对照) 中。

## ⏱️ 时间预期

| 阶段 | 预期耗时 | 翻车信号 |
|------|:---:|------|
| 环境检查 | 5-10 min | — |
| M0 ICS 验证 | 5-10 min | — |
| tshark 启动 + 流量采集 | 5-10 min | — |
| M1-M5 并行 Agent | 60-90 min | < 30 min → 未做深度分析 |
| 审计队列 (etsi-report-auditor) | 与 Mx 重叠，每条 3-5 min | — |
| Mx 重测 (如有 NEEDS) | 10-30 min/条 | — |
| 报告生成 | 15-20 min | 报告 < 500 行 |
| **总计** | **2-3 小时** | **< 1 小时肯定漏了东西** |

> 审计 Agent 随 Mx 完成触发，与后续 Mx 并行，不单独占时间段。
