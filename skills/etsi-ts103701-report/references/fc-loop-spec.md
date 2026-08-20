# FC-Loop 规范：Agent 执行引擎

> 这是 ETSI Mx Agent 的 FC-Loop（Function Calling Loop）显式建模。当前子 agent 的内部推理-工具调用循环是隐式的——agent 自由发挥，没有结构化约束。本规范将 FC-Loop 从隐式行为升级为可跟踪、可审计的执行引擎。

## 一、Loop 结构

每个 Mx agent 执行一条 FC-Loop。Loop 由若干 Round 组成，每轮 agent 决定执行什么动作。Loop 终止条件：所有条款已裁决 OR 轮次预算耗尽 OR 超时。

```
FC-Loop
  │
  ├── Round 0: PREFLIGHT     ← 前置检查 (通道/弹药库/会话确认)
  ├── Round 1..N-1: WORK     ← 工具调用 + 推理 + 自检
  └── Round N:   DELIVERY    ← 交付前质量门禁确认 → 写入 evidence
```

### Round 类型

| 类型 | 触发 | 行为 | 计入 maxLlmRounds |
|------|------|------|:---:|
| `preflight` | Loop 启动 | 确认 tshark pcap / Burp MCP / playwright / 弹药库 / 认证会话 可用 | ✅ |
| `tool_call` | agent 决定调用工具 | 执行工具 → 收集结果 → 记录 finding | ✅ |
| `reasoning` | 工具返回后 | 分析结果 → 对照 IXIT → 形成初步裁决 → 决定下一步 | ✅ |
| `self_check` | 每 N 轮 (harness-config.json: roundCheckInterval) | 进度自检 → 是否继续/加速/交付 | ✅ |
| `pivot` | 工具不可用或结果异常 | 降级决策 (查 ToolErrorKnowledgeBase) → 切换策略 | ✅ |
| `delivery` | 全部条款裁决完成 OR 预算耗尽 | preDeliveryChecklist → 写 evidence JSON + MD | ✅ |

## 二、超时分级控制

每次工具调用受三级超时约束：

| 级别 | 超时 | 适用 | 超时后行为 |
|------|:---:|------|-----------|
| T1 单工具 | 60s | nmap -sn, curl, Burp proxy_history(limit=1) 等轻量调用 | 重试 1 次 (不同参数) |
| T2 工具组 | 120s | nmap 全端口、tshark 协议统计、sqlmap 探测、xray 启动 | 查 ToolErrorKnowledgeBase → 降级决策 |
| T3 Agent 总超时 | harness-config timeoutMinutes | 整个 agent 生命周期 | 已完成条款正常交付，未完成标 INCONCLUSIVE |

**agent 在每轮 tool_call 后记录实际耗时到 `executionTrace.steps[].durationSec`。**

## 三、Round 跟踪模板

agent 在每轮结束时往 executionTrace.steps 追加一条。这不是 post-hoc 总结——是 **round-by-round 实时追加**：

```json
{
  "seq": 3,
  "phase": "tool_call",
  "summary": "nmap TCP 全端口扫描 DUT",
  "tool": "nmap",
  "params": "-sS -p- -T4 --open <DUT_IP>",
  "finding": "开放端口: 80, 443, 554, 8000。其中 8000 未在 IXIT 15-Intf 登记",
  "clauseIds": ["5.6-1"],
  "durationSec": 45,
  "error": null
}
```

```json
{
  "seq": 7,
  "phase": "pivot",
  "summary": "playwright browser_tabs 返回空 — 浏览器未启动",
  "tool": "mcp__playwright__browser_tabs",
  "finding": null,
  "clauseIds": ["5.1-3", "5.5-1"],
  "durationSec": 3,
  "error": {
    "signature": "PLAYWRIGHT_MCP_UNAVAILABLE",
    "kb_lookup": "tool-error-kb.json → playwright → browser_tabs 返回空",
    "decision": "report_to_main",
    "fallback": "5.1-3/5.5-1: report_to_main（暂停主流程，playwright 就绪前不裁决）",
    "affectedClauses": ["5.1-3", "5.5-1"]
  }
}
```

## 四、自检协议 (Self-Check Protocol)

按 harness-config.json 的 `roundCheckInterval`，每 5 轮强制执行一次 self_check：

```
Self-Check @ Round 5, 10, 15, 20, 25, 30:

1. 进度盘点:
   已裁决: X / 总数 Y 条款
   剩余轮次: (maxLlmRounds - currentRound)
   每条款平均剩余轮次: (maxLlmRounds - currentRound) / (Y - X)

2. 风险判定:
   若 每条款平均剩余轮次 < 2 → ⚠️ 加速模式
      → 跳过非关键工具调用
      → 非核心条款直接标 INCONCLUSIVE + 理由
      → 优先完成：FAIL 条款 (需证据) > PASS 条款 > 手工条款 (已有指引即可)

3. 停滞检测:
   若最近 3 轮 tool_call 均未产生新 finding:
      → 可能原因: 工具循环调用 / 参数错误 / 目标不可达
      → 查 ToolErrorKnowledgeBase
      → 若无法解决 → 受影响条款标 INCONCLUSIVE，继续下一批

4. 记录 self_check 到 executionTrace:
   {
     "seq": N,
     "phase": "self_check",
     "summary": "进度: 8/12 条款已裁决, 剩余 10 轮, 每条款 2.5 轮",
     "finding": "正常 — 继续执行",
     "clauseIds": ["5.6-1", "5.6-2", ...已完成条款],
     "durationSec": 0
   }
```

## 五、交付条件

agent 在以下任一条件满足时进入 delivery round：

| 条件 | 行为 |
|------|------|
| ✅ 全部条款已裁决 | 正常交付 → preDeliveryChecklist → 写 evidence |
| ⏰ maxLlmRounds 耗尽 | 部分交付 → 已完成条款正常写入，未完成标 INCONCLUSIVE + 注明「轮次预算不足」 |
| ⏰ timeoutMinutes 耗尽 | 部分交付 → 同上 |
| 🛑 不可恢复错误 | 部分交付 → 受影响条款标 INCONCLUSIVE + error signature |

交付前必须执行 preDeliveryChecklist (见 harness-config.json)，每一项确认后打勾。`selfCheck.hasErrors = true` 不得交付。

## 六、与 executionTrace 的关系

| executionTrace 字段 | FC-Loop 对应 |
|---------------------|-------------|
| `startedAt` | Round 0 PREFLIGHT 开始时间 |
| `completedAt` | DELIVERY round 完成时间 |
| `totalRounds` | 实际执行的 Round 总数 (含 preflight + delivery) |
| `steps[]` | 每轮的记录 (preflight / tool_call / reasoning / self_check / pivot / delivery) |
| `steps[].error` | 工具失败时的降级决策记录 |
| `warnings[]` | agent 自识别的执行风险 |

## 七、集成点

| 集入位置 | 内容 |
|---------|------|
| module-split.md agent prompt 模板 | 注入 FC-Loop 结构 + 自检协议 + 交付条件 |
| harness-config.json | maxLlmRounds / roundCheckInterval / timeoutMinutes 作为 Loop 参数 |
| tool-error-kb.json | 降级决策的数据源 |
| fallback-decider.md | 降级决策逻辑 (agent 在 pivot round 时查阅) |
| validate_evidence.py | 检查 executionTrace.totalRounds > 0 + steps 覆盖全部条款 |
| etsi-report-auditor skill (Step 1.5) | 对照 harness 检查 totalRounds ≤ maxLlmRounds (超限警告) |
