# 每节点快照（Node Snapshot）设计提案 v1

> 状态：**已定稿（2026-08-21）**——三项决策见文末"已决策"。
> 定位：断点续跑 / 幂等跳过 / 证据链追溯的统一地基。
> 原则：**保护结果，不保护运输**（运输错误→暂停等待，见 transport pause；快照只记"已成立的结果"）。

## 1. 目标

| 能力 | 现状 | 快照后 |
|---|---|---|
| 幂等跳过 | 仅 M0 概念条款（checkpoint） | 任意节点：输入 hash 匹配 = 已完成，不重跑 |
| 断点续跑 | 阶段级（pipeline_state.json） | 节点级：从第一个未完成节点续跑 |
| 证据链追溯 | 散落各文件 | 每节点可答"消费了什么、产出了什么、哪次尝试、什么模型" |

## 2. 节点模型（三层）

```
stage/<state>            阶段节点     如 stage/m1_m5、stage/traffic     （9 阶段）
phase/<module>/<phase>   相位节点     如 phase/M1/phase_C               （PhaseEngine 执行单元）
clause/M0/<clause_id>    条款节点     如 clause/M0/5.1-1                （仅 M0 概念，已有 checkpoint）
```

- phase 是 **M1-M5 的最小可复用单元**：evidence 以 phase 为单位产出/归并，拆到条款会动归并逻辑，v1 不做。
- M0 条款 checkpoint（`evidence/checkpoints/M0/concepts/`）**保留为产物本体**，快照只建索引指向它，不双写。

## 3. Schema v1

`<workspace>/snapshots/<node_id 转义 '/'→'__'>.json`，原子写（复用 FileBus.write_atomic）：

```json
{
  "schema_version": 1,
  "node_id": "phase/M1/phase_C",
  "kind": "phase",
  "status": "completed",
  "attempt_id": "run_20260821_1530_a3",
  "input_digest": "sha256:ab3f...",
  "outputs": [
    {"path": "evidence/pre-M1-phase_C-evidence.json",
     "digest": "sha256:cd71...", "bytes": 128443}
  ],
  "pool_outputs_written": ["M1_shared_findings"],
  "started_at": "2026-08-21T15:30:02",
  "ended_at": "2026-08-21T15:31:47",
  "model": "glm-5-turbo",
  "agent_trace_ids": ["work_M1_phase_C_v1_20260821153002"],
  "tool_receipt_count": 6,
  "parent": "stage/m1_m5",
  "error": null
}
```

`status ∈ {in_progress, completed, failed, skipped}`。`failed` 也落快照（带 error）——
失败是事实，resume 时 failed 且输入未变的节点按重试策略处理，不是无脑跳过。

### input_digest 的算法（核心）

节点输入的**确定性摘要**，决定"能不能复用"：

```
输入 = {
  task 摘录（phase 条款清单 + recipe 引用，不含时间戳/attempt）
  pool 依赖：{key 列表 + 各 key 当前值的 digest}
  persona + knowledge 文件内容 digest 列表
  max_tool_turns + tool_manifest
}
→ key 排序、剔除易变字段 → 规范化 JSON → sha256
```

**模型名不参与 digest**（已决策）：换模型后旧 evidence 照样复用。`model` 字段仍
记录在快照里，追溯时能看到每个节点实际用的模型。

匹配语义：
- `input_digest` **相等** → 结果可复用（幂等跳过）
- **不等** → 输入变了（上游重跑/模型换了/知识库改了），旧结果不可信，重跑

### 索引文件

`<workspace>/snapshots/index.json`：`node_id → {status, input_digest, attempt_id}`。
resume 时一次读入，不用扫目录。

## 4. Resume 语义

1. 读 `index.json`，对每个节点重算当前 `input_digest`，与快照比对
2. 拓扑序遍历：`completed` 且 digest 匹配 → **跳过**；跳过 phase 时从 `outputs` 的
   evidence 文件读回 `pool_outputs_written` 并 put 回 ContextPool（下游才能继续）
3. 第一个不匹配/未完成的节点开始实跑
4. transport 暂停恢复后的重试：成功才落快照，暂停本身不产生任何快照

### 非幂等节点（显式声明）

- **stage/traffic**：pcap 是用户操作窗口的产物，**不可重现**。快照只记录既成事实
  （pcap digest），resume 时 traffic 永不自动跳过，必须人工重新确认（沿用现有
  WAITING_START 门）。
- **stage/report**：依赖全部上游，永远重算（成本低）。

## 5. 与现有机制的关系（不推倒重来）

| 现有 | 关系 |
|---|---|
| `pipeline_state.json` | 保留，阶段级"进度表"；快照是它下面的证据细化层 |
| M0 条款 checkpoint | 产物本体不变；`clause/M0/*` 快照作为索引层（digest 指向 checkpoint 文件） |
| transport 暂停（2026-08-21） | 互补：暂停保护"运输中"，快照保护"已到岸" |
| tool receipts / agent traces | 快照引用其 ID/计数，不复制内容 |

## 6. 实施分期

- **P1**：`SnapshotStore`（write/query/replay-pool）+ phase 节点落快照 + resume 跳过
  （改 phase_engine：执行前查快照，成功后落快照）——最大头，价值最高
- **P2**：stage 节点 + M0 clause 索引入口 + CLI `--resume` 开关
- **P3**：前端 stepper 每阶段可点开看节点快照（输入/输出 hash、attempt、耗时）

## 7. 已决策（2026-08-21）

1. **模型名不参与 digest**：换模型后旧 evidence 复用不重跑；快照 `model` 字段
   保留用于追溯。
2. **traffic 非幂等**：同意。resume 永不自动跳过，必须人工重新确认采集窗口。
3. **P1 只做 phase 级**（M1-M5）；M0 条款沿用现有 checkpoint，收编放 P2。
