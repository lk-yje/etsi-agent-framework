# 工作区文件分类与留存标准

## 目的

用“生命周期/证据权威性”作为第一层边界，用“内容类型”作为第二层目录。阶段（M0、Traffic、M1…）写入 manifest、事件和文件名，不作为顶层硬目录；同一 PCAP、工具回执或审计结论经常跨越多个阶段。

## 顶层目录

| 目录 | 放什么 | 不能放什么 | 留存规则 |
|---|---|---|---|
| `framework/`、`pipelines/`、`web/`、`scripts/`、`skills/`、`tests/` | 可执行代码、受控知识、测试代码 | 某次运行产生的证据或模型回执 | 随代码版本管理 |
| `docs/` | 长期有效的方案、架构、验收、教训、规范 | 原始 PCAP、模型工具回执 | 变更时修订 |
| `runs/<run-id>/` | 正式或待正式的 DUT 运行记录 | 临时探针、无 DUT 的模型试验 | 原始记录；不因控制台移除而删除 |
| `experiments/<experiment-id>/` | 可复核的非正式试验、回归、网关兼容性验证 | 认证结论、生产报告 | 保留输入哈希、代码版本、边界和结论 |
| `scratch/` | 一次性辅助脚本、临时映射、进程日志、可随时重建的中间文件 | 需要复核的证据、唯一的试验结果 | 定期清理前先迁入 `experiments/` 或 `docs/` |
| `archive/` | 已冻结且不再活跃的 run/experiment | 当前活跃工作区 | 只读归档，保留 manifest |

## `runs` 与 `experiments` 的内部结构

每一个运行或实验是一个**完整边界**，推荐具有下列子目录；没有产生的可不创建：

```text
<run-or-experiment>/
├── manifest.json          # 身份、性质、输入 hash、工具/模型版本、结果与路径索引
├── input/                 # 输入引用、归一化 IXIT、固件清单；不复制大文件除非必要
├── state/                 # pipeline_state、tokens、运行配置
├── evidence/              # 正式 EvidenceManifest 与 revisions
├── artifacts/             # pcap、扫描输出、截图、解析产物等原始/派生产物
├── audit/                 # L1/L2/cross-audit 及审计轮次快照
├── rework/                # 打回范围、原因、旧/新 evidence hash
├── reports/               # Markdown/HTML/PDF 报告与导出包
├── logs/                  # 事件、stdout/stderr、trace
└── tool-receipts/         # 工具调用参数摘要、时间、输出索引
```

文件本身跨阶段时只保存一份；通过 `manifest.json`、evidence 的 `path`、receipt 与报告索引从多个条款引用它。不得为“每个条款一个目录”复制同一个 PCAP 或扫描输出。

## M0 概念 checkpoint 归档（可恢复运行）

为避免“单条概念条款失败导致前面已完成的几十条全部丢失”，M0 概念阶段把每条**通过单条范围校验**的条款原子落盘为独立 checkpoint：

- **位置**：`<workspace>/evidence/checkpoints/M0/concepts/<clause-id>.json`（含该条 `ClauseResult` + `execution_trace`）。
- **复用条件**：重跑时校验外层 `clause_id` 戳章、`ClauseResult` schema、IXIT 引用非空、trace 非空，全部通过才复用；否则视为缺失/无效重跑，绝不把不完整输出当 PASS。
- **与正式 evidence 的归并关系**：checkpoint 只用于“补齐缺失/无效的概念条款”，不是正式证据；正式 `evidence/pre-M0-evidence.json` 仍由 `M0ConceptStage` 在 62 条全部有效后一次性归并写入，`conceptualClauseCount=62`。

## Traffic Intelligence 数据分级

Traffic Intelligence 产物全部属于运行工作区数据，不属于代码仓库内容：

| 分级 | 典型内容 | 默认访问策略 | Git 策略 |
|---|---|---|---|
| 原始受限 | `capture.pcap/pcapng`、完整 Stream、TLS key log、私有 dissector | 仅测试人员与受控工具按需访问 | 一律忽略 |
| 受限索引 | EasyTshark SQLite、完整帧索引、Decode-As staging | Agent 不直接读取；通过受限查询接口下钻 | 一律忽略 |
| 结构化证据 | Flow、协议候选、加密评估、声明对齐、frame refs | 校验 Bundle manifest 后只读 | 仅保存在 run workspace |
| 受控派生 | `traffic-intelligence-derived/decode-as-attempts/` | 每次尝试独立 manifest 绑定父 Bundle/PCAP；不得修改原 Flow | 仅保存在 run workspace |
| 报告摘要 | 脱敏后的计数、差异和证据引用 | 可进入最终报告 | 报告仍属于 run，不进入公共源码仓库 |

`traffic-intelligence/manifest.json` 是读取入口。消费者必须确认 `complete=true`、
PCAP SHA-256 一致、artifact 文件大小和哈希一致后，才可使用其中结论。临时目录、
失败后端输出和未登记文件不得被视为认证证据。

公共测试不得复制客户 PCAP。确需协议回归时，只能使用脚本确定性生成的合成包，
并确保其中的 IP、域名、MAC、Payload 和证书均为保留测试值或虚构数据。

## 命名与状态

- 正式运行：`runs/YYYY-MM-DD_<dut-alias>_<run-id>/`。
- 非正式实验：`experiments/YYYY-MM-DD_<topic>/attempt-01_<short-purpose>/`。
- `manifest.json` 必须含：`kind`（`formal_run` / `nonformal_experiment`）、`authority`、`source_hashes`、`environment`、`status`、`limitations`。
- 仅当 L1/L2 和流程门禁满足时，证据可标为 `formal_candidate`；非正式试验一律标 `nonformal`，不得混入认证报告。
- `scratch` 中的路径可以出现在历史日志里；迁移后不改写这些历史事实，而在新 manifest 中给出 `migrated_from`。

## 清理与迁移

1. 先生成/核验 manifest 与目录清单，再移动；绝不先删除。
2. 移动后做文件数与大小核验；失败时停止，不覆盖目标。
3. `.runs.json` 的“从控制台移除”只取消注册，不得删除 `runs/`、`experiments/`、evidence、PCAP 或报告。
4. `skills/path-mapping.json` 不属于运行产物；不得因整理工作区而修改它。

## 本次落地

2026-08-19 的 M0/IXIT 非正式试验已迁入 `experiments/`；其使用的本地 XLSX、DeepSeek 网关和离线边界均在各自 manifest 中声明。SQLMap 桥接试验另放在独立日期目录，避免与 ETSI 概念性审查记录混在一起。
