# ETSI TS 103 701 · 待解决问题清单（pending issues）

> 状态：阶段 (a) 扩展源码改动已完成；**阶段 (c) KB 对齐已完成（2026-08-17，逐条处置已写入 `tool-error-kb.json`）**。
> 本文件记录已**亲验**的病灶与待对齐条目，供阶段 (c)（连接性验证通过后）对齐
> `tool-error-kb.json` 使用。每条格式：主张 → 证据 → 处置状态。
> 约定：本次扩展源码（BurpMCP-Ultra 2.0.1）已按下列处置实现；KB 的正式改写留 (c)。

## P0. 多运行模式与功能性测试直达（最高优先级，执行中）
- **主张**：当前 ETSI 编排把 `M0_AUDIT → TRAFFIC_COLLECT → M1–M5` 作为唯一入口。
  该硬 gate 对正式认证正确，却使日常真实 DUT 功能性调试必须先完成高成本 M0 审计，无法高效验证
  Playwright、tshark/xray、BurpMCP 和 M1–M5 链路。
- **证据**：`pipelines/etsi/pipeline.py` 的 M0 审计 transition 要求 `.audit_M0_ACCEPTED` 才能进入 Traffic；
  本次 DVWA 运行已多次在 M0 L2 审计消费时间/模型额度，尚未到功能性阶段。现有
  `docs/NODE_SNAPSHOT_DESIGN.md` 已定义节点快照、输入 digest 与阶段/phase/clause 三层模型，可作为
  多模式编排的恢复与溯源基础。
- **处置（P0 范围）**：
  1. 新增 `RunProfile` / `RunPlan` 合约与计划预览：`certification-full`、`functional-smoke`、
     `functional-module`、`audit-only`、`report-rebuild`；先输出 DAG、所需输入、将跳过的认证 gate 和风险标识，
     再执行。
  2. `functional-smoke` 从 Traffic 开始，随后运行可满足依赖的 M1–M5；`functional-module` 由依赖解析器
     展开所选模块的上游 phase/证据要求。缺少 pcap、登录态、固件、工具或人工确认时必须 `blocked`，不得静默降级。
  3. 非认证 profile 绝不伪造 `.audit_M0_ACCEPTED`；workspace/run config/报告均写入
     `certification_claim=false`、profile、跳过原因、模型和工具来源。
  4. 把已停止/失败快照作为可见、可继续的运行对象；恢复按节点/phase 输入 digest 复用有效结果，Traffic 始终要求人工重新确认。
- **2026-08-24 进度**：已新增 `contracts/run_plan.py` 与 `framework/run_planner.py`，CLI 可用
  `run_pipeline.py plan --profile functional-smoke` 或 `--profile functional-module --modules M3`
  预览 DAG；模块模式会自动展开 M3 → M2 依赖，并明确 `certificationClaim=false`、跳过的
  认证 gate、所需输入和“不得降级”的风险。已增加 3 条规划器测试。**尚未接入实际执行器或 Web；
  因此当前不能声称 functional profile 已可启动。**
- **2026-08-24 执行层进度**：`functional-smoke` / `functional-module` 现会为每次运行创建
  `父工作区/runs/<profile-时间-随机号>/`，仅复制 `ixit.json`、`run_config.json` 与环境快照；状态、
  tokens、evidence、pcap 和日志均在该 run 根目录内生成，不会改写父 workspace 的认证快照。
  ETSI Pipeline 已能以 `TRAFFIC_COLLECT` 为非认证起点，并按 `selectedModules` 过滤 M1–M5；
  非认证分支不经过 M0/Cross 认证 gate，也不生成认证报告。`audit-only` / `report-rebuild` 暂仅可预览，
  执行会明确拒绝，防止误入 Traffic。
- **2026-08-24 Web 运行归属**：Web 控制台现在在启动前创建并登记实际的 `runs/...` 子工作区，
  CLI 以 `--run-workspace-ready` 消费该目录而不二次创建；Run 元数据同时记录父 workspace、实际运行
  workspace、profile 与 `certification_claim`。因此轮询、日志、停止和恢复会指向同一真实目录，不会再
  发生“前端看父目录、子进程写子目录”的进度丢失。已通过 Web API / RunManager / RunPlan 21 项回归。
- **2026-08-24 Web 计划操作面**：控制台已支持选择 `certification-full`、`functional-smoke` 和
  `functional-module`，可在启动前调用 `/api/run-plan` 预览节点、依赖、跳过 gate 与风险；功能性模式
  以醒目的“非认证功能性运行”标识展示，模块模式会展开上游依赖。已通过 22 项 Web/RunManager/RunPlan
  回归。下一项为已停止快照的可见恢复入口。
- **验收**：同一 DVWA+IXIT 工作区可在不运行 M0 审计的情况下预览并启动 `functional-smoke`；
  Web 显示其为非认证运行、可见所有节点快照和进度；`certification-full` 的 M0 gate 行为保持不变；
  profile/DAG/跳过项、输入 hash、模型、工具和证据均可导出追溯。

## P0.1 M1–M5 条款调度范围与 Burp MCP 覆盖对齐（最高优先级，待实施）

- **主张**：功能性条款 catalog 已定义 68 条映射，但当前 M1–M5 的模块定义与 phase 定义只调度 47 条；
  另外，catalog 中 11 条要求 Burp MCP 的条款仅有 6 条进入 M4 phase。因此运行页面显示的 `47 / 6`
  是当前执行配置的真实投影，却不是 catalog 的完整能力范围。
- **已确认缺口**：未被当前 M4 phase 覆盖的 Burp MCP 条款为 `5.3-5`、`5.3-7`、`5.3-9`、`5.3-11`、
  `5.3-12`。其余 16 条映射也必须逐一定位并纳入恰当模块/phase，不能仅为使计数变为 68 而重复或错配。
- **处置**：
  1. 以 `framework/clause_tool_map.json` 为唯一功能性条款基线，调整 `pipelines/etsi/modules.py` 与
     `framework/phase_definitions.json`（及所有派生 registry/静态校验）使 M1–M5 调度集合精确覆盖 68 条，
     每条只进入其语义正确的模块和 phase。
  2. 扩展 M4 phase 使全部 11 条 Burp MCP recipe 都获得实际调用机会；特别确保上述 5 条不是只在文档或
     catalog 中声明，而是会在满足 prerequisites 后被 PhaseEngine 下发。
  3. 强化 `scripts/validate_clause_alignment.py` 和测试：默认输出总 catalog、M1–M5 调度、遗漏、重复和
     Burp MCP 总数/已调度/遗漏清单；`--strict` 在任一集合不相等或 Burp 覆盖不全时失败。
  4. 更新面板/API 的统计口径：分别显示 catalog 总数、计划调度数和本次实际执行数；不得把未纳入计划的
     catalog 条款显示为已执行或静默隐藏。
  5. 修改 `skills/exploit/SKILL.md`：SQL 注入自动化的主路径明确为 BurpMCP-Ultra 的
     `sqlmap_targets` → `sqlmap_bridge_run` / `sqlmap_batch_run` → `sqlmap_bypass_retry` bridge；直接 Bash
     `sqlmap` CLI 仅用于 bridge 所产 `.req` 的数据提取、受控手工复现或 bridge 不可用时的明确兜底，且
     必须保留授权、证据与四态结果边界。
- **验收**：`validate_clause_alignment.py --strict` 证明 catalog=68、M1–M5 调度=68，且 Burp MCP
  catalog=11、M4/相关 phase 已调度=11；每个新增条款在 phase recipe 中可追溯到工具、先决条件、证据和
  oracle。用 mock MCP 运行至少一条新增 Burp 条款和 `5.13-1`，分别留下真实 tool receipt；若 L1/gate
  未通过，应明确记录为未调用而不能声称 bridge 已执行。

## 1. HTTP_SEND_REQUEST_DROPS_HEADERS — rootCause 证伪
- **主张**：`http_send_request` 丢弃请求头，导致认证头丢失。
- **证据**：`HttpBridge.buildRequest`（L631-633）用 `withHeader`/`withRemovedHeader` 原样应用传入头，
  无任何丢弃逻辑。401 是凭据配对/过期所致（ISAPI Cookie+SessionTag 双头缺一 → AUTH_TOKEN_PAIR_MISMATCH），
  不是工具丢头。
- **处置**：**不改代码**。待 KB 该条 rootCause 重写为「双头认证配对 / 令牌过期」。

## 2. BURP_PROXY_HISTORY_OVERFLOW — 真根因 = 参数名不匹配（已修）
- **主张**：proxy_history 返回被截断。
- **证据**：`ProxyTools.proxy_history` 读 `count`（默认 100），framework 脚本传 `max_results` → 被忽略 → 恒取 100。
  非溢出，是参数别名缺失。
- **处置**：已加 `max_results` 别名。待 KB 重写根因。

## 3. 频率分析虚构 — proxy_latest_auth 真实现（已修）
- **主张**：`auth_token_discovery.find_best_token` 声称做频率分析。
- **证据**：实际只取「index 最大的认证帧」，无任何路径计数。
- **处置**：`proxy_latest_auth`（新工具）内实现真频率分析（按规范化路径计数，平局取新 index）。
  待 KB AUTH_SESSION_EXPIRED 更新。

## 4. auth_diff 单头注入 / header_name 无 value 静默 no-op（已修）
- **主张**：auth_diff 每 level 只能注入单头；`header_name` 无 `header_value` 时两分支都不执行。
- **证据**：原 AnalysisBridge L487-497。
- **处置**：支持 `headers:[{name,value}]` 多头数组 + 向后兼容；header_name 无 value → 抛
  `AUTH_DIFF_HEADER_VALUE_MISSING`。待 KB AUTH_DUAL_HEADER_REQUIRED 标 resolved。

## 5. auth_diff 不剥 base 认证头 → none 漏报（已修）
- **主张**：none 级别仅剥 4 个头，base 残留认证头导致 none 也带认证。
- **证据**：原 AnalysisBridge L490-497 只对 none 剥头。
- **处置**：所有 level 默认剥 base 的 Cookie/Authorization/X-API-Key/X-Auth-Token（保留 SessionTag），
  none 额外剥 SessionTag；`preserve_headers` 逃生舱 + `auth_headers_stripped` 明示。
  待 KB AUTH_DIFF_LEAKS_ORIGINAL_AUTH 标 resolved。

## 6. 裸 \n 导致 TCP 挂起 ~8s（已修）
- **主张**：raw 请求残留裸 `\n` 时 sendRequest 长时间无响应。
- **证据**：入参未做 CRLF 规范化。
- **处置**：`normalizeRequestCrlf` + 结构校验（请求行 / Host）。待 KB AUTH_DIFF_CRLF_TIMEOUT 标 resolved。

## 7. device_hint:"isapi" 静默忽略（已修）
- **主张**：device_hint 参数存在但从不读取。
- **证据**：AuthDiffTools 不读该参数。
- **处置**：真参数化 —— isapi 时做双头校验（base 有 SessionTag 且无 level 注入 Cookie →
  `AUTH_DIFF_DUAL_HEADER_REQUIRED`）；none 额外剥 SessionTag。待文档/KB 更新。

## 8. 302 裁决信号差异（有意为之，需确认）
- **主张**：Python `auth_verdict_decider.apply_matrix` 302 分支读 `none_body_preview`（body 预览）。
- **证据**：302 响应 body 几乎恒空 → 原实现基本恒判 SUSPICIOUS，丢失「重定向到登录页」的 PASS 信号。
- **处置**：扩展版改判 **Location 响应头**优先 + body 兜底。判定结果可能比 Python 更敏感（更多 PASS）。
  这是有意的增强，待阶段 (c) 确认是否反向同步 Python。

## 9. verdict / 端点收集已下沉到扩展
- **主张**：裁决矩阵与端点收集逻辑在 Python（auth_verdict_decider / auth_orchestrator）。
- **证据**：auth_diff 输出新增 `verdict`（镜像 apply_matrix）；新工具 `auth_scan_endpoints` 内建
  collectEndpoints（镜像 cmd_endpoints）+ 批量裁决（镜像 cmd_verdict）。
- **处置**：字段名与阈值零漂移对齐（details 含 admin_status/none_status/body_similarity/
  none_body_preview/burp_findings 等）。待 (c) 确认双向喂数兼容。

## 10. 安全停止后控制台丢失最后快照与继续入口（待修）
- **主张**：用户在 Web 控制台执行安全停止后，运行页显示“管线尚未启动（pipeline_state.json 不存在）”，
  隐藏了实际存在的 `cancelled` 快照，且没有从该快照继续的入口。
- **证据**：对应工作区的 `pipeline_state.json` 仍存在，
  记录 `current_state=cancelled`、`m0_audit=failed`；M0 evidence、L1 token、两轮审计输入/输出和
  `audit-results/revisions/M0/round-2.json` 均保留。问题属于 Web 状态派生/终态展示与恢复操作缺失，
  不是工作区快照被删除。
- **处置**：待实现“已停止快照”视图（显示最后阶段、取消原因、可恢复阶段）和显式恢复动作；恢复必须按
  阶段粒度复用已有有效审计批次，不能把 `cancelled` 误报为文件不存在，也不能重跑无关条款。
- **2026-08-24 进度**：控制台已保留终态 run 并显示取消时间线；对于
  `certification-full + current_state in {cancelled, failed} + m0_audit=failed`，实时面板显示
  “从 M0 审计快照恢复”。该动作会创建新的受管恢复 run，保留原 M0 evidence/L1 结果，仅传递
  `--resume-cancelled-m0-audit` 或 `--resume-failed-m0-audit`；其他终态、功能性 profile 和非 M0
  失败点一律拒绝，避免错误重跑。Web/M0 回归 25 项通过。尚待把 Phase 输入 digest 的通用恢复扩展到
  M1–M5 节点。
- **2026-08-24 M1–M5 digest 恢复**：已新增 `--resume-m1m5`。仅当快照处于
  `failed/cancelled` 且 `m1_m5` 本身未完成时允许执行；它将状态回到 `traffic`、清除取消控制信号并
  写入 `audit/resume-history`，同时启用 `SNAPSHOT_RESUME=1`。Traffic 必须重新由操作者确认；随后
  `PhaseEngine` 仅复用 `input_digest` 与输出 hash 均匹配的 completed phase，其他 phase 必须实跑。
  `snapshots/` 不被恢复动作改写。M1–M5 恢复/快照/状态机 13 项回归通过。Web 按钮接入待完成。
- **2026-08-24 M1–M5 Web 恢复入口**：控制台已接入“重新采集后恢复 M1–M5”。仅在终态且
  `m1_m5` 为 failed/in_progress/awaiting_gate 时显示；服务端派生新的受管 run 并传递
  `--resume-m1m5`。确认框明确提示 Traffic 需重新确认、只有输入与产物 hash 匹配的 phase 可复用。
  Web API / RunManager / M1–M5 / SnapshotStore 30 项回归通过。
