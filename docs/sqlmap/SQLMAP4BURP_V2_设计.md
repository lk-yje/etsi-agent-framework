# sqlmap4burp++ v2（AI 时代重设计）方案

> 背景：sqlmap4burp++（c0ny1 v0.2，2017 前后，540 行 7 文件）设计前提是"人在终端前"——右键→弹终端→人眼看。
> 本次先做的「桥」（`sqlmap_bridge_run` 把插件启动逻辑内嵌进 burpmcp）是绕道：驱动 sqlmap 的逻辑放错了层。
> v2 的正解是 **把 sqlmap 驱动逻辑放进它该在的层，做成机器可驱动、evidence 一等公民、LLM 在环可插拔**。
> 桥不白做——其 Runner + LogParser + 三态判定 + 双措辞 not-injectable 全部验证过，是 v2 核心模块的种子。

---

## 一、设计原则

1. **程序化优先** — 一切能力必须能被外部（agent / 其他扩展）以 JSON 驱动；UI 只是其中一个客户端。
2. **Evidence 一等公民** — 每次扫描产出可复现、可索引的证据包，不是终端里的眼痕。满足框架 §12 证据质量门。
3. **LLM 在环可插拔** — 决策点定义为接口，可接 agent（外部驱动，默认，可审计）也可接内置 LLM（插件自驱，可选）。
4. **单源真相** — sqlmap 驱动逻辑只活在一个地方；调用方（MCP 工具 / UI / 未来独立插件）都是薄客户端。

## 二、架构分层

```
┌─────────────────────────────────────────────────┐
│  LLM 决策层（DecisionHooks 接口，可插拔）          │
│   selectInjectionPoints / bypassStrategy /        │
│   triageResult                                    │
├─────────────────────────────────────────────────┤
│  服务层（机器驱动接缝）                             │
│   in-process: SqlmapService 门面（MCP 工具直调）   │
│   cross-process: localhost HTTP/JSON（未来独立插件│
│   时启用，镜像 sqlmapapi 的 task/scan 模型）        │
├─────────────────────────────────────────────────┤
│  任务层（TaskManager）task 生命周期/quick→deep 升级│
├─────────────────────────────────────────────────┤
│  驱动层（SqlmapRunner + SqlmapLogParser）          │
│   命令拼装 / 同步执行 / timeout / --output-dir /   │
│   日志→三态 + 阻塞账本                              │
├─────────────────────────────────────────────────┤
│  证据层（EvidenceStore）扁平布局 + task.json +      │
│   block_ledger.jsonl（Phase3 绕过账本）             │
│  会话层（SessionManager，Phase2）认证刷新            │
│  配置层（ConfigSnapshot，Phase4）JSON 预设          │
│  UI 层（UiTab，Phase4）任务列表/状态/证据浏览器      │
└─────────────────────────────────────────────────┘
```

### 接缝决策（Phase 1 实现）

设计原稿以 localhost HTTP 服务为唯一入口，理由"Burp 扩展间无 IPC"。但当前 sqlmap 逻辑已住在 burpmcp 同一进程内，MCP 工具与服务门面同进程直调，**HTTP loopback 是纯开销**。因此：

- **Phase 1**：服务接缝 = `SqlmapService` 进程内门面，MCP 工具 `sqlmap_bridge_run` 是它的一号客户端。
- **未来**：若要把 v2 独立成单独插件（burpmcp 变 HTTP 客户端），在门面上加一个 HTTP 适配器即可，业务层不动。

## 三、服务接口契约

镜像 sqlmapapi 语义，一个 task 一次扫描。进程内门面方法（未来 HTTP 化时一一映射）：

| 门面方法 | HTTP 映射 | 语义 |
|---|---|---|
| `taskCreate(spec)` | `POST /task/new` | 建任务 → task_id |
| `scanStart(taskId)` | `POST /scan/start` | 写 .req → 同步跑 sqlmap → 写 evidence |
| `scanData(taskId)` | `GET /scan/data` | 完成态证据 JSON |
| `scanStop(taskId)` | `POST /scan/stop` | 强杀（对应 timeout_seconds） |

入参（来自 MCP 工具 / 未来 HTTP）：
```
workspace      : string   // 工作区绝对路径
endpoint_id    : string   // manifest seq 或 .req 文件路径
mode           : string   // quick | deep
python/sqlmap_path/extra_options/timeout_seconds   // 可覆盖，缺省走 saveExtensionSetting 语义
```

## 四、证据模型（EvidenceStore）

> Phase 1-4 落地布局（外部契约保持桥的扁平布局，不引入 per-task 目录）：
> `task.json` 结构化四态记录为增量；`block_ledger.jsonl`（JSON Lines，Phase 3）为 WAF 绕过审计账本。

```
{workspace}/sqlmap/{METHOD}_{path}.req     # 字节精确 .req（Cookie+SessionTag 双头保留）
{workspace}/sqlmap/output/                 # sqlmap --output-dir 原生日志（框架文档已引用此路径）
{workspace}/sqlmap_output.txt              # sqlmap stdout 重定向
{workspace}/sqlmap_stderr.txt              # sqlmap stderr 重定向
{workspace}/sqlmap/task.json               # 结构化四态记录（最近一次运行，审计/报告索引）
{workspace}/sqlmap/block_ledger.jsonl      # WAF 绕过账本（JSON Lines 追加，Phase 3）
{workspace}/sqlmap_config.json             # Phase 4 预设（JSON，见 §十 偏差记录）
```

`task.json` 四态 schema（与 evidence_M5 对齐，`status` 三态 + `triage` 四态）：
```json
{"ok": true, "task_id": "...", "status": "found|clean|blocked",
 "triage": "confirmed|clean|suspect|blocked",
 "injected_parameter": null, "payload": null, "injection_points": 0,
 "mode": "quick", "url": null, "method": null, "path": null,
 "output_dir": null, "request_file": null, "log_files": [],
 "exit_code": 0, "timed_out": false, "stdout_tail": "",
 "note": null, "error": null}
```

`block_ledger.jsonl` 每行一条绕过尝试（可被 SqlmapUiTab「Reload Ledger」回读）：
```json
{"attempt": 0, "tamper": null, "status": "blocked", "triage": "blocked",
 "parameter": null, "payload": null, "cmd": "sqlmap -r ...", "ts": "..."}
```

## 五、LLM 决策环（三个 hook，Phase 3 已落地）

接口定义（`DecisionHooks.kt`，Phase 3 已实现；Phase 1 只留接口位）：
1. `selectInjectionPoints(manifest, priorResults)` → 扫描顺序 + 注入点策略。（未落地：当前 manifest 全量跑，agent 协调顺序）
2. `bypassStrategy(ledger, payload)` → 下一轮 tamper（`DefaultHooks.TAMPER_CHAIN = [space2comment, between, charencode, randomcase, hex, percentage]`），有界重试，每轮写 block_ledger。→ `WafBypassLoop.kt` 落地。
3. `triageResult(status, exitCode, stdoutTail)` → confirmed/clean/suspect/blocked。`DefaultHooks` 落地：found→confirmed, clean→clean, else WAF_SIGNAL/HEURISTIC/exitCode==0→suspect else blocked。

接线现状：**插件自驱**（`DefaultHooks` 内置规则驱动：tamper 链 + 四态 triage），外部 agent 经 MCP 仍可覆盖 hooks（`runWithBypass` 的 `hooks` 参数）。满足红队穷尽/求真纪律 —— 每次绕过尝试均入 block_ledger.jsonl 可追溯。

## 六、模块/文件划分（落点：burpmcp 源码）

```
src/main/kotlin/com/burpmcp/ultra/sqlmap/
  SqlmapRunner.kt        # ProcessBuilder list 拼装、同步执行、timeout、--output-dir、stdin→EOF
                         #   重定向（Win NUL / Unix /dev/null）——防 sqlmap 把未关闭的
                         #   PIPE stdin 当目标源自读而阻塞（Phase1 harness 抓出的桥潜伏 bug）
  SqlmapLogParser.kt     # Parameter/Payload 正则 + not-injectable 双措辞
  SqlmapEvidenceStore.kt # 任务布局 + task.json schema + .req 字节精确写 + writeBlockLedger
  SqlmapTaskManager.kt   # task 生命周期、fresh 输出目录、auth-retry 循环、runBatch 批量升级
  SqlmapService.kt       # 进程内门面（runScan/runBatch/runWithBypass，MCP 工具与未来 HTTP 的接缝）
  SessionManager.kt      # (Phase2) AuthRefresher fun interface + 401/403 信号 + 重写认证头
  DecisionHooks.kt       # (Phase3) triageResult + nextTamper 决策接口 + DefaultHooks 内置规则
  WafBypassLoop.kt       # (Phase3) tamper 链有界迭代，逐次写 block_ledger.jsonl
  ConfigSnapshot.kt      # (Phase4) 读 {workspace}/sqlmap_config.json → modePresets/defaultMode/...
```

调用侧：
- `tools/etsi/EtsiSqlmapBridgeTools.kt` → 薄客户端，注册 `sqlmap_bridge_run`/`sqlmap_batch_run`/`sqlmap_bypass_retry`，调 `SqlmapService`
- `tools/etsi/SqlmapAuthRefresh.kt` → Montoya 层共享 helper（prefGetFor / defaultAuthRefresher）
- `ui/SqlmapUiTab.kt` → (Phase4) Swing 面板，registerSuiteTab("Sqlmap v2")
- `bridge/AnalysisBridge.kt` → sqlmapBridgeRun 已迁移；`findLatestAuthTokens` 保留供 auth 刷新复用

## 七、与现有资产接缝与迁移（桥不白做）

| 现在（桥） | 迁移后（v2） |
|---|---|
| `AnalysisBridge.sqlmapBridgeRun` 内嵌启动逻辑 | `SqlmapRunner` + `SqlmapLogParser` 原生实现（种子搬入） |
| `sqlmap_bridge_run` 工具实现三态 | 薄客户端调 `SqlmapService` |
| `sqlmap_targets` manifest | 直接喂 `scanStart`（endpoint_id = manifest seq） |
| `proxy_latest_auth` | 喂 `SessionManager` 刷新 hook（Phase 2） |
| sqli_probe quick→deep | `TaskManager` 原生升级（Phase 2） |
| 框架四处对齐 + recipe 注入 | **接口契约不变**，零框架改动 |

**桥的 Runner + LogParser + 三态判定 + 双措辞 not-injectable，验证过、可用，直接成为 v2 核心模块种子**——迁移不是推倒，是搬家到正确的层。外部契约（MCP 工具名、参数、返回 JSON）完全不变，框架侧已对齐的文档零改动。

## 八、实施阶段

- **Phase 1**（替换桥，本次）：`SqlmapRunner` + `SqlmapLogParser` + `SqlmapEvidenceStore` + `SqlmapTaskManager` + `SqlmapService` → `EtsiSqlmapBridgeTools` 改薄客户端 → 删 AnalysisBridge 内嵌逻辑 → 编译 + 三态回归。
  - **验证**：gradle compileKotlin 干净；`scratch/sqlmap-kt-test/SqlmapHarness.java`（javac harness 直调 `SqlmapService.INSTANCE`）驱动**真实 sqlmap** 打真实靶场 —— `/vuln → found`（param=id, payload=`id=1 AND 4320=4320`, exit 0）、`/benign → clean`（exit 0）；task.json + .req + output-dir log 均落盘。
  - **Phase 1 抓出的 bug**：ProcessBuilder 默认 PIPE stdin 永不关闭 → sqlmap 视非 TTY stdin 为管道目标源 `self.stdin.read()` 阻塞至超时；`SqlmapRunner` 补 stdin→NUL//dev/null EOF 重定向后通过。此 bug 桥里一直潜伏（Python 镜像用 communicate() 天然 EOF，掩盖了它），standalone 直跑真模块才暴露。
- **Phase 2**（✅ 已落地）：`SessionManager`（fun interface AuthRefresher，401/403 信号 → 刷新 → 重试，注入式免 Montoya 依赖）+ `TaskManager.runBatch`（多端点 + escalate quick→deep 升级 + batchDelayMs 限速 + summary 四态汇总）。
- **Phase 3**（✅ 已落地）：`DecisionHooks` + `WafBypassLoop` + 四态 triage。绕过链有界重试，每次尝试追加 `block_ledger.jsonl`。
- **Phase 4**（✅ 已落地）：`ConfigSnapshot`（JSON 预设）+ `SqlmapUiTab`（Swing 面板，workspace/config/批量/绕过/ledger 回读）+ recipe 模板（框架侧对齐见 §十一）。

### 落地验证（`SqlmapHarness.java` 驱动真实 sqlmap 1.10.5 × 本地靶场 vuln_server，2026-08-17）

| 场景 | 输入 | 结果 |
|------|------|------|
| 单端点快扫 | /vuln mode=quick | `status=found triage=confirmed`, param=`id`, payload=`id=1 AND 2754=2754`, exit 0 |
| 对照排除 | /benign mode=quick | `status=clean triage=clean`（sqlmap not-injectable 双措辞命中） |
| 批量+升级 | batch [1,2] escalate=true | summary `{total:2, confirmed:1, clean:1}`；seq1 escalated=true（found→deep）、seq2 escalated=false（clean） |
| WAF 绕过（决断） | /vuln bypass maxAttempts=3 | 1 次尝试即 decisive 停止（found），block_ledger.jsonl 落盘 |
| WAF 绕过（被拦） | /connrefused bypass | tamper 链 attempt0 blocked → space2comment → between → charencode（4 次全 blocked/suspect），完整账本 |
| 认证刷新 | /auth（无 X-Refreshed=401） | runOnce1 全 401 → looksAuthStale → AuthRefresher 注入 X-Refreshed → runOnce2 `status=found triage=confirmed`；最终 .req 含 X-Refreshed；服务器计数 `{with:60, without:2}` |
| Phase 4 预设 | sqlmap_config.json default_mode=deep | mode=default → 解析为 deep，vuln 命中 |

## 九、开放决策（后续再定，不阻塞 Phase 1-4）

1. 是否将 v2 独立成单独扩展（burpmcp 走 HTTP 客户端）——取决于是否有第三方消费方。门面已预留 HTTP 适配位。
2. LLM 内置客户端（插件自驱模式）选型——默认不做，走 Agent 驱动；`DefaultHooks` 为规则版（确定性、可审计），agent 可覆盖。
3. `selectInjectionPoints` hook 未落地——当前 manifest 全量跑；后续可在 `WafBypassLoop`/`runBatch` 里加注入点排序钩子。
4. block_ledger WAF 指纹库与框架 `tool-error-kb.json` 复用——待框架侧统一，当前 ledger 为纯 JSON Lines 追加，UiTab 可回读。

---

## 十、偏差记录（设计 → 落地的偏离，Phase 2-4）

| # | 设计原稿 | 落地 | 原因 |
|---|---------|------|------|
| 1 | ConfigSnapshot 读 **YAML** 预设 | 读 **JSON** `sqlmap_config.json` | 避免引入 SnakeYAML 依赖；JSON 与 Kotlin 序列化零适配 |
| 2 | per-task 目录 + `block_ledger.json` | **扁平布局** + `block_ledger.jsonl`（JSON Lines 追加） | 外部契约（框架文档引用的 `sqlmap/output/` 路径）不变；JSONL 追加免读写锁，UiTab 逐行回读 |
| 3 | `selectInjectionPoints` hook | 未落地，manifest 全量跑 | 当前批量规模小，agent 协调顺序足够；接口位保留 |
| 4 | 认证刷新 hook 由 `proxy_latest_auth` 单点接线 | 模块内 `fun interface AuthRefresher` 注入，Montoya 层 `SqlmapAuthRefresh.defaultAuthRefresher` 默认实现走 `AnalysisBridge.findLatestAuthTokens` | 保持 sqlmap 模块免 Montoya 依赖（可单元测试/Java harness 直调）；MCP 工具按 `auth_refresh` 参数接线 |
| 5 | 三态 status（found/clean/blocked） | **四态 triage**（confirmed/clean/suspect/blocked），status 保留三态 | 新增 suspect 承接 WAF 信号/启发式/exitCode==0 的中间态，驱动绕过链（§10 求真——疑似不冒充结论） |
| 6 | 快扫→深扫手工切换 | `sqlmap_batch_run` `escalate=true` 自动 quick→deep | agent 只需一次批量调用，升级逻辑内建 |
| 7 | Python 前缀恒为解释器 | **空白 python = standalone sqlmap.exe**（无解释器前缀） | Windows 真机常用独立 exe；`takeIf{isNotBlank}` 曾误把空白当默认值导致 "can't open file" |
| 8 | 认证预检门禁（agent 每调用前手工 proxy_latest_auth） | 三工具内置 `auth_refresh`（默认 true）自动刷新重跑 | 401/403 信号由 SessionManager 正则识别，免 agent 手工步骤，杜绝过期头静默出 clean 假阴性 |

## 十一、框架对齐（Phase 2-4 落地后，本次同步）

sqlmap 三工具族落地后，框架侧引用点全部对齐到 `sqlmap_bridge_run`/`sqlmap_batch_run`/`sqlmap_bypass_retry`：

- `framework/clause_tool_map.json` → 5.13-1 burp_mcp 工具表 + method（批量/绕过/内置认证刷新）
- `skills/etsi-ts103701-report/SKILL.md` → 工具表 + 5.13-1 行 + 5.13.1.2 自动化行
- `skills/etsi-ts103701-report/references/capability-matrix.md` → SQL 注入行（三工具族）
- `skills/etsi-ts103701-report/references/clause-reference.md` → 5.13-1 深度注入段
- `skills/etsi-ts103701-report/references/module-split.md` → M5 工具表 + tool 分工 + 权限预授权 + 认证预检门禁（sqlmap 三工具免预检）
- `pipelines/etsi/personas/work-agent.md` → 工具表 + 5.13-1 行
- `skills/exploit/references/web-sqli.md` → §2.1 总流程 + §2.4 执行（三工具分工表 + auth_refresh + 绕过链）+ 判定写回 + §2.6 集成 + §2.7 常见问题
- `scripts/sqli_probe.py` → 输出 `bridge_calls[]`（单端点 quick+deep）+ `batch_calls[]`（批量 escalate）+ `bypass_calls[]`（绕过链）；附 Python 3.8 `from __future__ import annotations` + UTF-8 stdout 兼容修复
