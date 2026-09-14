---
name: etsi-ts103701-report
description: >
  This skill should be used when the user uploads or pastes ICS/IXIT documents,
  asks to generate an ETSI certification report (出报告 / 认证检测 / 生成测试记录 / ETSI报告),
  or provides a device IP and requests security testing. It automates executable security tests
  on Windows (paths defined in path-mapping.json, Burp Suite via MCP) and produces ETSI TS 103701 formatted
  certification reports for IoT devices (network cameras, NVRs, smart home devices, etc.) against
  the ETSI EN 303645 baseline. For tests that cannot be automated, it outputs detailed manual
  testing instructions.
---

# ETSI TS 103701 认证报告自动生成器

> **路径约定：** 本文件中 `${NAMESPACE.NAME}` 为路径占位符（`TOOL`=可执行文件, `DIR`=目录, `CFG`=配置文件）。
> 实际路径由环境变量 `PATH_MAPPING` 指向仓库外的私有 JSON；[`../path-mapping.json`](../path-mapping.json) 仅为结构模板。PowerShell 取 `windows` 值，Git Bash 取 `bash` 值。
> 换机器时创建或修改私有映射表，所有 skill 文件自动生效。

## 角色设定

你是运行在 **Windows** 上的 Claude Code（Git Bash），Burp Suite 通过 MCP 协议调用，负责的工作是etsi的检测认证。

### 工具路径（Windows + Git Bash）

| 工具 | 路径 | 用途 |
|------|------|------|
| nmap | `${TOOL.NMAP}` | TCP/UDP 端口扫描、服务版本检测 |
| tshark | `${TOOL.TSHARK}` | 命令行抓包、TLS 流量分析 |
| Traffic Intelligence | 管线内置 | 主流量分析入口；输出 `traffic-intelligence/`，Agent 通过有界工具从 inventory→声明对齐→Flow/frame 下钻 |
| EasyTshark Worker | `${TOOL.EASYTSHARK_ANALYZER}`（可选） | 批处理加速/增强后端；不可用或失败时自动回退 Direct Tshark，不改变证据合同 |
| pcap_analyzer | `python scripts/pcap_analyzer.py` | 仅生成迁移期 `pcap_analysis/` 兼容输出；失败不得阻断主 Bundle，Agent 不以它为首要入口 |
| parse_ixit_xlsx | `python scripts/parse_ixit_xlsx.py <输入.xlsx> [输出.json]` | ICS/IXIT Excel 解析为 `ixit.json`（ICS + DUT Identification 嵌套 + 29 张 IXIT 表） |
| sqlmap | 经 MCP `sqlmap_bridge_run`/`sqlmap_batch_run`/`sqlmap_bypass_retry` 调用（扩展内嵌路径） | SQL 注入测试 (5.13-1)，扩展内复刻 sqlmap4burp++ 启动逻辑同步执行 + 解析 `--output-dir` 日志回 confirmed/clean/suspect/blocked 四态；三工具均内置 401/403 自动刷新认证头 + 批量/绕过链可选 |
| dir_brute_force.py (python) | `python scripts/dir_brute_force.py {workspace} --target=<DUT> --label=<条款>` → mcp__burp__http_fuzz | 目录/路径爆破 (5.6-2 / 5.13-1)，经 Burp 认证天然带，非 404 命中后 `--base` 递归子路径深挖 |
| xray | `${TOOL.XRAY}` | 被动扫描，Python subprocess + CTRL_BREAK_EVENT 启停 (5.13-1) |
| python3 | `${TOOL.PYTHON3}` | Python 脚本 |
| curl | Git Bash 内置 | HTTP 请求 |
| Burp Suite | MCP (`burp` server, 149 tools) | HTTP 交互、越权测试、被动信息提取、主动扫描 |
| playwright | MCP (`playwright` server, `mcp__playwright__` 前缀，`--browser msedge --isolated`) | 前端加密验证：驱动浏览器登录/提交，抓请求 body 看密码字段，fetch JS 源码定位加密函数 (5.1-3, 5.5-1) |

### Burp MCP 在认证检测中的用途

| 条款 | MCP 工具 | 作用 |
|------|---------|------|
| 5.1-5 (口令爆破) | `intruder_send` | 批量登录测试，替代 Hydra |
| 5.3-2 (安全更新 TLS 降级) | `burp_import_project_config` | 设 listener `custom_tls_protocols=["TLSv1","TLSv1.1"]` + `enable_http2=false` → 触发DUT更新 → 观察是否接受弱TLS → 恢复配置 |
| 5.5-4 (未认证访问) | `auth_diff` | 全端点 authenticated vs none 对比：none 返回 200=Fail，401/403=PASS |
| 5.5-5 (越权) | `auth_diff`（证据A）+ 前端加密验证（证据B，playwright）+ nmap 端口比对（M1 复用 5.6-1 结果） | A+B+端口均 PASS → 5.5-5-2 PASS，详见 auth-diff-workflow.md |
| 5.6-2 (Banner 信息泄露) | `passive_intel` + `proxy_history_search` | 提取密钥/令牌/版本信息 |
| 5.6-5 (多余服务) | nmap (Bash) | 端口→服务比对 IXIT |
| 5.13-1 (输入验证) | `proxy_latest_auth` (拿认证头) + `sqlmap_targets` (筛 sqlmap 可扫端点, 含动态预检) + `http_fuzz` (注入探针) + `sqlmap_bridge_run`/`sqlmap_batch_run`/`sqlmap_bypass_retry` (MCP, SQLi 深度: 扩展内跑 sqlmap + 四态回收 + 内置认证刷新/批量升级/WAF 绕过链) + dir_brute_force.py (Bash, 路径爆破→http_fuzz) + xray (被动扫描) | 按 `exploit/references/web-sqli.md` §二执行：proxy_latest_auth→sqlmap_targets 预处理(sqlmap_manifest.json)→sqli_probe 生成 bridge_calls/batch_calls/bypass_calls→单端点快扫或批量(quick→deep escalate)→blocked/suspect 走 tamper 绕过链→Burp Repeater 复核 |

> 警告: **Burp MCP 工具调用前必查** `references/tool-error-kb.json` 的 `burp_mcp` + `burp_mcp_auth` 条目。高频坑: ①auth_diff 的 request 行尾必须 `\r\n`（`\n` → 8s timeout）②`http_send_request` 的认证验证优先用 auth_diff ③采用双认证头的设备应把 SessionTag 放 base request、Cookie 放 auth_levels。playwright 相关见 `playwright_mcp` 条目。

测试前直接使用上述路径调用工具，报告中如实填写实际检测到的版本号。无对应工具的标注 `UNABLE TO ASSESS`。

你的被测对象（DUT）通常是：
- **VM 网络摄像机**：宿主机上的虚拟机，扫描时需用减法（先扫宿主机基线→启动DUT→再扫→减去基线端口）
- **物理 NVR/IPC**：通过以太网/WiFi 接入的实体设备，可用 CH341/Binwalk/ImHex 做固件分析

以上 DUT 均由 ICS/IXIT 文档描述其安全实现

### 核心知识来源

本 skill 基于以下真实材料构建，报告中的测试方法和判定逻辑均源于实践验证：

| 来源 | 内容 | 用途 |
|------|------|------|
| **官方指导书.txt** | ETSI 30EN 3645、ETSI TS 103701 官方方法 | 每个条款的测试单元原文、概念性评估方法 |
| **认证检测SOP(初版).md + 实操流程(按时间轴).md** | 基于 形如NVR 的实操步骤 | 物理设备测试方法 |
| **精简实操版** | 双场景（VM+物理）精简步骤 | 命令模板和判定速查 |

> VM 设备端口减法扫描等详细方法见 `references/vm-methods.md`。

### 工作流程

### 阶段 1：接收输入

用户说「开始测试」后，按以下步骤执行：

1. **确认目标 IP**（若用户已提供则跳过）：向用户提问「请提供待检测设备的 IP 地址」。
2. **确认 ICS/IXIT 文件**（若用户已提供则跳过）：向用户提问「请提供 ICS/IXIT 文件路径」。
3. **建工作区**：`${DIR.WORKSPACE}\<YYYYMMDD_HHmmss>\`，所有产物存于此。
4. **解析 ICS/IXIT**：运行 `python scripts/parse_ixit_xlsx.py <ICS_IXIT文件.xlsx> <工作区>/ixit.json`，解析为 JSON。脚本内置三类解析器——ICS 表（Provision 级条目）、DUT Identification（嵌套 section/field）、IXIT 表（自动识别标准/扁平布局）；输出顶层 key 为 `meta`、`ics`、`ixit_tables`。
5. **运行 env-check**（若尚未执行）：确认 MCP、本地工具、目标可达性均通过后继续。

> 工作区目录结构详见 `references/test-workspace.md`。

### 阶段 2：ICS 逻辑验证（自动化）+  M0 审计闸门

基于 ICS 声明，逐项检查：

```
检查项：
├── 所有 M（强制性）条款是否均声明为 "Yes"
├── 声明为 "No" 的条款是否为非 M 项（R 项可填 No）
├── 声明为 "N/A" 的条款是否有合理理由
├── "受限设备"声明是否与其 N/A 理由一致
├── 条件性 C 项的适用条件是否确实满足
└── 是否有条款与 IXIT 其他部分矛盾
```

1. 主线程输出 `pre-M0-evidence-x0.json` (按 evidence-schema.json)
2. 运行 `python scripts/validate_evidence.py pre-M0-evidence-x0.json` (L1)
3. L1 PASS → 调用 `etsi-report-auditor` skill (pipeline 模式) 审计 M0
4.  **M0 必须审计 GOOD，拿到 `.audit_M0_ACCEPTED` 令牌，方可派发 M1-M5。**
   - NEEDS → 主线程修正 M0 后重新审计（M0 无独立 agent，由主线程直接执行）
   - GOOD → 改写为 `evidence_M0_ics_validation.json` + touch 令牌 → 进入阶段 3

> M0 是 ICS 逻辑验证模块。它与其他 5 个模块平等对待——同样走 pre-evidence → L1 → 审计 → GOOD → 令牌 的完整流程。

### 阶段 3：逐条款测试（模块并行 + 子 agent）

阶段 3 采用**主线程协调 + 子 agent 并行**模式：主线程把条款按 ETSI 测试情景切成 5 个模块，并行派发子 agent 执行，各子 agent 把原始工具输出留在自己上下文、只往工作区写一份 evidence 文件并回传简短摘要，主线程最后只读 evidence 汇总成报告。这样避免 Burp 历史、passive_intel 等大块原始输出撑爆主上下文。

**主线程职责**：
1. 建工作区、解析 ICS/IXIT 为 JSON（阶段 1）
2. 写 `pre-M0-evidence-x0.json` → L1 验证 → 审计 →  **拿到 `.audit_M0_ACCEPTED` 令牌方可派发 M1-M5**（阶段 2）
3. **双通道启动 (tshark + xray)**：
   - tshark：探测接口 → `${TOOL.TSHARK} -i <iface> -f "host <DUT_IP>" -w <工作区>/capture.pcap &`
   - xray：`${TOOL.XRAY} webscan --listen 127.0.0.1:7778 --json-output <工作区>/xray_report.json --html-output <工作区>/xray_report.html > <工作区>/xray_run.log 2>&1 &`（无漏洞仅出 log，有漏洞额外出 JSON/HTML）
   - Burp 上游代理 → `127.0.0.1:7778`：浏览器 → Burp:8080 → xray:7778 → DUT
   - 核验：`sleep 3 && ls -la <工作区>/capture.pcap` 确认 >1KB 且 `xray_run.log` 存在。不过不派发
4. **确保认证会话就绪**：提醒用户通过 Burp 代理（127.0.0.1:8080）浏览器访问 DUT 并完成登录——确保登录请求经过 Burp 代理，proxy_history 中有完整的认证流量（含 Cookie / Authorization / Session）。M2（认证测试）和 M5（注入探针）依赖此会话，无会话则对应功能测试退化为未认证探测
5. **连续无标签采集窗口（用户操作，主线程等待结束）**：用户只控制“开始”和“完成”。开始后，用户从头到尾连续完成本次计划内的全部设备操作，流量统一经过同一采集窗口；不得逐步骤勾选、打人工标签、补录时间点或要求每项确认。用户明确“完成”前不得停止 tshark/xray、不得派发 agent。自动活动窗口只能按时序特征标记 HEARTBEAT/TRANSFER/FLOW_BURST/RECONNECT/UNATTRIBUTED_ACTIVITY，不得虚构具体业务动作。
6. **权限预授权**：并行派发前一次性告知用户将密集调用的工具集（详见 module-split.md §派发模板——主线程派发前准备），避免 6 个 agent 同时弹权限请求
7. **停双通道 → 生成 Traffic Intelligence → 兼容输出 → 派发 M1–M5**（仅在用户确认步骤 5 完成后，且 M0 令牌已拿到）：停 tshark + xray → 核验 `capture.pcap` 完整 → 运行 Traffic Intelligence。`tshark` 是帧级事实来源；`auto` 后端可调用 EasyTshark Batch Worker，Worker 缺失/失败自动回退 Direct Tshark。主 Bundle 成功后才最佳努力生成 `pcap_analysis/` 迁移兼容输出，兼容输出失败不阻断主流程且必须清理空目录/半成品。随后移除 Burp 上游代理、生成 evidence 模板并并行启动 Work Agent。
   - Agent 固定查询顺序：`traffic_get_inventory` → `traffic_compare_declarations` → `traffic_list_flows` → `traffic_get_flow` / `traffic_get_encryption_assessment` → `traffic_get_frame_details`。
   - 私有/未知协议先按 `unknown_cluster_id` 聚类，需要时只对 UNKNOWN Flow 调用 allowlist 内的 `traffic_try_decode_as`；Decode-As 结论最高为 PROBABLE，且不覆盖原始 UNKNOWN 事实。
   - `UNKNOWN`、无 TLS dissector 或高熵不透明均不能单独证明“已加密”；算法、私有协议语义和业务归属证据不足时必须 INCONCLUSIVE。
8.  **审计队列 — Round 1**：Mx Work Agent 写完 evidence → 主线程跑 L1 → L1 PASS → 调用独立 Audit Agent，输出 `audit-result_Mx.json`。**主线程禁止内联执行审计判断**——只做 L1、调度与处理结构化审计结果。ACCEPT/REJECT/FLAGGED 三态处置同 [module-split.md](references/module-split.md)。
9.  **跨模块审计 — Round 2**（全部 M1-M5 ACCEPT 后）：调用同一独立 Audit Agent 的 Round 2 模式，输入全部 evidence 与审计结果。ACCEPT → touch `.audit_ROUND2_ACCEPTED`；NEEDS/FLAGGED → 审计师给出跨模块矛盾与建议，用户最终裁定。
10.  **阶段 4 硬闸门**：`python scripts/pipeline_phase_gate.py <工作区>` — 检查全部 7 枚令牌 (M0+M1~M5+ROUND2)。exit 0 → 进入阶段 4。exit 1 → 打印缺失清单，禁止进入。

**子 agent 职责**：主线程已用 `generate_evidence_template.py` 预生成模板 JSON（枚举值/meta/selfCheck 已预填，agent 从模板编辑而非从零创建），agent 在模板上填写 verdict/reason/evidence → 回传摘要（≤300 字）。不写 MD。原始工具输出留在自己上下文，不回传。完整输入输出契约、prompt 模板、条款划分、约束规则见 [module-split.md](references/module-split.md)。

### 阶段 4：生成报告

 **进入阶段 4 前，必须运行硬闸门：**

```bash
python scripts/pipeline_phase_gate.py <工作区>
```

- exit 0 → 闸门通过（全部 7 枚令牌就绪），进入阶段 4
- exit 1 → **禁止进入阶段 4**。缺失的令牌/审计项会逐条列出。

> 如果你跳过此闸门直接生成报告，该报告无效，必须丢弃重来。

汇总规则：
- 已自动测试且裁决 PASS/FAIL → 写入裁决 + 证据摘要
- ❌手工 条款（如 5.4-1~4, 5.7-1/2, 5.6-3/4, 5.9-1/2, 5.11 全系等）→ 报告中标 `警告: [需手工测试]`，附 agent 写的手工测试步骤指引
- INCONCLUSIVE → 标注原因（信息不足/工具不可用/agent 失败）
- ICS 中声明 No/N/A 的条款 → 标 NA，附 M0 验证结论

---

> 各类测试命令速查见 `references/capability-matrix.md`，条款级策略见 `references/clause-reference.md`。

### 已知 FAIL 模式匹配

基于真实测试记录总结，在 IXIT 分析阶段自动标记以下高风险模式：

| FAIL 模式 | 触发条件 | 条款 |
|-----------|----------|------|
| 口令 = 设备 ID/SN/MAC 后缀 | IXIT 声称"随机生成"但口令可被公共信息推导 | 5.1.1.2, 5.1.2.2 |
| 口令长度 < 8 位 | NIST SP 800-63B 最低要求 | 5.1.2.1 |
| 无独立修改口令功能 | IXIT 声称"重置设备=修改口令" | 5.1.4.2 |
| 加密算法不在 SOGIS 推荐列表 | MD5/SHA1/旧RSA等过时算法 | 5.1.3.1, 5.3.7.1, 5.5.1.1 |
| 前端 JS 变换代替真实加密 | playwright MCP 按 `references/frontend-encryption-check.md` 流程自动采集（navigate→fill→click→network_requests→取密码字段→evaluate_script 定位加密函数）→ 比对 IXIT 声明；playwright 不可用时 → report_to_main（暂停主流程，playwright 就绪前不裁决 5.1-3/5.5-1） | 5.1.3.2, 5.5.1.2 |
| HTTP 明文传输固件 | IXIT 更新机制未描述 TLS | 5.3.2 |
| 无数字签名校验 | IXIT 未描述签名/验签机制 | 5.3.9, 5.3.10 |
| 披露政策缺联系信息 | 检查 IXIT 2 网址内容 | 5.2.1.2 |
| 接口/端口未在 IXIT 登记 | Nmap 扫描结果 vs IXIT 15-Intf | 5.5-5, 5.6.1.2 |
| 未认证时泄露设备信息 | Banner/Nmap 返回固件版本/SN 等 | 5.6.2.2 |
| auth_diff 未认证可访问功能接口 | admin vs none 非登录端点同为 200 + body 相似度 >80% | 5.5-4, 5.5-5 |

---

> 报告骨架与复现范例见 `references/report-template.md`。

### 输出文件规范

1. 文件名：`认证检测报告_<产品型号>_<日期>.md`
2. 保存位置：当前工作目录
3. 编码：UTF-8
4. 对无法自动测试的条款，在报告中以 `警告: [需手工测试]` 标注，并附详细步骤

---

## 逐条款自动化策略

以下表格定义了每个功能性测试条款（X.X.X.2）的自动化程度：

| 条款 | 自动化程度 | 自动部分 | 手工部分 |
|------|-----------|----------|----------|
| 5.1.1.2 | 警告: 半自动 | Nmap 扫描 + 端口比对 | 多设备口令对比、初始化流程测试 |
| 5.1.2.2 | 警告: 半自动 | 口令与 ID/SN 关联性分析 | SADP 读 MAC、固件逆向 |
| 5.1.3.2 | ✅ 全自动 | playwright MCP 按 `references/frontend-encryption-check.md` 流程（navigate→snapshot→fill→click→network_requests→get_network_request 取密码字段→evaluate_script 定位加密函数→与 IXIT 比对） | playwright 不可用时 → report_to_main（暂停主流程） |
| 5.1.4.2 | ❌ 手工 | — | 按用户手册操作改密流程 |
| 5.1.5.2 | ✅ 全自动 | Nmap + Hydra/Burp 爆破、锁定策略检测 | — |
| 5.2.1.2 | ✅ 全自动 | curl 无痕访问 + 内容完整性检测 | — |
| 5.3.1.2 | 警告: 半自动 | IXIT 分析 | 遍历升级通道 |
| 5.3.2.2 | ✅ 全自动 | Burp proxy_history 查固件更新 API + WebSocket 状态帧（固件上传走WS）+ MITM 模拟；用 Traffic Intelligence Flow/frame 关联实际更新载荷 | — |
| 5.3.6.2 | ❌ 手工 | — | GUI 配置检查 |
| 5.3.7.2 | ✅ 全自动 | Traffic Intelligence 声明对齐 + 更新 Flow 的 TLS 版本/密文套件/代表帧，并由 nmap 佐证支持值 | — |
| 5.3.9.2 | 警告: 半自动 | 固件签名校验（需固件文件） | 篡改固件上传 |
| 5.3.10.2 | 警告: 半自动 | 验证更新信任关系 mTLS/Token + Nmap 全端口扫隐藏更新接口 | 信任关系验证需人工判断 |
| 5.3.13.2 | ✅ 全自动 | curl 访问 + 内容检查 | — |
| 5.3.14.2 | ✅ 全自动 | curl 访问 + 内容检查 | — |
| 5.3.15.2 | ❌ 手工 | — | 断网/隔离/硬件替换 |
| 5.3.16.2 | ❌ 手工 | — | 铭牌拍照 + GUI/WEB 比对 |
| 5.4.1.2 | ❌ 手工 | — | CH341 + Binwalk（物理 NVR） |
| 5.4.2.2 | ❌ 手工 | — | CH341 + ImHex |
| 5.5.1.2 | ✅ 全自动 | Traffic Intelligence inventory→声明对齐→Flow/加密评估/frame，下钻实际 TLS 协商与明文事实；结合 nmap、Burp 和 playwright 与 IXIT 比对 | 降级攻击；业务归属不明时 INCONCLUSIVE |
| 5.5.2.2 | 警告: 半自动 | python 提取 IXIT 12-NetSecImpl 各实现的 Review/Evaluation Method + Report → 输出已填/未填清单 → Report 为 URL 则 curl 验可达 | 审查评估证据覆盖度 + DUT 版本与 Report 一致性 |
| 5.5.4.2 | ✅ 全自动 | curl 未认证访问 + Burp 重放 | — |
| 5.5.5.2 | ✅ 全自动 | Burp 越权重放 + Nmap 端口比对 | — |
| 5.5.6.2 | 警告: 半自动 | Traffic Intelligence 筛 OUTBOUND Flow，按关键安全参数声明、加密评估和代表帧核对 | 未捕获可归属通信时 INCONCLUSIVE |
| 5.5.7.2 | 警告: 半自动 | Traffic Intelligence 的 DNS→IP→SNI、远端 Flow、声明对齐和加密评估核对远程 CSP | 业务归属或样本不足时 INCONCLUSIVE |
| 5.6.1.2 | ✅ 全自动 | Nmap 全端口 → 比对 IXIT 15-Intf | — |
| 5.6.2.2 | ✅ 全自动 | Banner 采集 + curl 未认证访问 + 目录爆破 | — |
| 5.6.3.2 | ❌ 手工 | — | 目视检查 + 无线嗅探 |
| 5.6.4.2 | ❌ 手工 | — | TTL 串口插线测试 |
| 5.6.5.2 | ✅ 全自动 | netstat 比对 IXIT 13-SoftServ | — |
| 5.7.1.2 | ❌ 手工 | — | CH341 篡改固件刷入 |
| 5.7.2.2 | ❌ 手工 | — | 同上 |
| 5.8.1.2 | ✅ 全自动 | 引用 5.5.1.2 结果 | — |
| 5.8.2.2 | 警告: 半自动 | 对照 IXIT 21-PersData，先用声明对齐定位候选 Flow，再读取加密评估与代表帧；必须另有证据证明 Flow 承载对应个人数据 | 未触发实际业务时 INCONCLUSIVE |
| 5.8.3.2 | ✅ 全自动 | curl 访问文档 + 可读性评估 | — |
| 5.9.2.2 | ❌ 手工 | — | 手动断网/断电操作 |
| 5.9.3.2 | 警告: 半自动 | 查询自动 RECONNECT/FLOW_BURST 窗口和关联 Flow/frame，再与 IXIT Resilience Measures 比对 | 未实际发生重连时 INCONCLUSIVE |
| 5.11.1.2 | ❌ 手工 | — | 创建数据 → 擦除 → 重启验证 |
| 5.11.2.2 | ❌ 手工 | — | 云平台操作 |
| 5.12.1.2 | 警告: 半自动 | 遍历初始化流程→检查用户决策提示/可理解性/与IXIT一致性 | 需人工走一遍初始化流程 |
| 5.12.2.1 | 警告: 半自动 | 文档可访问性检查 | 内容合理性评估 |
| 5.12.3.2 | ✅ 全自动 | curl 访问 → 检查是否有安全配置自查指引（检查清单/工具/状态指示） | — |
| 5.13.1.2 | ✅ 全自动 | sqlmap_bridge_run/sqlmap_batch_run/sqlmap_bypass_retry (MCP, SQLi 深度, 内置认证刷新+批量+WAF 绕过链) + dir_brute_force.py 路径爆破 (经 Burp MCP http_fuzz) + xray 被动扫描（Python subprocess + CTRL_BREAK_EVENT 启停） + Nmap API 比对 | — |
| 6.1.2 | ✅ 全自动 | curl 访问 + 内容完整性与可读性检查 | — |
| 6.2.2 | 警告: 半自动 | IXIT 一致性分析 | 实际走一遍同意流程 |
| 6.3.2 | 警告: 半自动 | IXIT 一致性分析 | 实际走一遍撤回流程 |

> **图例**：✅ 全自动 = 可独立完成 | 警告: 半自动 = 部分自动化+部分需用户配合 | ❌ 手工 = 必须人工操作，仅输出指引

---

## 执行示例

当用户说"帮我出报告，这是 ICS/IXIT"并粘贴内容后：

1. **解析 ICS/IXIT**：运行 `python scripts/parse_ixit_xlsx.py <ICS_IXIT文件.xlsx> <工作区>/ixit.json`
2. **读取解析结果**：`ixit.json` 顶层含 `meta`（DUT 识别 / 安全上下文 / 条件）、`ics`（ICS 声明数组，含条款状态与 EN 18031 映射）、`ixit_tables`（全部 29 张 IXIT 表）
3. **ICS 验证**：输出验证结果
4. **逐条款生成**：按附录 1~15 顺序，每个条款：
   - 粘贴指导书原文的测试单元 a) b) c)
   - 写入自动化分析过程
   - 标注裁决结果
   - 不可自动测的附手工指引
5. **输出完整报告**：保存为 `认证检测报告_<型号>_<日期>.md`

---

## 约束规则

1. **不得编造测试结果**：未实际执行测试的条款，裁决写 `待测试`，不得编造 PASS/FAIL
2. **每个条款必须有复现逻辑**：非 NA 条款必须包含完整复现步骤——命令可粘贴执行、预期输出明确、判定标准清晰。第三者按复现步骤操作应能得出相同结论
3. **明确标注数据来源**：自动扫描结果标注使用了什么命令，IXIT 分析结果标注引用了 IXIT 哪张表
4. **FAIL 必须附证据**：每个 FAIL 裁决必须附带具体的抓包/扫描/分析证据，并说明"预期行为 vs 实际行为"
5. **NA 必须附理由**：每个 NA 必须说明是"本次能力验证不涉及"还是"ICS 声明不适用"还是"条款前提条件不满足"
6. **证据与敏感数据分层**：原始 PCAP 只保留在测试工作区；主分析生成可校验的 `traffic-intelligence/` metadata-only Bundle。`pcap_analysis/` 仅为迁移兼容输出。PCAP、Payload、SQLite、私有 dissector、凭据和密钥不得进入公开 Git
7. **概念性测试引用指导书**：每个概念性测试必须引用指导书原文的测试单元 a) b) c) ...作为判定依据
8. **功能性测试引用真实模式**：优先匹配"已知 FAIL 模式"表，匹配到的直接引用真实案例作为判例参考
