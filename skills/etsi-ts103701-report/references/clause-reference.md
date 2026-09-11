# ETSI TS 103701 条款速查表

> 用于报告生成时的快速查表——每个功能测试条款的测试方法原文、自动化策略、已知结果。

## 缩写说明
- **策略**: ✅全自动 ⚠️半自动 ❌手工
- **裁决**: P=PASS F=FAIL N=NA I=INCONCLUSIVE

---

## 概念性测试通用判定框架

以下框架供 agent 在执行每条概念性测试 (X.X.X.1) 时使用，无需逐条款预填判定文本。

### 怎么做

1. **读条款原文**：EN 303 645 该 provision 的 "shall/should" 语句 + 实施指南中的示例。Claude 训练数据中已包含此标准全文，无需外挂 PDF。
2. **读 IXIT 对应字段**：用 python 从 IXIT JSON 提取本条款相关 sheet（如 5.1-1 对应 IXIT 1-AuthMech）。
3. **对照判定**：按下方三类问题逐一打分。

### 判定三问

| # | 问题 | 用于判断 |
|---|------|---------|
| ① | IXIT 描述的设计是否**可逻辑自洽地满足**条款的 shall/should 要求？ | 是 → PASS / 明显矛盾 → FAIL |
| ② | IXIT 内部是否存在**自相矛盾**？（如 1-AuthMech 声称"用户自定义密码"但 10-SecParam 写"出厂固定密码"） | 有 → FAIL |
| ③ | IXIT 信息是否**足够判断**？是否缺失关键细节导致无法验证？ | 不足 → UNCERTAIN |

### 裁决标准

| 裁决 | 条件 | 例子 |
|------|------|------|
| **PASS** | ①②均通过，设计合理能自洽 | "设备初始化强制要求用户设置 8-16 位密码，不允许跳过" → 满足 5.1-1 用户自定义 |
| **FAIL** | ①不通过或②有矛盾 | "密码生成算法为 MD5(MAC 地址)" → 公共信息可推导，违反 5.1-2 不可预测性 |
| **UNCERTAIN** | ③不通过，IXIT 字段为空或描述过于模糊 | "设备支持安全通信"但未列加密套件/协议 — 需用户补充 TLS 版本与密码套件清单 |

### UNCERTAIN 处理

UNCERTAIN 不是失败——是有信息缺口。agent 必须写出**具体缺少什么信息**（不是"文档不完整"这种废话），让用户能直接补充。格式：

```markdown
⚠️ 条款 5.X-X 概念性测试 UNCERTAIN
缺失信息: [具体缺什么，如"11-ComMech 未列出 TLS 版本号"]
需要用户确认: [具体问题，如"请提供设备支持的 TLS 版本和密码套件列表"]
```

### 不需要单独做概念性测试的情况

以下情况概念性测试直接标 NA（不单独裁决，不消耗判断时间）：
- 条款在 ICS 中声明为 No/N/A → 跳过全部测试
- 条款属于纯功能性条款（如 5.3-9 固件签名校验、5.4-1 硬件存储），设计描述与实现完全绑定，概念性结论等同于功能测试结论
- 条款是纯文档类（如 5.2-1 漏洞披露政策），curl 访问到文档内容即覆盖概念

---

## 功能性测试条款速查

## 测试情景 5.1：不使用通用默认口令

| 条款 | 测试案例 | 类型 | 策略 | 核心测试方法 | 已知 FAIL 模式 |
|------|----------|------|------|-------------|---------------|
| 5.1-1 | 5.1-1-2 | 功能 | ⚠️ | ①Nmap全端口→比对IXIT ②多设备口令对比 ③playwright MCP 初始化跳过密码: browser_navigate 初始化页→browser_snapshot 确认密码设置界面→browser_type 密码留空→browser_click 下一步→browser_snapshot 检查: "密码不能为空"=PASS / 进入下一页=FAIL →browser_type 输入弱密码→browser_click→browser_snapshot: 提示长度/复杂度不足=PASS / 接受=FAIL。⚠️ 需DUT恢复出厂状态；注意部分设备初始激活走桌面工具(如SADP)非Web UI，密码设置不在浏览器内→此时标 INCONCLUSIVE | 口令=设备ID后缀；有隐藏认证接口；允许跳过/弱密码 |
| 5.1-2 | 5.1-2-2 | 功能 | ⚠️ | 比对实际口令与IXIT生成机制描述（长度/字符集/唯一性） | 口令<8位；与公共信息关联 |
| 5.1-3 | 5.1-3-2 | 功能 | ✅ | ①读 `pcap_analysis/5.1-3_tls_versions.json` + `pcap_analysis/5.1-3_tls_ciphers.json` (TLS实际协商值) ②nmap ssl-enum-ciphers (DUT支持值) ③Burp proxy_history查登录请求 ④playwright MCP 按 [frontend-encryption-check.md](frontend-encryption-check.md) 流程：browser_navigate→browser_snapshot→browser_fill_form→browser_click→browser_network_requests→browser_network_request取密码字段→browser_evaluate fetch JS grep 定位加密函数→与IXIT比对 ⑤playwright 不可用时 → report_to_main（暂停，禁止降级） | 字符替换代替RSA；MD5/SHA1；加密函数与IXIT不一致 |
| 5.1-4 | 5.1-4-2 | 功能 | ⚠️ | playwright MCP: browser_navigate 登录页→browser_fill_form 登录→browser_navigate 密码修改页→browser_fill_form oldPassword+newPassword+confirmPassword→若弹窗内Confirm按钮 browser_click 超时(视口外)则降级 browser_evaluate click→browser_network_requests 检查 POST 200→退出→新密码登录成功+旧密码登录失败=PASS。⚠️ 需已知登录凭据 | 无独立改密功能(仅重置)；旧密码仍可登录 |
| 5.1-5 | 5.1-5-2 | 功能 | ⚠️ | ①Nmap全端口→确认认证接口 ②Burp Intruder 重放登录请求（前端有加密则重放密文 payload，无加密则替换明文密码字段）③观察锁定阈值: 记录第N次尝试后触发锁定+锁定持续时间，比对IXIT声明。⚠️ 仅做 1-2 次失败探针确认机制存在，完整锁定测试标手工 | 锁定次数与IXIT不一致 |

## 测试情景 5.2：漏洞披露

| 条款 | 测试案例 | 类型 | 策略 | 核心测试方法 | 已知 FAIL 模式 |
|------|----------|------|------|-------------|---------------|
| 5.2-1 | 5.2-1-2 | 功能 | ✅ | curl无痕访问→检查:①联系信息②确认收到时限③状态更新时限 | 缺联系信息 |
| 5.2-2 | 5.2-2-1 | 概念 | ⚠️ | 用 python 精确提取 IXIT `3-VulnTypes` 各漏洞类型的 Action/Time Frame，回查 `2-UserInfo` 漏洞披露政策，再核对 `4-Conf` 的漏洞行动确认。逐类看行动、时限、责任与第三方协作是否自洽；缺任一关键描述→INCONCLUSIVE，不能凭政策标题判 PASS。 | 某类漏洞无行动/时限；政策与流程矛盾；未确认执行 |
| 5.2-3 | 5.2-3-1 | 概念 | ⚠️ | 用 python 提取 IXIT `5-VulnMon`，分开评估持续监测、判断对 DUT 的影响、纠正/缓解三环节，并核对 `4-Conf` 漏洞监控确认。单一公告订阅或“定期关注”不等于闭环；任一环节描述不足→INCONCLUSIVE。 | 无持续监测/影响识别/纠正机制；无确认 |

## 测试情景 5.3：保持软件更新

| 条款 | 测试案例 | 类型 | 策略 | 核心测试方法 | 已知 FAIL 模式 |
|------|----------|------|------|-------------|---------------|
| 5.3-1 | 5.3-1-2 | 功能 | ⚠️ | 读IXIT JSON→遍历6-SoftComp每个机制→汇总证据（5.3-2-2直接+5.3-9/5.3-10间接+观察）→LLM逐机制判定是否可被滥用。⚠️ 5.3-2-2 INCONCLUSIVE→对应机制同判，不阻塞其他。 | — |
| 5.3-2 | 5.3-2-2 | 功能 | ✅ | **①TLS降级MITM**: `burp_import_project_config` 设 `custom_tls_protocols=["TLSv1","TLSv1.1"]` + `enable_http2=false` → 触发DUT更新 → 观察是否接受弱TLS完成更新下载 → 恢复配置。**②固件篡改**: Burp代理劫持更新请求；上传旧/篡改固件→验证拒绝；中断传输→验证恢复。⚠️ 元数据查询≠固件下载，未触发实际载荷传输→INCONCLUSIVE。⚠️ WebSocket坑：`proxy_websocket_history`禁全量拉取，`direction=server_to_client`+`max_results≤20`分批取状态帧。固件上传走 WebSocket：`proxy_history` 找 `/updateFirmware` + status 101 → `websocket_list` 定位连接 → `websocket_get_messages` 查 `server_to_client` 帧 → statusCode=4 + fileError = 拒绝 PASS。 | HTTP明文；MD5；无签名 |
| 5.3-3 | 5.3-3-1 | 概念 | ⚠️ | 读取 ICS.required_ixit_entries + IXIT `6-SoftComp` / `7-UpdMech`，按组件建立“组件→已登记更新机制”表。每个组件至少有一条用户可理解的更新路径才可 PASS；缺组件—机制关系或可用性描述→INCONCLUSIVE。 | 组件无更新机制；机制未登记 |
| 5.3-4 | 5.3-4-1 | 概念+功能佐证 | ⚠️ | 先判 ICS/IXIT 是否支持自动更新；不支持则 N/A。支持时核对每组件的自动检查/更新机制，用 playwright `browser_navigate→browser_snapshot` 复核更新设置的默认状态。可配置时至少一种自动机制默认启用。不得点击保存或实际升级。 | 自动机制全关闭；组件无自动更新 |
| 5.3-5 | 5.3-5-1 | 概念+功能佐证 | ⚠️ | 从 `7-UpdMech` 查 DUT 触发、初始化后行为和周期；Traffic 窗口触发一次检查，用 Burp `proxy_history` 索引请求并用 UI snapshot 佐证。单次抓包不能证明“定期”，无周期说明→INCONCLUSIVE。 | 仅人工检查；无周期 |
| 5.3-6 | 5.3-6-2 | 功能 | ⚠️ | playwright MCP: browser_navigate 登录→系统维护→固件升级页→browser_snapshot 寻找自动更新相关开关(自动检查/自动下载/自动安装/通知新版本等，不同设备开关数量不同)→记录每个开关默认状态(ON/OFF)→browser_click 切换→验证可修改。输出: 各开关默认状态+是否可修改。⚠️ 需已知登录凭据 | 自动更新不可禁用；更新通知不可关闭 |
| 5.3-7 | 5.3-7-1 | 概念+功能 | ✅* | 用 Burp 索引更新流量→读 `pcap_analysis/5.5-1_server_hello.json` / `5.5-1_proto_hierarchy.txt` → nmap `ssl-enum-ciphers` 佐证支持值→逐项比对 `7-UpdMech` / `11-ComMech` / `12-NetSecImpl` 的 TLS、套件、证书、签名算法。未捕获实际更新载荷→INCONCLUSIVE（`✅*` 仅指链路自动化）。 | 更新载荷明文；弱算法；元数据查询误当更新流量 |
| 5.3-8 | 5.3-8-1 | 概念 | ⚠️ | 读取 `6-SoftComp` / `7-UpdMech`，按组件核对及时部署与执行确认机制。缺少时效、部署路径或确认机制时必须 INCONCLUSIVE；不能只凭“支持升级”判 PASS。 | 无部署/确认能力；宣传文字替代证据 |
| 5.3-11 | 5.3-11-1 | 概念+功能佐证 | ⚠️ | 先判自动检查更新前提；前提不成立且 ICS=N/A→N/A。前提成立时，从 `7-UpdMech` 和 UI snapshot 核对通知可识别、明显且包含缓解的安全风险；手动检查不是通知。真实推送事件未发生时不伪造。 | 仅版本提示；无通知机制 |
| 5.3-12 | 5.3-12-1 | 概念+功能佐证 | ⚠️ | 从 `7-UpdMech` 判断更新是否中断基本功能；明确不影响→按 escape clause PASS。会中断时，用 UI snapshot/用户观察索引 DUT 上的中断提示；未经确认不得主动中断业务功能。 | 中断无 DUT 侧通知 |
| 5.3-9 | 5.3-9-2 | 功能 | ⚠️ | 篡改固件上传→观察拒绝；断网离线校验。固件上传流量查询同 5.3-2：Burp `proxy_history`→WebSocket→`websocket_get_messages` `direction=server_to_client`+`max_results≤20`。 | — |
| 5.3-10 | 5.3-10-1 | 功能 | ✅ | 验证更新信任关系:IXIT文档分析mTLS/Token/用户确认等授权实体验证机制；Nmap全端口扫隐藏更新接口→比对IXIT 7-UpdMech | 无信任关系校验；未登记更新接口 |
| 5.3-13 | 5.3-13-2 | 功能 | ✅ | curl访问公示页→检查:①可访问②无需注册③支持期限已发布 | — |
| 5.3-14 | 5.3-14-2 | 功能 | ✅ | curl访问→检查:①理由②替换计划③期限④无需注册 | — |
| 5.3-15 | 5.3-15-2 | 功能 | ❌ | 断网→验证本地功能；独立隔离环境；硬件替换操作 | 断网后本地功能丢失 |
| 5.3-16 | 5.3-16-2 | 功能 | ⚠️ | playwright MCP: browser_navigate DUT Web UI 首页/系统信息页→browser_snapshot 提取设备型号→与 nmap HTTP title/SSL cert CN 对比→与 IXIT 型号声明对比。输出三栏对比表: Web UI \| nmap \| IXIT → 一致=PASS。⚠️ 需已知登录凭据 | IXIT未申报型号名称；Web UI型号与铭牌不一致 |

## 测试情景 5.4：安全存储敏感安全参数

| 条款 | 测试案例 | 类型 | 策略 | 核心测试方法 | 已知 FAIL 模式 |
|------|----------|------|------|-------------|---------------|
| 5.4-1 | 5.4-1-2 | 功能 | ❌ | CH341读Flash→Binwalk解包→检索敏感参数存储格式 | 明文存储密码/密钥 |
| 5.4-2 | 5.4-2-2 | 功能 | ❌ | 多渠道读硬件ID→软件篡改尝试→整机刷机覆盖 | WEB可修改SN |
| 5.4-3 | 5.4-3-2 | 功能 | ❌ | 固件逆向→搜索硬编码密钥模式→多台设备对比 | 多台同型号恒定密钥 |
| 5.4-4 | 5.4-4-2 | 功能 | ❌ | 多台设备导出同类密钥对比→确认每台唯一 | 批量相同密钥 |

> ⚠️ 基线测试范围：侵入式硬件分析（热风枪吹Flash）不在基准要求内。"无反证即合规"原则适用。

## 测试情景 5.5：安全通信

| 条款 | 测试案例 | 类型 | 策略 | 核心测试方法 | 已知 FAIL 模式 |
|------|----------|------|------|-------------|---------------|
| 5.5-1 | 5.5-1-2 | 功能 | ✅ | ①读 `pcap_analysis/5.5-1_server_hello.json` (逐帧TLS版本+密文套件→与IXIT比对) + `pcap_analysis/5.5-1_client_hello.json` (ClientHello逐帧L4完整TLS清单→降级攻击/版本不匹配检测) + `pcap_analysis/5.5-1_proto_hierarchy.txt` (协议分层) + `pcap_analysis/5.5-1_conversations.txt` (TCP会话字节统计→找非TLS大流量) + `pcap_analysis/5.5-1_http_check.json` (有无HTTP明文) + `pcap_analysis/5.5-1_http_responses.json` (响应状态码+Content-Length→区分302重定向/200明文内容) ②nmap ssl-enum-ciphers ③Burp proxy_history查通信请求 ④playwright MCP 按 [frontend-encryption-check.md](frontend-encryption-check.md) 流程抓通信负载、定位加密实现→与IXIT比对 ⑤降级攻击测试 ⑥playwright 不可用时 → report_to_main（暂停，禁止降级） | HTTP明文；加密与IXIT不一致；前端弱加密伪装 |
| 5.5-2 | 5.5-2-2 | 功能 | ⚠️ | python 提取 IXIT 12-NetSecImpl 各实现的 Review/Evaluation Method + Report → 输出已填/未填清单 → Report 为 URL 则 curl 验可达 → 手工审查评估证据覆盖度 + DUT 版本与 Report 一致性 | 无审查评估证据；自研密码学未经评估 |
| 5.5-3 | 5.5-3-1 | 概念 | ⚠️ | python 从 IXIT `6-SoftComp` 筛出 Cryptographic Usage 组件→逐组件关联 Update Mechanism/`7-UpdMech`→检查算法/原语升级的兼容性和副作用处理。组件随受控固件更新可作为机制佐证；未关联机制或未说明副作用→INCONCLUSIVE。 | 密码学组件不可更新；未考虑算法升级副作用 |
| 5.5-4 | 5.5-4-2 | 功能 | ✅ | **①认证控制**: `auth_diff` 全端点 authenticated vs none 对比：none 返回 200+body 一致=FAIL，401/403=PASS。**②加密验证**: playwright MCP 前端加密分析（同5.1-3流程）+ `pcap_analysis/5.5-1_server_hello.json` TLS密码套件/证书与IXIT比对。两项均PASS → 5.5-4-2 PASS。 | 未认证可访问功能页；加密与IXIT不一致 |
| 5.5-5 | 5.5-5-2 | 功能 | ✅ | **A+B+端口**: ①Burp auth_diff 全端点 admin vs none 对比 (证据A, 见 auth-diff-workflow.md) ②前端加密逻辑与IXIT一致性 (证据B, 见 frontend-encryption-check.md) ③nmap 全端口 vs IXIT 15-Intf。三者均PASS → 5.5-5-2 PASS | 未认证可访问功能接口；前端加密与IXIT不一致；未登记端口 |
| 5.5-6 | 5.5-6-2 | 功能 | ⚠️ | python 先以 IXIT `10-SecParam→11-ComMech` 建立关键安全参数—通信机制映射，再读 `pcap_analysis/5.5-6_*` 五类产物核对机密性与实际加密设置。零外连不等于 PASS；未捕获可归属关键安全参数通信→INCONCLUSIVE。 | 关键安全参数明文/非TLS传输；实测与IXIT矛盾 |
| 5.5-7 | 5.5-7-2 | 功能 | ⚠️ | python 以 IXIT `10-SecParam→11-ComMech` 筛远程可访问通信，再读 `5.5-7_remote_ips.json`、`all_destinations.json` 和非TLS结果。只有确认不存在远程 CSP 通信才 N/A；不能只因 remote_ips 为空推断。 | 远程关键安全参数明文传输 |
| 5.5-8 | 5.5-8-1 | 概念 | ⚠️ | python 提取 IXIT `14-SecMgmt`，逐类 CSP 核对生成、分发、存储、更新、停用/归档/销毁、过期/泄露处理，并核对 `4-Conf` 安全管理确认。生命周期环节缺失或描述不足必须逐项报告。 | CSP 生命周期管理缺环；未确认执行 |

## 测试情景 5.6：最小攻击面

| 条款 | 测试案例 | 类型 | 策略 | 核心测试方法 | 已知 FAIL 模式 |
|------|----------|------|------|-------------|---------------|
| 5.6-1 | 5.6-1-2 | 功能 | ✅ | Nmap全端口→比对IXIT 15-Intf Enable/Disable | 未登记端口/WiFi接口 |
| 5.6-2 | 5.6-2-2 | 功能 | ✅ | ①读 `pcap_analysis/5.6-2_broadcast.json` (广播/组播流量→信息泄露渠道) + `pcap_analysis/5.6-2_plaintext_services.json` (非TLS非HTTP的TCP明文Banner→版本/SN泄露) ②ncat Banner采集 ③curl未认证路径 ④Burp目录爆破 | 未认证披露版本/SN/IP |
| 5.6-3 | 5.6-3-2 | 功能 | ❌ | 四项检查：①目视核对暴露物理接口 vs IXIT ②UART/JTAG调试接口保护验证 ③rfkill/iwconfig无线接口检查 ④间歇性/休眠接口在不需要时是否禁用原始功能 | — |
| 5.6-4 | 5.6-4-2 | 功能 | ❌ | 对暴露接口插线测试+用调试工具测试其他接口 | 调试接口可用 |
| 5.6-5 | 5.6-5-2 | 功能 | ✅ | netstat查看监听服务→比对IXIT 13-SoftServ | 多余默认服务 |
| 5.6-6 | 5.6-6-1 | 概念 | ⚠️ | python 精确提取 IXIT `16-CodeMin` 的代码最小化技术，判断是否适合把代码减少到 DUT 必需功能，并检查是否涵盖未使用/不需要代码。网络扫描不能证明无死代码；描述泛泛→INCONCLUSIVE。 | 明确保留无用功能/死代码；技术与最小化目标矛盾 |
| 5.6-7 | 5.6-7-1 | 概念 | ⚠️ | python 提取 IXIT `17-PrivlCtrl`，按组件建立权限—限制机制映射，判断是否共同促进职责分离、知其所需和最小权限。root 进程不自动 FAIL，须结合能力限制/隔离机制；缺映射→INCONCLUSIVE。 | 网络/普通组件无约束运行于最高权限 |
| 5.6-8 | 5.6-8-1 | 概念 | ⚠️ | python 提取 IXIT `18-AccCtrl`，对每个机制判定是否硬件级（含嵌入硬件固件）以及是否实际控制内存访问；需关联机制、控制对象和边界。仅列术语未说明效果→INCONCLUSIVE。 | 无硬件级内存控制；机制不能控制内存访问 |
| 5.6-9 | 5.6-9-1 | 概念 | ⚠️ | python 提取 IXIT `19-SecDev`，逐项核对培训、需求/设计、安全编码、实现工具、测试、审查、归档、部署及适用时第三方处理，再核对 `4-Conf` 安全开发确认。政策标题不等于覆盖全部阶段。 | 缺适用安全开发阶段；未确认实施 |

## 测试情景 5.7：软件完整性

| 条款 | 测试案例 | 类型 | 策略 | 核心测试方法 | 已知 FAIL 模式 |
|------|----------|------|------|-------------|---------------|
| 5.7-1 | 5.7-1-2 | 功能 | ❌ | 篡改系统固件分区→上电→观察是否拒绝启动 | 篡改后正常启动 |
| 5.7-2 | 5.7-2-2 | 功能 | ❌ | 破坏系统镜像重启→观察告警+网络隔离 | 无告警/正常联网 |

## 测试情景 5.8：个人数据安全

| 条款 | 测试案例 | 类型 | 策略 | 核心测试方法 | 已知 FAIL 模式 |
|------|----------|------|------|-------------|---------------|
| 5.8-1 | 5.8-1-2 | 功能 | ⚠️ | python 以 IXIT `21-PersData→11-ComMech` 建立个人数据—通信机制映射，复用 5.5-1 TLS/明文证据并比对 `12-NetSecImpl`。必须证明捕获流量确实承载对应个人数据；未触发业务样本→INCONCLUSIVE。 | 个人数据明文传输；实测与IXIT矛盾 |
| 5.8-2 | 5.8-2-2 | 功能 | ⚠️ | 对照 IXIT 21-PersData 逐类核实：①概念评估加密算法安全性（AES/TLS/SHA256 等有无已知可行攻击）②功能验证每类数据实际传输加密：读 `pcap_analysis/5.5-1_proto_hierarchy.txt` + `pcap_analysis/5.5-1_server_hello.json` (确认加密层覆盖对应协议，非流配置元数据)。⚠️ 流通道配置参数（codec/分辨率/码率）不属于敏感个人数据，不可据此判 FAIL。未触发实际业务（邮箱/人脸/POS 操作、RTP 视频流）时标 INCONCLUSIVE | 视频流HTTP明文；敏感数据无加密 |
| 5.8-3 | 5.8-3-1 | 功能 | ✅ | curl访问传感器文档→可读性评估→目视检查传感器 | — |

## 测试情景 5.9：系统故障恢复

| 条款 | 测试案例 | 类型 | 策略 | 核心测试方法 | 已知 FAIL 模式 |
|------|----------|------|------|-------------|---------------|
| 5.9-1 | 5.9-1-2 | 功能 | ❌ | 手动断网→手动断电→验证恢复 | — |
| 5.9-2 | 5.9-2-2 | 功能 | ❌ | 断网10分钟→验证本地功能；断电重启→验证配置保留 | 断网数据丢失(未补传) |
| 5.9-3 | 5.9-3-2 | 功能 | ⚠️ | python 先读 IXIT `11-ComMech` 的 Resilience Measures，再读 `5.9-3_syn_bursts.json`、timestamps、retransmissions 比对有序连接与重连行为。普通稳定流量无 SYN 突发不证明故障后的回退；未发生重连→INCONCLUSIVE。 | 无延迟密集重连；实测与弹性措施矛盾 |

## 测试情景 5.10：遥测数据

| 条款 | 测试案例 | 类型 | 策略 | 核心测试方法 | 已知 FAIL 模式 |
|------|----------|------|------|-------------|---------------|
| 5.10-1 | 5.10-1-1 | 概念 | ✅ | IXIT分析:安全检查方案存在性+适用性 | — |

## 测试情景 5.11：用户数据删除

| 条款 | 测试案例 | 类型 | 策略 | 核心测试方法 | 已知 FAIL 模式 |
|------|----------|------|------|-------------|---------------|
| 5.11-1 | 5.11-1-2 | 功能 | ❌ | 创建设备数据→执行擦除→重启验证→Flash读残留 | 擦除后数据残留 |
| 5.11-2 | 5.11-2-2 | 功能 | ❌ | 云平台创建数据→解绑/注销→检查云端残留 | — |
| 5.11-3 | 5.11-3-1 | 功能 | ❌ | 按删除说明文档执行→评估文档覆盖度+简明性 | — |
| 5.11-4 | 5.11-4-1 | 功能 | ❌ | 执行删除→检查确认通知 | 无删除确认 |

## 测试情景 5.12：安装和维护

| 条款 | 测试案例 | 类型 | 策略 | 核心测试方法 | 已知 FAIL 模式 |
|------|----------|------|------|-------------|---------------|
| 5.12-1 | 5.12-1-2 | 功能 | ⚠️ | playwright MCP: browser_navigate 登录→点击 Configuration Wizard(或恢复出厂后初始化流程)→逐页 browser_snapshot 提取每步决策点 → 每项检查: ①有无默认勾选?(预选框→FAIL) ②术语可理解?(专业缩写如DST未展开→标记) ③是否有Skip/跳过按钮?(强制决策无跳过→标记) ④涉及隐私/服务条款时是否有链接可查看? →与IXIT 26-UserDec比对。输出: 每决策点评估表。⚠️ 需DUT恢复出厂或使用Configuration Wizard | 决策隐藏；预选框默认同意；术语难懂；与IXIT不一致 |
| 5.12-2 | 5.12-2-1 | 功能 | ⚠️ | 按安全设置文档配置DUT→检查安全决策覆盖度 | — |
| 5.12-3 | 5.12-3-2 | 功能 | ✅ | curl访问制造商文档→检查是否提供安全配置自查指引（检查项清单/自动检查工具/安全状态指示） | 无安全自查文档；文档不包含检查步骤 |

## 测试情景 5.13：输入验证

| 条款 | 测试案例 | 类型 | 策略 | 核心测试方法 | 已知 FAIL 模式 |
|------|----------|------|------|-------------|---------------|
| 5.13-1 | 5.13-1-2 | 功能 | ✅ | **①路径发现**: `python scripts/dir_brute_force.py {workspace} --target=<DUT> --label=5.13-1` 生成 mcp__burp__http_fuzz 路径 FUZZ 指令（内置 IoT/Web 词表，经 Burp 代理认证天然带）→ 非 404 命中用 `--ingest` 筛 hits → 目录型命中加 `--base=<path>` 递归子路径深挖 + `sitemap_query` 提取 API 端点（自动聚合去重，替代 proxy_history 前缀切分法）。**②参数注入**: `http_fuzz` 对已发现端点的参数/Cookie/Body 标记 `FUZZ` 注入 SQLi/XSS/命令 payload。**③深度注入**: `sqlmap_bridge_run`/`sqlmap_batch_run`/`sqlmap_bypass_retry`（MCP，扩展内复刻 sqlmap4burp++ 启动逻辑：读 manifest 取 request→写 .req→同步跑 sqlmap→解析 `--output-dir` 日志回 confirmed/clean/suspect/blocked 四态；三工具均内置认证刷新 `auth_refresh=true`（401/403→proxy_latest_auth 重取→重写 .req→重跑）；批量场景用 `sqlmap_batch_run{endpoint_ids, escalate:true, batch_delay_ms}` quick→deep 自动升级；blocked/suspect 端用 `sqlmap_bypass_retry{max_attempts}` 沿 tamper 链迭代）+ Burp Repeater 按 `exploit/references/web-sqli.md` §二执行：proxy_latest_auth 拿认证头→sqlmap_targets 预处理(sqlmap_manifest.json, 过滤/去重/参数分级/动态预检)→sqli_probe 生成 bridge_calls/batch_calls/bypass_calls→快扫(mode=quick: `--level=1 --risk=1 --smart --delay=1`)→仅可疑端点深挖(mode=deep: `--level=3 --risk=2 --tamper`)→Burp Repeater 手工复核。**④广度复核**: xray 被动扫描 + nmap 端口 vs API 比对。⚠️ dir_brute_force.py 路径爆破 hits=0（http_fuzz 全 404/空）且 sitemap 无 DUT 条目 → http_fuzz 和 sqlmap_bridge_run 无靶可打 → INCONCLUSIVE。 | 未登记远程API |

## 测试情景 6：数据保护规定

| 条款 | 测试案例 | 类型 | 策略 | 核心测试方法 | 已知 FAIL 模式 |
|------|----------|------|------|-------------|---------------|
| 6-1 | 6-1-2 | 功能 | ✅ | curl访问个人数据文档→内容完整性+可读性 | — |
| 6-2 | 6-2-2 | 功能 | ⚠️ | 实走同意流程:自由+明显+明确 | 预选框/默认同意 |
| 6-3 | 6-3-2 | 功能 | ⚠️ | 实走撤回流程→与IXIT一致性 | 注销≠撤销授权 |
| 6-4 | 6-4-1 | 概念 | ⚠️ | python 逐项提取 IXIT `24-TelData` 的遥测数据、目的与引用的 `21-PersData`，为每项建立“数据—目的—必要性”判断。泛化的“分析/体验改进”用途不能直接判 PASS；目的或必要性缺失→INCONCLUSIVE。 | 超出所述功能必要范围；用途矛盾 |
| 6-5 | 6-5-2 | 功能 | ✅ | curl访问遥测文档→内容完整性 | — |
