# 证据充分性审计标准

> 审计者在审查报告中每条裁决的证据时，按此标准逐项核验。
> 核心原则：**可索引、可复现、可对照、不越界**。

---

## 一、证据分级标准

| 等级 | 定义 | 示例 | 审计判定 |
|:---:|------|------|:---:|
| **L1** | 直接可复现的完整证据 | pcap frame 91 含 HTTP POST + 响应 200 + Follow TCP Stream 全文 + 预期 vs 实际对照 | ✅ 充分 |
| **L2** | 可索引但缺少部分要素 | 引用了 pcap 文件名但无 frame 编号；有命令但无实际输出 | ⚠️ 基本充分，需标注缺失项 |
| **L3** | 有证据文件但无法索引 | 只说"见附件 pcap"无 frame 号/无 Follow 内容/无截图路径 | 🔍 证据不足，不可独立验证 |
| **L4** | 无证据，仅有结论描述 | "经测试，通信已加密" — 无命令/无输出/无 frame 引用 | ❌ 无证据，裁决不成立 |
| **L5** | 证据与结论矛盾 | 引用的 pcap frame 显示 HTTP 200 但判决称"加密通信" | ❌ 证据矛盾，裁决错误 |

---

## 二、证据类型规格

### 2.1 pcap/流量分析证据

```
最低要求（L2+）:
├── pcap 文件路径（可访问）
├── tshark 分层统计: -q -z io,phs 输出（协议分布帧数）
├── 关键 frame 编号
├── 关键 frame 的 Follow TCP Stream 或字段提取输出
└── 预期 vs 实际对照

升级到 L1 需要额外:
├── tshark 命令完整参数（含接口编号、BPF filter）
├── TLS 协商的实际 cipher suite + 版本
└── HTTP 明文请求计数（若判 FAIL 因"部分明文"）
```

**审计检查项**：

| # | 检查点 | 缺失时的判定 |
|---|--------|:---:|
| 1 | pcap 文件存在且非空（>1KB） | ❌ 无证据 |
| 2 | 引用含 frame 编号 | 🔍 不可索引 |
| 3 | 分层统计表（用于判"全部通信加密"类结论） | 🔍 证据不足以支撑"全部" |
| 4 | Follow TCP Stream 内容（用于判"明文传输"类结论） | 🔍 不可验证 |
| 5 | DUT 出站连接目的地址列表（用于 5.5-7 远程 CSP 判断） | 🔍 N/A 理由不充分 |

### 2.2 Nmap/端口扫描证据

```
最低要求:
├── 完整 nmap 命令（含参数 -sS -sV -p-）
├── 完整 nmap 输出（保存为 .txt 路径）
├── 端口-服务-版本-状态 对照表
└── IXIT 15-Intf Enable/Disable 对照

VM 设备额外要求:
├── 宿主机基线扫描结果
└── DUT 端口 = DUT 扫描 - 宿主机基线（减法过程）
```

**审计检查项**：

| # | 检查点 | 缺失时的判定 |
|---|--------|:---:|
| 1 | 扫描了 TCP 全端口（-p-） | 🔍 可能遗漏隐藏端口 |
| 2 | 扫描了 UDP（或记录了跳过理由） | 🔍 可能遗漏 UDP 服务 |
| 3 | 每个开放端口对照了 IXIT 15-Intf | ❌ 5.6-1 裁决无依据 |
| 4 | VM 设备做了端口减法 | ❌ 宿主机端口可能被误判为 DUT 端口 |

### 2.3 Burp/HTTP 交互证据

```
最低要求:
├── 具体请求（URL + Method + Headers + Body 关键字段）
├── 具体响应（Status Code + Headers + Body 关键片段）
├── Burp proxy_history 请求序号 或 直接 curl 命令
└── 预期 vs 实际对照
```

**审计检查项**：

| # | 检查点 | 缺失时的判定 |
|---|--------|:---:|
| 1 | 越权测试：列出了请求身份 A vs 身份 B 的响应差异 | 🔍 不可验证 |
| 2 | 爆破测试：记录了尝试次数 + 锁定触发点 + 锁定时长 | 🔍 证据不完整 |
| 3 | 未认证访问测试：curl 命令完整可粘贴执行 | 🔍 不可复现 |

### 2.4 sqlmap/http_fuzz 路径爆破/xray 证据

```
最低要求:
├── 命令完整参数
├── 输出文件路径（sqlmap_output.txt、fuzz_dir_*.json 等）
└── 结果摘要：端点数、探针类型、发现漏洞或 clean
```

**xray 特殊要求**：
- 无漏洞时：`xray_run.log` 存在且末尾含扫描统计（端点覆盖数 + 探针数）
- 有漏洞时：额外 `xray_report.json` / `xray_report.html` 存在
- 若 xray 未运行 → 需说明原因（如"无 xray 工具"）

### 2.5 前端 JS 加密分析证据（playwright MCP）

```
最低要求:
├── 对 IXIT 1-AuthMech 加密描述的引用
├── playwright 采集: navigate → fill → click → network_requests → 取密码字段
├── browser_evaluate 提取的 JS 加密函数名/算法
└── 与 IXIT 的比对：一致/不一致/IXIT 未描述
```

**若无 playwright MCP**（禁止降级）：
```
├── verdict: INCONCLUSIVE
├── reason: "playwright MCP 不可用 — 前端加密必须由浏览器真实执行，禁止 Burp/手工替代"
└── action: report_to_main（暂停主流程，playwright 就绪后再继续）
```

### 2.6 IXIT 文档分析证据

```
最低要求:
├── 引用的 IXIT sheet 名称（如 1-AuthMech）
├── 引用的具体行/字段内容摘要
├── 分析逻辑：为何 PASS / FAIL / UNCERTAIN
└── UNCERTAIN 时：写明具体缺失什么信息
```

**IXIT JSON 结构参考**（来自真实 ixit.json 样本）：

```
ixit.json 顶层结构:
├── meta: 元数据
│   ├── dut_identification: {section: {field: value}} 嵌套结构
│   ├── security_context: 安全上下文
│   └── conditions: 条件列表
├── ics: ICS 声明数组（约 78 条 Provision）
│   └── 每条: {applicability, reference, status, en18031, support, detail_justification, required_ixit_entries}
└── ixit_tables: 29 张 IXIT 表
    ├── 1-AuthMech ~ 29-InpVal
    └── 每表: {meta: {...}, rows: [{col1: val1, ...}, ...]}
```

**审计时重点检查 IXIT 引用精度**：
- 报告只说"根据 IXIT 文档"→ 🔍 不精确，需要标注
- 报告写"IXIT 1-AuthMech 第 1 行描述..."→ ✅ 精确

### 2.7 curl/Web 访问证据

```
最低要求:
├── 完整 curl 命令（含 -I/-v/-k 等参数）
├── HTTP 状态码 + 关键响应头
├── 响应体关键内容（如隐私政策关键段落）
└── URL 地址
```

---

## 三、裁决类型的证据门槛

### PASS 的最低证据标准

| 裁决场景 | 最低要求 |
|---------|---------|
| 纯 IXIT 分析 PASS | IXIT 字段引用 + 逻辑自洽分析 + 无反证 |
| 功能测试 PASS | 命令 + 实际输出 + 满足了哪些条件 + 无反证 |
| escape_clause PASS | escape 条件确认（引用 IXIT 具体字段证明条件成立） |
| 手工条款 PASS（无反证） | 标注"无反证即合规"原则 + IXIT 字段引用 |

### FAIL 的最低证据标准

| 裁决场景 | 最低要求 |
|---------|---------|
| 任何 FAIL | **强制**: 预期行为 vs 实际行为 对照 |
| 协议/加密 FAIL | pcap frame 编号 + 实际协议/算法 vs 标准要求 |
| 接口未登记 FAIL | nmap 端口号 + 服务名 + IXIT 15-Intf 对应行 |
| IXIT 矛盾 FAIL | 矛盾的两个 IXIT 字段引用 + 为何不能自洽 |

> **审计红线**：FAIL 无预期 vs 实际对照 → 直接标为 ❌ 证据不足，裁决不成立。

### INCONCLUSIVE 的证据标准

| 场景 | 要求 |
|------|------|
| 工具不可用 | 写明哪个工具、为何不可用 |
| 无法触发测试场景 | 写明尝试了什么、为何失败 |
| 信息不足 | 写明具体缺什么、需用户提供什么 |

> **审计红线**：INCONCLUSIVE 无具体原因（只写"无法测试"）→ 退回。

### N/A 的证据标准

| 场景 | 要求 |
|------|------|
| 条件性条款前提不满足 | 引用 ICS/IXIT 证明条件确实不满足 |
| 受限设备豁免 | 引用受限设备声明 + 合理理由 |
| 功能不存在 | 引用 ICS Support=N/A 或 IXIT 相关描述 |

> **审计红线**：N/A 理由循环论证（"没发生过所以不需要"）→ 直接标为 ❌。

---

## 四、证据链完整性检查

### 跨条款一致性

| 检查项 | 矛盾例 |
|--------|--------|
| 同一 pcap 的结论一致性 | 5.5-1 判 FAIL(HTTP 明文) 但 5.8-1 判 PASS(个人数据加密) — 同源流量不应出现矛盾 |
| ICS 声明一致性 | ICS 5.5-1=Y (支持加密) 但报告 5.5-1 判 FAIL — 结论需与 ICS 对齐 |
| 继承链一致性 | 5.5-1 FAIL → 5.8-1 应 FAIL (或解释为何不同) |

### 工具版本可追溯性

| 检查项 | 要求 |
|--------|------|
| nmap 版本 | 命令输出中可见 `Nmap version X.XX` |
| tshark 版本 | 命令输出中可见或 `tshark --version` |
| sqlmap 版本 | 命令输出首行 |
| 其他工具 | 至少列出工具名和版本号，不可写"最新版" |

---

## 五、审计时证据判定速查

| 报告写... | 审计判定 | 问题 |
|-----------|:---:|------|
| "经测试，通信已加密" | ❌ | 无证据，L4 |
| "见附件 capture.pcap" | 🔍 | 无 frame 编号，L3 |
| "tshark frame 91 显示 HTTP POST，响应 200，无 TLS 握手" | ✅ | 可索引 + 可复现，L1 |
| "根据 IXIT 描述..." | 🔍 | 未引用具体 sheet/行，L3 |
| "IXIT 1-AuthMech Row1: 用户自定义 PIN，6 位数字..." | ✅ | 精确引用，L1 |
| "nmap 发现 5 个开放端口" | 🔍 | 未列出端口号，L3 |
| "端口 80/tcp HTTP, 443/tcp HTTPS, 554/tcp RTSP" | ✅ | 可索引，L1 |
| "与 IXIT 不一致" | ❌ | 未说明哪条 IXIT 什么内容 vs 实际什么内容，L4 |
| "IXIT 11-ComMech 声称 TLS 1.3，实际 pcap frame 91 为 HTTP 明文" | ✅ | 精确对照，L1 |

---

*End of evidence standards reference.*
