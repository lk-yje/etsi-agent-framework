# 自动化能力矩阵

> 各测试类别的命令速查。具体条款策略见 `clause-reference.md`。

## 网络扫描类（全自动）

| 测试内容 | 命令 | 适用场景 |
|----------|------|----------|
| TCP 全端口扫描 | `nmap -Pn -n -sS -sV --open -v -p- <IP>` | 通用 |
| UDP 端口扫描 | `nmap -Pn -n -sU -sV --open -v --max-retries 1 -p- <IP>` | 物理设备 |
| VM UDP 端口采集 | 不扫宿主机 UDP（随机端口干扰），改查进程端口：<br>① `netstat -ano \| findstr ":<已知TCP端口>"` 得 PID<br>② `netstat -ano \| findstr "<PID>"` 得该进程全部监听端口<br>③ 若无法定位进程（DUT 不在本机），跳过 UDP 扫描，记录 `UNABLE TO ASSESS` | VM 设备 |
| VM TCP 端口减法 | ① `nmap -Pn -n -sS -sV --open -p- 0.0.0.0` 扫宿主机基线<br>② 启动 DUT<br>③ `nmap -Pn -n -sS -sV --open -p- <DUT_IP>` 扫 DUT<br>④ 减去宿主机端口 → DUT 独有端口 | VM 设备 |
| TLS 套件枚举 | `nmap --script ssl-enum-ciphers -p <PORT> <IP>` | 通用 |
| Banner 采集 | `nmap -sV -p <PORTS> <IP> && ncat -nv <IP> <PORT>` | 通用 |
| 服务版本探测 | `nmap -sV -p <PORT> <IP>` | 通用 |

## 流量分析类

### 抓包通道（阶段 3.1 主线程启动，双通道并行）

| 通道 | 命令 | 抓什么层 | 给谁用 |
|------|------|---------|--------|
| **Burp 代理** | 用户准备阶段挂 `127.0.0.1:8080`，MCP 暴露 `proxy_history` | 应用层 HTTP | M1/M5（5.5-4/5.5-5/5.6-2/5.13-1） |
| **tshark** | `tshark -i <iface> -f "host <DUT_IP>" -w <工作区>/capture.pcap`（后台，BPF 内核过滤） | 传输层全协议 | M2/M3/M4/M5（5.1.3.2/5.3.2.2/5.5.1/5.5.6/5.5.7/5.9.3） |

> tshark 接口编号需运行时探测：
> ```bash
> # 1. 取本机到 DUT 的出口 IP
> LOCAL_IP=$(curl -s -o /dev/null -w "%{local_ip}" http://<DUT_IP>)
> # 2. 列出所有接口，匹配该 IP 对应的接口编号
> tshark -D | grep -i "$LOCAL_IP"
> # 3. 取匹配行开头的数字即为 -i 参数（如 "5. ..." → -i 5）
> ```

### xray（被动扫描，进主流程）

**xray 与 tshark 同生命周期**——用户确认开始时启动，用户连续完成全部计划内操作并回复「完成」后关闭。不等固定时长，也不要求逐步骤勾选、标签或时间点。5.13-1 阶段与 sqlmap/dir_brute_force.py/Burp http_fuzz 并列执行。

**代理链路**：`Browser → Burp:8080 → xray:7778 → DUT`（Burp 设上游代理 `127.0.0.1:7778`，目标 host 为 DUT IP）。xray 配置 `${CFG.XRAY}` 的 `restriction.hostname_allowed` 在 `/etsi-env-check` 时已覆写为本次 DUT IP。

**重要**: 终端环境下 CTRL_BREAK_EVENT 不可靠→xray 来不及 flush。改用 `taskkill` 直接杀，不依赖信号优雅退出。

**启动**（主线程，阶段 3.1，用户浏览前执行）：
```python
import subprocess, os
os.chdir(r"${DIR.XRAY}")
proc = subprocess.Popen(
    [r"${TOOL.XRAY}", "webscan",
     "--listen", "127.0.0.1:7778",
     "--html-output", r"<工作区>\xray_report.html",
     "--json-output", r"<工作区>\xray_report.json"],
    stdout=open(r"<工作区>\xray_run.log", "w"), stderr=subprocess.STDOUT
)
with open(r"<工作区>\xray_pid.txt", "w") as f:
    f.write(str(proc.pid))
print(f"xray started, PID={proc.pid}")
```

**探活**（主线程 🚪 等待用户期间，每 5 分钟一次）：

```python
import os, time

WS = r"<工作区>"
log_path = os.path.join(WS, "xray_run.log")
pid_file = os.path.join(WS, "xray_pid.txt")

last_size = 0
stall_count = 0

while True:
    time.sleep(300)  # 每 5 分钟探活

    # 检查1: 进程存活
    with open(pid_file) as f:
        pid = int(f.read().strip())
    try:
        os.kill(pid, 0)
    except OSError:
        print(f"[!] xray died (PID={pid}) — check log")
        break

    # 检查2: 日志是否增长
    try:
        cur_size = os.path.getsize(log_path)
    except OSError:
        cur_size = 0

    if cur_size == last_size:
        stall_count += 1
        if stall_count >= 2:
            print("[!] xray log stalled 10min — proxy chain may be broken")
    else:
        stall_count = 0
    last_size = cur_size
```

> 探活循环在用户回复「完成」后由主线程退出。告警不中断流程——用户继续浏览，异常记入日志供事后排查。

**关闭**（主线程，阶段 3.7，用户说「完成」后）：
```powershell
$pid = Get-Content "<工作区>\xray_pid.txt"
taskkill /F /PID $pid 2>$null

$logSize = (Get-Item "<工作区>\xray_run.log").Length
$hasReport = Test-Path "<工作区>\xray_report.json"
Write-Output "xray stopped — log: $logSize bytes, report: $hasReport"
```

**产出**：
| 情况 | 文件 | 证据价值 |
|------|------|---------|
| 有漏洞 | `xray_run.log` + `xray_report.json` + `xray_report.html` | ✅ JSON/HTML 含完整请求/响应 + payload 原文 |
| 无漏洞 | `xray_run.log` 仅此一份 | ✅ 端点列表 + 探针数 + `scanned: N`，广度复核证据 |

### Traffic Intelligence（主流量分析入口）

主线程停抓包后先生成并校验 `<工作区>/traffic-intelligence/`。tshark 是帧级事实来源；EasyTshark 仅是可选批处理 Worker，缺失或失败时回退 Direct Tshark。`pcap_analysis/` 仅为最佳努力的迁移兼容输出，不是 Work Agent 前置条件。

Agent 固定从 `traffic_get_inventory` 开始，再依次使用 `traffic_compare_declarations`、`traffic_list_flows`、`traffic_get_flow`/`traffic_get_encryption_assessment` 和 `traffic_get_frame_details`。未知协议按需查 cluster，远端名称按需查 DNS correlation，重连/传输行为按需查自动 activity windows。

| 条款 | 模块 | 首要查询 | 判定要点 |
|------|:---:|----------|----------|
| 5.1-3 | M2 | alignment → 登录 Flow → encryption/frame | TLS 实际协商与 IXIT 比对；前端密码字段仍需 Playwright/Burp 业务证据 |
| 5.3-2 / 5.3-7 | M4 | Burp 更新请求 → 对应 Flow/encryption/frame | 未捕获实际更新载荷时 INCONCLUSIVE |
| 5.5-1 | M3 | 全局 inventory/alignment → 相关 Flow/encryption/frame | 明文或声明不一致形成风险；UNKNOWN/高熵不等于加密 |
| 5.5-6 | M3 | OUTBOUND Flow + 10-SecParam/11-ComMech 对齐 | 未能归属关键安全参数通信时 INCONCLUSIVE |
| 5.5-7 | M3 | DNS→IP→SNI + 远端 Flow/alignment/encryption | 零外连不能单独推出 N/A/PASS |
| 5.6-1 / 5.6-2 | M1 | 未声明端口/Flow、广播/明文、unknown cluster | 与 nmap、Banner、Burp 主动证据交叉验证 |
| 5.8-1 / 5.8-2 | M3 | 个人数据声明 → Flow/encryption/frame | 必须证明 Flow 承载对应个人数据 |
| 5.9-3 | M5 | RECONNECT/FLOW_BURST window → Flow/frame | 未实际发生重连时 INCONCLUSIVE |

> 原始 PCAP 不进入 Agent 上下文或公开 Git。frame 下钻默认 metadata-only、一次最多 20 帧，不返回 Payload。

## Web 渗透类（全自动，需设备可达）

| 测试内容 | 命令/方法 |
|----------|----------|
| 目录爆破 | `python scripts/dir_brute_force.py {workspace} --target=<DUT> --label=<条款>` → mcp__burp__http_fuzz 路径 FUZZ（内置 IoT/Web 词表，非 404 命中后 `--base` 递归子路径） |
| SQL 注入 | 三工具族: ①`mcp__burp__sqlmap_bridge_run{workspace, endpoint_id:<manifest seq>, mode:quick}` 单端点快扫（主流程：扩展内同步跑 sqlmap + 解析 `--output-dir` 日志回 confirmed/clean/suspect/blocked 四态）→ 命中再 `mode:deep`（深挖，`--level=3 --risk=2 --tamper`）；②`mcp__burp__sqlmap_batch_run{workspace, endpoint_ids:"1,2,3", mode:quick, escalate:true, batch_delay_ms}` 批量跑+quick→deep 自动升级+限速；③`mcp__burp__sqlmap_bypass_retry{workspace, endpoint_id, max_attempts}` WAF 绕过（tamper 链 space2comment→between→charencode→…，逐次追加 `sqlmap/block_ledger.jsonl`）。三工具均带内置认证刷新（`auth_refresh` 默认 true: 401/403 → proxy_latest_auth 重取头 → 重写 .req → 重跑）。数据提取（`--dbs/--tables/--dump`）与手动兜底才直调 sqlmap CLI。完整策略 (含预处理+参数分级+Burp Repeater): `exploit/references/web-sqli.md` §二 |
| 注入探针 | Burp MCP `http_fuzz`（主流程） |
| 未认证访问 | `curl -I <URL>/admin` / `curl <URL>/api/devinfo` |
| 越权重放 (5.5-5) | Burp MCP `auth_diff`: sitemap_query 枚举端点 → 提取令牌 → 逐端点 admin vs none 对比 → body 相似度 >80%+同为200 → FAIL。详见 auth-diff-workflow.md |
| xray 复核 | 必备，与 sqlmap/dir_brute_force.py/Burp http_fuzz 并列进主流程，Python subprocess 自动化启停（见上方 xray 章节） |

## 固件分析类（需用户提供固件文件）

| 测试内容 | 命令 | 输入 |
|----------|------|------|
| 固件解包 | `binwalk -Me <firmware.bin>` | 用户提供固件文件 |
| 口令/密钥搜索 | `grep -r -i "password\|key\|seed\|SN\|MAC" <extracted_dir>` | 固件解包后 |
| 硬编码密钥模式 | `grep -rE "[0-9A-Fa-f]{32,64}" <extracted_dir>` | 固件解包后 |

## 物理操作类（全手工，仅出指引）

| 测试内容 | 说明 |
|----------|------|
| CH341 Flash 读取 | 需编程器 + 拆机 |
| TTL 串口调试 | 需串口线 + 拆机 |
| 整机刷机测试 | 需 CH341 回写 |
| 断电/断网测试 | 需手动操作 |
| 硬件替换测试 | 需备件 |
| 多设备口令对比 | 需多台同型号设备 |

## 前端 JS 分析类（playwright MCP，全自动）

> 依赖 `playwright` MCP server（`npx @playwright/mcp@latest --browser msedge --isolated`，工具前缀 `mcp__playwright__`）。
> 用于验证前端加密实现是否与 IXIT 声明一致。playwright MCP 不可用时 → `report_to_main`（暂停主流程，不允许降级为 Burp/curl 替代）。详见 [frontend-encryption-check.md](frontend-encryption-check.md)。
> **完整流程、工具名映射与判定逻辑见 [frontend-encryption-check.md](frontend-encryption-check.md)。** 其中的示例已匿名化；此处仅列速查。

| 测试内容 | playwright MCP 工具调用顺序 | 适用条款 |
|----------|---------------------------|---------|
| 登录加密验证 | `browser_tabs`(list) → `browser_navigate` 登录页 → `browser_take_screenshot` → `browser_snapshot` 定位 ref → `browser_fill_form` 填测试密码 → `browser_click` 提交 → `browser_network_requests`(static=false) → `browser_network_request`(index=N, part="request-body") 取密码字段 → `browser_evaluate` fetch JS grep `encrypt\|SHA256\|CryptoJS\|btoa\|MD5\|salt\|challenge\|iterations\|isIrreversible` 定位加密函数 → 与 IXIT 比对 | 5.1-3, 5.5-1 |
| 通信加密验证 | `browser_navigate` 功能页 → `browser_snapshot` → 触发提交 (`browser_fill_form`+`browser_click`) → `browser_network_requests`+`browser_network_request` 抓通信负载 → `browser_evaluate` grep `encrypt\|AES\|RSA` → 比对 IXIT | 5.5-1 |
| JS 加密库识别 | `browser_evaluate` grep `CryptoJS\|forge\|sjcl\|jsencrypt\|node-forge\|Web Crypto` → 识别加密库 → 评估安全性 | 5.1-3, 5.5-1 |
| 硬编码敏感参数 | `browser_evaluate` grep `password\|secret\|key\|token\|apiKey\|private` → 检查 JS 源码中是否硬编码凭据 | 5.4-3, 5.6-2 |
| 文档可访问性检查 | **流程**: ①从 IXIT JSON 提取文档 URL ②`browser_navigate(url)` → `browser_snapshot` 检查页面正常加载、文本量足够、含预期关键词 ③`browser_take_screenshot(filename="5.X-X_doc.png")` → PowerShell `Copy-Item` 搬至工作区（命名含条款号便于核实）④playwright 不可用时 → `report_to_main`（不允许降级为 curl 替代）。覆盖 5.2-1/5.8-3/5.12-3/6-1/6-5 | 5.2-1, 5.8-3, 5.12-3, 6-1, 6-5 |

### playwright MCP 工具速查

| 工具名（`mcp__playwright__` 前缀） | 用途 | 参数要点 |
|---|---|---|
| `browser_tabs` | 列出/切换/关闭标签页 | `action: "list"\|"new"\|"select"\|"close"` |
| `browser_navigate` | 导航到 URL，自动开始记录网络请求 | `url: "http://..."` |
| `browser_take_screenshot` | 截取页面截图 | `type: "png"`, `fullPage: true/false` |
| `browser_snapshot` | a11y 树，返回 `ref=fXeY` 元素引用 | ref 值 session-scoped，每次操作前应重新 snapshot |
| `browser_type` | 单字段输入 | `target: "[ref=...]"`, `text: "..."` |
| `browser_fill_form` | 批量填表 | `fields: [{target, name, type, value}]` |
| `browser_click` | 点击元素 | `target: "[ref=...]"`, `element: "描述"` |
| `browser_network_requests` | 列出导航以来的网络请求 | `static: false` 过滤静态资源 |
| `browser_network_request` | 取请求详情（header/body） | `index: N`（1-based）, `part: "request-body"\|"response-body"` |
| `browser_evaluate` | 页面上下文执行 JS | `function: "() => { ... }"` |
| `browser_run_code_unsafe` | 任意 Playwright 代码（escape hatch） | `code: "async (page) => { ... }"` |

> ⚠️ 没有独立的 capture start/stop 工具。`browser_network_requests` 自动记录自上次导航以来的请求。
