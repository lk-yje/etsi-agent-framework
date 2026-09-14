# 测试产物工作区

> 每次认证检测开始前，在 `${DIR.WORKSPACE}\` 下新建以当前时间戳命名的工作区文件夹，本次测试的所有产物——原始扫描数据、抓包、xray 报告、截图，以及 ICS/IXIT 解析后的 JSON——统一存放于此。报告中所有证据路径均指向该文件夹。

## 工作区创建

```bash
# 时间戳格式 YYYYMMDD_HHMMSS，例如 20260717_140300
WORKSPACE="${DIR.WORKSPACE}/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$WORKSPACE"
echo "$WORKSPACE"   # 后续所有产物路径以此为根
```

一次检测对应一个工作区。报告引用的 `.txt` / `.pcap` / `.html` / 截图 / JSON 路径均位于此文件夹内。

## ICS/IXIT 文件解析

用户上传的 ICS/IXIT 文件为 Excel（`.xlsx`），由本仓库脚本解析为 JSON 存入工作区：

```bash
python scripts/parse_ixit_xlsx.py <ICS_IXIT文件.xlsx> "$WORKSPACE/ixit.json"
```

脚本内置三类解析器——ICS 表（Provision 级条目）、DUT Identification（嵌套 section/field）、IXIT 表（自动识别标准/扁平布局）。输出统一为 `ixit.json`，顶层 key：`meta`（dut_identification / security_context / conditions）、`ics`（ICS 声明数组）、`ixit_tables`（29 张 IXIT 表）。后续阶段 2 的 ICS 逻辑验证与 IXIT 表格提取均读取该 JSON。

> 解析核对：可用 `python scripts/compare_ixit_html.py <旧.json> <新.json> [输出.html]` 生成新旧比对页，人工复核解析结果差异。

## 工作区目录结构示例

```
${DIR.WORKSPACE}\<时间戳>\
├── ixit.json             # parse_ixit_xlsx.py 解析 ICS/IXIT 的产出
├── evidence_M0_ics_validation.md   # 阶段2 ICS 逻辑验证（主线程产出）
├── evidence_M1_attack_surface.md   # 阶段3 各模块 evidence（子 agent 产出）
├── evidence_M2_auth_password.md
├── evidence_M3_comm_crypto.md
├── evidence_M4_update_integrity.md
├── evidence_M5_input_dataprotection.md
├── 认证检测报告_<型号>_<日期>.md     # 阶段4 最终报告
├── baseline_tcp.txt       # nmap 基线扫描
├── dut_tcp.txt            # nmap DUT 扫描
├── capture.pcap           # tshark 抓包（M2/M3/M4/M5 共享）
├── traffic-intelligence\  # 首要流量分析 Bundle（manifest 完整性校验）
│   ├── manifest.json
│   ├── inventory.json
│   ├── flows.jsonl
│   ├── frames.jsonl       # metadata-only，不含 Payload
│   ├── encryption-assessments.jsonl
│   ├── declaration-alignments.json
│   ├── unknown-protocol-clusters.json
│   ├── automatic-activity-windows.json
│   └── dns-correlations.json
├── pcap_analysis\         # 迁移期兼容输出；失败时不保留空目录/半成品
├── xray_run.log           # xray 被动扫描运行日志（必备，端点覆盖率 + 探针数统计）
├── xray_report.html       # xray 漏洞报告（有漏洞时产出）
└── screenshots\           # 证据截图
```

## evidence 文件（阶段 3 产出）

阶段 3 采用模块并行：主线程写 `evidence_M0`（阶段 2），5 个子 agent 各写 `evidence_M1`~`evidence_M5`。每份 evidence 是对应模块的 distilled 事实依据——测试过程、IXIT 引用、裁决（PASS/FAIL/NA/待测试）、证据路径。子 agent 把原始工具输出留在自己上下文，只往工作区写 evidence + 回传简短摘要；主线程最后只读这 6 份 evidence 汇总成报告，避免原始大输出撑爆主上下文。

evidence 命名与模块划分见 `module-split.md`。
