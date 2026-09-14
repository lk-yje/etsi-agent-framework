# Traffic Intelligence 查询与兼容说明

> 本文件名为历史兼容名。当前首要入口是工作区内可校验的 `traffic-intelligence/` Bundle 及其 Agent 查询工具；`pcap_analysis/` 只是迁移期兼容输出。

## 证据边界

- `tshark` 是帧级事实来源，负责从同一份 `capture.pcap` 提取标准协议、端点、端口、TLS 握手、DNS 和帧引用。
- EasyTshark 是可选批处理 Worker。选择 `auto` 或 `easytshark_batch` 时，Worker 缺失、超时或产物无效必须回退 Direct Tshark，并把原因记录进 manifest。
- Agent 不得直接遍历 PCAP、猜测路径或读取任意文件；只能使用绑定到当前工作区的有界 Traffic Intelligence 工具。
- 默认 `metadata_only`：Flow/frame 查询不返回 Payload，所有 frame 响应必须标明 `payload_included=false`。
- Bundle manifest 与 PCAP SHA-256 不一致、产物散列不一致或 `complete=false` 时，全部流量证据不可用。

## Agent 固定查询顺序

1. `traffic_get_inventory`：确认分析后端、Flow/端点/未知簇数量、对齐计数、警告和高风险 Flow。
2. `traffic_compare_declarations`：读取 IXIT 11-ComMech/15-Intf 与实测流量的 `MATCH`、`MISMATCH`、`NOT_OBSERVED`、`UNDECLARED_OBSERVED` 或 `INSUFFICIENT_EVIDENCE`。
3. `traffic_list_flows`：按方向、传输层、端点、端口、协议、加密分类、`unknown_cluster_id` 或 `alignment_status` 缩小范围。
4. `traffic_get_flow` 与 `traffic_get_encryption_assessment`：按稳定 `flow_id` 读取协议依据、TLS 信息、DNS/SNI、加密分类及限制。
5. `traffic_get_frame_details`：只对候选 Flow 的代表帧做 metadata 下钻，一次最多 20 帧。

按需使用：

- `traffic_list_unknown_clusters` / `traffic_get_unknown_cluster`：检查行为相似的 UNKNOWN/私有协议 Flow。
- `traffic_list_dns_correlations`：核对 DNS answer → endpoint IP → Flow → SNI 的证据链。
- `traffic_list_activity_windows`：查询无人工标签的 HEARTBEAT、TRANSFER、FLOW_BURST、RECONNECT 或 UNATTRIBUTED_ACTIVITY 窗口。
- `traffic_try_decode_as`：仅对 UNKNOWN Flow 尝试 allowlist 内的 dissector。结果写入独立派生目录，最高只能是 `PROBABLE`，不得覆盖原始 Flow/UNKNOWN 结论。

## 主 Bundle 产物

| 产物 | 用途 |
|------|------|
| `manifest.json` | PCAP 散列、后端、版本、fallback 原因和各产物散列 |
| `inventory.json` | 有界总览、计数、警告和高风险 Flow |
| `flows.jsonl` | 双向规范化 Flow、稳定 ID、端点/端口/方向/协议候选 |
| `frames.jsonl` | 无 Payload 的帧级元数据与协议事实 |
| `flow-frame-index.jsonl` | Flow 到代表帧的索引 |
| `encryption-assessments.jsonl` | 加密分类、依据、限制和 frame refs |
| `declarations.json` | 从 IXIT 11-ComMech 与可关联 15-Intf 提取的声明 |
| `declaration-alignments.json` | 声明与实测 Flow 的逐维对齐结果 |
| `unknown-protocol-clusters.json` | 私有/未知协议的稳定行为聚类，不含 Payload |
| `automatic-activity-windows.json` | 基于时序自动识别的无人工标签活动窗口 |
| `dns-correlations.json` | DNS、实际远端 IP、Flow 与 SNI 的可审计关联 |

## 条款查询映射

| 条款 | 首要查询 | 判定边界 |
|------|----------|----------|
| 5.1-3 | inventory → alignment → 登录候选 Flow → encryption/frame | TLS 实际协商与 IXIT 比对；前端口令变换仍需 Playwright/Burp 业务证据 |
| 5.3-2 / 5.3-7 | Burp 定位更新请求 → 对应 Flow/encryption/frame | 元数据查询或普通 Web TLS 不能替代固件更新载荷证据 |
| 5.5-1 | inventory → alignment → 全部相关 Flow → encryption/frame | HTTP 明文或声明不一致可形成风险；UNKNOWN/高熵不能当作已加密 |
| 5.5-4 / 5.5-5 | Burp auth_diff + alignment/Flow | 认证控制与通信保护必须分别有证据 |
| 5.5-6 | `OUTBOUND` Flow + 关键安全参数声明 + encryption/frame | 未捕获可归属关键安全参数的通信时为 INCONCLUSIVE |
| 5.5-7 | DNS correlation + 远端 Flow + alignment/encryption | 远端列表为空不自动代表 N/A 或 PASS |
| 5.6-1 | nmap 开放端口 + `UNDECLARED_OBSERVED`/端口 alignment | 抓包未出现不能否定 nmap 已确认的监听端口 |
| 5.6-2 | 广播/组播、明文 Flow、unknown cluster + 主动 Banner/路径探测 | 高熵/UNKNOWN 不能推断“无信息泄露” |
| 5.8-1 / 5.8-2 | 21-PersData 声明 → alignment → Flow/encryption/frame | 必须另有证据证明 Flow 承载相应个人数据 |
| 5.9-3 | RECONNECT/FLOW_BURST window → Flow/frame | 普通稳定流量或没有 SYN 突发不能证明故障恢复安全 |

## 私有协议与加密的保守结论

- tshark 能识别已安装 dissector 支持的协议；不能识别时只能记录 UNKNOWN、端口、方向、时序、长度分布、稳定哈希和行为簇。
- “端口像某协议”“负载高熵”“没有看到明文”都不是确认协议或加密算法的充分证据。
- 标准 TLS/QUIC 等有明确 dissector 与握手字段时可判 `STANDARD_ENCRYPTION_CONFIRMED`。
- 显式 HTTP/可识别明文可判 `PLAINTEXT_CONFIRMED`。
- 高熵不透明最多判 `OPAQUE_HIGH_ENTROPY`；它也可能是压缩、编码、媒体或私有二进制格式。
- 厂商私有协议要确认消息语义或算法，需要受控 dissector、协议规范、密钥/握手证据或制造商说明；不足时必须 `INCONCLUSIVE`。

## `pcap_analysis/` 迁移兼容层

`python scripts/pcap_analyzer.py <pcap> --dut-ip <IP> --out-dir <工作区>/pcap_analysis` 仍可最佳努力生成旧版 22 个 JSON/TXT 文件，供旧报告或外部脚本过渡使用。规则如下：

- Traffic Intelligence 必须先运行；兼容层失败不得阻断主流程。
- Work Agent 不得把 `_index.json` 或任何旧文件作为前置门禁。
- 兼容层失败时清理空目录和半成品，避免被误认为完整索引。
- 新条款映射和新报告只以已校验的主 Bundle 为首要流量入口。
