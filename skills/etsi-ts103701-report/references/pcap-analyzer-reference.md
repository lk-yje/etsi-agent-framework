# pcap_analyzer.py 查询命令对照表

## 用法

```bash
python pcap_analyzer.py <pcap_path> [--dut-ip 192.0.2.54] [--out-dir pcap_analysis] [--workers 6]
```

## 18 组 tshark 命令 → 22 个输出文件

| # | tshark 命令 | 输出文件 | ETSI 条款 |
|---|---|---|---|
| 1 | `-Y "tls.handshake.type==2"` `-e frame.number -e tcp.dstport -e tls.handshake.extensions.supported_version -e tls.handshake.ciphersuite -e tls.handshake.type` | `5.1-3_tls_versions.json` `5.1-3_tls_ciphers.json` `5.5-1_server_hello.json` | 5.1-3, 5.5-1, 5.3-7, 5.8-2 |
| 2 | `-Y "tls.handshake.type==1"` `-e frame.number -e tcp.dstport -e tls.handshake.extensions.supported_version -e tls.handshake.type` | `5.5-1_client_hello.json` | 5.5-1 |
| 3 | `-q -z io,phs` | `5.5-1_proto_hierarchy.txt` | 5.5-1, 5.3-7, 5.8-2 |
| 4 | `-q -z conv,tcp` | `5.5-1_conversations.txt` | 5.5-1 |
| 5 | `-Y "http"` `-e frame.number -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.response.code` | `5.5-1_http_check.json` | 5.5-1 |
| 6 | `-Y "http.response"` `-e frame.number -e http.response.code -e http.content_length_header -e http.content_type` | `5.5-1_http_responses.json` | 5.5-1 |
| 7 | `-Y "ip.src=={DUT}"` `-e ip.dst -e tcp.dstport` | `5.5-6_dut_outbound.json` `5.5-7_all_destinations.json` | 5.5-6, 5.5-7 |
| 8 | `-Y "ip.src=={DUT} && !tls"` `-e frame.number -e ip.dst -e tcp.dstport -e frame.protocols` | `5.5-6_non_tls.json` | 5.5-6 |
| 9 | `-Y "ip.src=={DUT} && http"` `-e frame.number -e ip.dst -e http.request.uri` | `5.5-6_http_outbound.json` | 5.5-6 |
| 10 | `-Y "ip.src=={DUT} && tls.record.content_type==23"` `-e frame.number -e ip.dst -e tcp.dstport -e tls.record.length` | `5.5-6_tls_appdata.json` | 5.5-6 |
| 11 | `-Y "ip.src=={DUT} && not ip.dst=={TEST}"` `-e ip.dst` | `5.5-7_remote_ips.json` | 5.5-7 |
| 12 | `-Y "eth.dst[0]==1 \|\| ip.dst==255.255.255.255 \|\| (ip.dst>=224.0.0.0 && ip.dst<=239.255.255.255)"` `-e frame.number -e ip.src -e ip.dst -e frame.protocols` | `5.6-2_broadcast.json` | 5.6-2 |
| 13 | `-Y "tcp.payload && !tls && !http && ip.dst=={DUT} && tcp.dstport!=443"` `-e frame.number -e tcp.dstport -e tcp.payload` | `5.6-2_plaintext_services.json` | 5.6-2 |
| 14 | `-Y "tcp.flags.syn==1 && tcp.flags.ack==0"` `-e frame.number -e frame.time_relative -e ip.src -e ip.dst -e tcp.dstport` | `5.9-3_syn_timestamps.json` `5.9-3_syn_bursts.json` | 5.9-3 |
| 15 | `-Y "tcp.analysis.retransmission"` `-e frame.number -e ip.src -e tcp.dstport` | `5.9-3_retransmissions.json` | 5.9-3 |
| 16 | `-Y "http.request"` `-e http.request.method -e http.request.uri -e ip.src` | `5.3-2_http_methods.json` | 5.3-2 |
| 17 | `-Y "http contains \"password\" or http contains \"sessionID\" or http contains \"token\" or http contains \"secret\""` `-e frame.number -e http.request.method -e http.request.uri -e ip.dst` | `5.5-6_sensitive_keywords.json` | 5.5-6 |
| 18 | `-q -z io,stat,0` | `_global_summary.txt` | (全局) |

## 常用 tshark display filter 速查

| Filter | 含义 |
|---|---|
| `tls.handshake.type==1` | ClientHello |
| `tls.handshake.type==2` | ServerHello |
| `tls.record.content_type==23` | Application Data (加密载荷) |
| `tcp.flags.syn==1 && tcp.flags.ack==0` | 纯 SYN (排除 SYN-ACK) |
| `tcp.analysis.retransmission` | TCP 重传 |
| `eth.dst[0]==1` | MAC 首字节 bit0=1 → 组播/广播 |
| `http contains "password"` | HTTP 内容匹配 (大小写敏感) |
| `!tls` | 非 TLS 流量 |

## 常用 tshark 字段 (`-e`)

| 字段 | 含义 |
|---|---|
| `frame.number` | 帧号 |
| `frame.time_relative` | 相对首帧秒数 |
| `frame.protocols` | 协议栈 `eth:ip:tcp:http` |
| `ip.src` / `ip.dst` | 源/目的 IP |
| `tcp.dstport` | TCP 目的端口 |
| `tls.handshake.ciphersuite` | 协商的密码套件 |
| `tls.handshake.extensions.supported_version` | TLS 版本 |
| `http.request.method` / `http.request.uri` | HTTP 方法/路径 |
| `http.response.code` | HTTP 状态码 |
| `tcp.payload` | TCP 载荷 (hex) |

## Python 后处理函数

| 函数 | 输入 | 输出 | 应用 |
|---|---|---|---|
| `count_values(rows)` | 多行单列 | `[{"value": …, "count": N}]` | TLS版本/密码套件统计 |
| `count_pairs(rows)` | 多行双列 | `[{"ip": …, "port": …, "count": N}]` | DUT外连目标 |
| `unique_values(rows)` | 多行单列 | `["ip1", "ip2", …]` | 远程IP去重 |
| `count_by_src(rows)` | 多行 | `[{"src": …, "count": N}]` | 重传统计 |
| `as_table(rows)` | 任意 | `{"total_rows": N, "data": […200]}` | 通用表结构 |
| `compute_intervals(rows)` | SYN时间戳 | `{"min_delta_s": …, "verdict_hint": …}` | 重连间隔分析 |
| `detect_bursts(rows)` | SYN时间戳 | `{"total_bursts": N, "bursts": […]}` | SYN突发检测 |
| `raw_text(rows)` | 任意 | 原始字符串 | `-z` 统计输出 |

## 设计要点

- **合并**: 第1/7/14组共享 display filter，合并为 1 次 tshark (省 ~23s)，Python 侧按列索引分发给不同后处理器
- **并行**: 18 组用 `ThreadPoolExecutor` 并发 (默认 6 workers)，tshark 纯 I/O 密集 + 同文件 OS 页缓存友好
- **兼容**: 22 个输出文件名与 v1 完全一致，消费侧零改动
