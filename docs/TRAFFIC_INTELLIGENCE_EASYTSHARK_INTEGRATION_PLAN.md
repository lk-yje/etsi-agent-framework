# Traffic Intelligence 与 EasyTshark 集成落地方案

> 状态：实施前设计稿
> 适用项目：ETSI Agent Framework
> 目标：把连续 PCAP 转换为适合 AI 查询、可审计、可与 IXIT 声明逐维度对齐的流量智能证据
> 核心约束：测试人员只负责开始测试、连续完成全部设备操作、结束测试；中途不分步骤、不打标签、不补充时间标记

---

## 1. 结论

本项目不把 EasyTshark 桌面应用整体嵌入 framework，也不把它当前的 HTTP 服务直接暴露给 Agent。

目标架构新增一个 framework 原生的 `Traffic Intelligence Pipeline`：

- `tshark` 继续作为帧级协议解码器和最终复核依据；
- 吸收 EasyTshark 的五元组会话化、双向统计、流重组、SQLite 索引和大文件处理思路；
- 将 EasyTshark 改造成可选的无界面批处理 Worker，作为统一分析后端之一；
- 同时保留直接调用 tshark 的原生后端，用相同输入和相同输出合约做 A/B 对比；
- 在两种后端之上实现未知/私有协议画像、加密分类、IXIT 声明对齐和 AI 按需下钻；
- EasyTshark 后端失败或不可用时，原生 tshark 后端必须可独立完成分析，不得阻断已有 Pipeline。

最终要解决的不是“给每个流量贴一个协议名称”，而是建立以下可追溯关系：

```text
IXIT 原始声明
    ↕
规范化通信声明
    ↕
实测 Flow / Session
    ↕
协议候选 + 加密证据 + 端口/方向/目标
    ↕
逐维度 MATCH / MISMATCH / NOT_OBSERVED / UNDECLARED_OBSERVED / INSUFFICIENT_EVIDENCE
    ↕
frame.number + PCAP SHA-256 + Tool Receipt
```

---

## 2. 范围

### 2.1 本期目标

1. 对一次从头到尾的连续抓包建立完整流量资产清单。
2. 对所有可见网络流量进行会话化，包括 TCP、UDP，以及不能建立双向会话的其他网络层协议。
3. 识别已知协议，并为未识别或私有协议建立稳定指纹和候选分类。
4. 分离“标准加密已确认”“明文已确认”“高熵但算法未知”“证据不足”等状态。
5. 从 IXIT 中提取通信机制、端口、方向、目标、加密和用途声明。
6. 将每项声明与观察结果逐维度比对。
7. 向 Agent 提供小体积摘要和只读下钻工具，避免把整份 PCAP、PDML 或 SQLite 放进模型上下文。
8. 将所有结论关联到原始 PCAP 哈希、帧号、工具版本、参数和工具收据。
9. 对 Direct Tshark 与 EasyTshark Worker 进行可重复的能力、性能和结果一致性对比。

### 2.2 明确不做

- 不要求测试人员为每个操作点击开始/结束或填写标签。
- 不把“高熵”直接等同于“安全加密”。
- 不把“不是 TLS”直接等同于“明文”。
- 不在没有协议规范、密钥或 dissector 的情况下声称已经理解私有协议字段语义。
- 不让 Agent 直接控制实时抓包进程、任意文件路径或 EasyTshark 原始管理 API。
- 不让 EasyTshark 替换现有 tshark + xray + Burp Traffic 采集链路。
- 不默认把 Payload、Cookie、Token、完整 Stream 或个人数据写入报告。
- 不把 EasyTshark 源码、第三方数据库和大型资源直接复制到 framework 仓库。

---

## 3. 当前架构事实与缺口

### 3.1 Framework 当前能力

当前 `TrafficCollectStage` 已经负责：

- 解析 DUT 地址；
- 定位并启动 tshark；
- 启动 xray；
- 配置和恢复 Burp 上游代理；
- 维护 `traffic_state.json`；
- 等待用户完成整段操作；
- 停止并清理子进程；
- 验证 `capture.pcap` 存在且大于最小阈值；
- 调用 `pcap_analyzer.py`；
- 为抓包、xray 和 PCAP 分析写阶段级 Tool Receipt；
- 将 `capture.pcap` 和 `pcap_analysis/` 作为证据产物引用。

现有 `pcap_analyzer.py` 的主要问题不是 tshark 能力不足，而是分析逻辑采用固定查询组，面向少数 ETSI 条款输出约二十个结果文件，缺少：

- 完整通信资产清单；
- UDP 会话与非 TCP/UDP 流量的统一建模；
- 未知协议聚类；
- Decode-As 候选尝试；
- Payload 结构画像；
- 私有加密与明文的多态分类；
- IXIT 声明逐维度对齐；
- 面向 AI 的按需查询接口。

### 3.2 EasyTshark 当前能力

本方案对 EasyTshark 的判断基于上游提交 `a2d5c0aae960acabe6226eaca0186b8f4184add8` 的静态审阅；进入实施前必须重新锁定并复核实际采用的 commit/tag。

EasyTshark 当前 C++ 引擎以 tshark 输出为输入，提取帧号、时间、MAC、IP、端口、TCP/UDP stream、长度、传输层协议号、`_ws.col.Protocol`、`_ws.col.Info`、HTTP Host、DNS Name 和 TLS SNI，并写入 SQLite。

它提供：

- 五元组会话聚合；
- 双向包数和字节数；
- 会话持续时间；
- 应用协议标签；
- IP、端口、协议、国家统计；
- Follow TCP/UDP Stream；
- 本机进程关联；
- 大 PCAP 分片和多线程解析。

### 3.3 EasyTshark 当前缺口

1. 协议标签直接来自 tshark `_ws.col.Protocol`，不存在独立私有协议识别能力。
2. 只对 TCP/UDP 创建会话，其他协议只保留为散包。
3. 固定字段集合丢失大量 Wireshark 协议树细节。
4. 只有一个全局 Manager、一个 SQLite 和一个工作状态，不能按 framework run 隔离。
5. 固定监听 `127.0.0.1:9122`，需要 UI PID，生命周期与 Tauri 耦合。
6. 默认写 `%APPDATA%/easytshark` 或 `$HOME/easytshark`，不符合 framework workspace 证据边界。
7. 文件路径、过滤条件和命令执行方式需要安全加固。
8. 没有适合机器消费的完整批量导出合约。
9. 当前公开仓库没有自动化测试、CI 或稳定发布 tag。

因此 EasyTshark 当前版本不能直接成为认证证据引擎，但其会话索引实现适合作为后端候选和设计来源。

---

## 4. 架构决策

### AD-01：tshark 是解码器，不是最终业务分析器

tshark 负责输出协议树、字段和统计；framework 负责把这些数据组织成可验证的会话、协议画像、加密结论和声明对齐结果。

所有已知协议名称必须带来源：

- `tshark_dissector`
- `decode_as`
- `port_hint`
- `payload_signature`
- `tls_metadata`
- `vendor_dissector`
- `ai_hypothesis`

只有前三类或经过验证的厂商 dissector 可以作为确定性协议证据；AI 猜测永远不能提升为确定性事实。

### AD-02：统一输出合约先于后端选择

先定义 `TrafficIntelligenceBundle`，再分别实现：

- `DirectTsharkBackend`
- `EasyTsharkBatchBackend`

两个后端必须产生同一组规范化对象。上层私有协议分析、声明对齐、Agent 工具和报告不得依赖某个后端的私有字段。

### AD-03：EasyTshark 采用批处理 Worker，而不是常驻 Sidecar

第一目标形态为：

```text
easytshark-analyzer
  --input <workspace>/capture.pcap
  --output <workspace>/traffic-intelligence/easytshark-staging
  --tshark <resolved-tshark-path>
  --format jsonl
  --no-network
  --no-raw-payload
```

批处理 Worker 完成后退出。这样不需要固定端口、HTTP Token、服务发现、UI PID和常驻进程清理。

只有未来确实需要交互式高速分页查询时，才考虑在 framework 后端内部打开受控的短生命周期查询服务。

### AD-04：连续抓包是唯一用户流程

用户工作流固定为：

```text
Pipeline 自动开始抓包
    → 用户自由完成全部设备操作
    → 用户点击完成
    → Pipeline 自动停止并分析
```

系统可以自动生成“活动窗口”，但不得要求用户提供步骤标签。活动窗口只作为用途推断的辅助信号，不作为协议、端口和加密判断的前置条件。

### AD-05：AI 使用渐进式上下文

AI 默认只读取全局摘要和异常清单。需要复核时再按以下层级下钻：

```text
L0 资产与对齐摘要
L1 Flow / Session / Unknown Cluster
L2 有界帧字段与有界 Stream 样本
L3 原始 PCAP 或条款 PCAP Slice
```

L2、L3 必须通过只读工具显式请求，并记录 receipt。原始 Payload 不自动进入模型上下文。

### AD-06：声明对齐采用多维状态，不采用单一布尔值

每个观察对象按以下维度分别评价：

- 方向
- 传输层协议
- 应用层协议
- 本地端口
- 远端端口
- 远端地址/域名
- 加密外壳
- TLS/DTLS/QUIC 版本
- 密码套件或算法声明
- 通信用途
- 是否在本次抓包中观察到

维度状态统一为：

- `MATCH`
- `MISMATCH`
- `NOT_OBSERVED`
- `UNDECLARED_OBSERVED`
- `INSUFFICIENT_EVIDENCE`
- `NOT_APPLICABLE`

---

## 5. 目标运行链路

```text
TrafficCollectStage
    │
    ├── capture.pcap
    ├── xray_report / Burp history
    └── traffic_state.json
            │
            ▼
TrafficIntelligencePipeline
    │
    ├── Backend A: DirectTsharkBackend
    ├── Backend B: EasyTsharkBatchBackend
    │
    ├── FlowNormalizer
    ├── ProtocolProfiler
    ├── EncryptionClassifier
    ├── AutomaticActivitySegmenter
    ├── DeclarationExtractor
    ├── DeclarationMatcher
    └── BundleWriter
            │
            ▼
traffic-intelligence/
    │
    ├── Agent Read-only Tools
    ├── M1/M2/M3/M4/M5 Evidence
    ├── Audit Agent
    └── Unified Report
```

### 5.1 执行顺序

1. Traffic 阶段停止 tshark 和 xray。
2. 计算 `capture.pcap` 的 SHA-256、大小和基本格式信息。
3. 调用选定后端生成标准帧索引和会话索引。
4. 执行协议识别、未知流聚类和加密分类。
5. 从 IXIT 生成规范化通信声明。
6. 执行声明—观察对象匹配。
7. 写入原子化 Bundle 和 manifest。
8. 执行结构校验和跨文件引用校验。
9. 成功后才将 `traffic_state` 转为 `COMPLETE`。
10. M1-M5 Agent 通过只读工具读取 Bundle。

---

## 6. 数据合约

### 6.1 TrafficCaptureManifest

```json
{
  "schema_version": 1,
  "capture_sha256": "...",
  "capture_size": 123456,
  "capture_format": "pcapng",
  "capture_started_at": "...",
  "capture_finished_at": "...",
  "dut_addresses": ["192.0.2.10"],
  "analysis_backend": "direct_tshark",
  "backend_version": "...",
  "tshark_version": "...",
  "analysis_started_at": "...",
  "analysis_finished_at": "...",
  "complete": true,
  "warnings": []
}
```

### 6.2 ObservedFlow

每条 Flow 至少包含：

```json
{
  "flow_id": "flow-000001",
  "transport": "TCP",
  "ip_version": 4,
  "src_ip": "192.0.2.10",
  "src_port": 51000,
  "dst_ip": "198.51.100.8",
  "dst_port": 443,
  "direction_relative_to_dut": "OUTBOUND",
  "first_frame": 101,
  "last_frame": 390,
  "frame_count": 290,
  "bytes_src_to_dst": 12000,
  "bytes_dst_to_src": 98000,
  "duration_ms": 5230,
  "stream_id": 12,
  "dns_names": ["cloud.example.test"],
  "sni": ["cloud.example.test"],
  "protocol_candidates": [],
  "encryption": {},
  "payload_profile_ref": "payload-profiles/flow-000001.json",
  "frame_refs": [101, 102, 103, 389, 390]
}
```

`frame_refs` 保存能证明建连、协议、加密和异常的代表帧，不保存所有帧号。完整映射进入 `flow-frame-index.jsonl`。

### 6.3 ProtocolCandidate

```json
{
  "name": "TLS",
  "layer": "application_or_security",
  "confidence": 0.99,
  "status": "CONFIRMED",
  "basis": [
    {"type": "tshark_dissector", "value": "tls"},
    {"type": "frame_protocols", "frame": 103},
    {"type": "server_hello", "frame": 106}
  ]
}
```

候选状态：

- `CONFIRMED`
- `PROBABLE`
- `POSSIBLE`
- `UNKNOWN`

### 6.4 PayloadProfile

默认只保存脱敏、聚合后的统计特征：

- 可打印字符比例；
- ASCII/UTF-8/JSON/XML/HTTP/protobuf 等格式迹象；
- Shannon entropy；
- 前缀/后缀稳定性；
- 前 N 字节脱敏十六进制样本；
- 请求/响应方向序列；
- 包长度序列摘要；
- 帧间隔统计；
- 固定位置与变化位置候选；
- 周期性与心跳候选；
- 重复消息类型候选；
- 可疑明文关键字段类别，不保存真实密码、Token 或 Cookie 值。

### 6.5 EncryptionAssessment

分类枚举：

- `STANDARD_ENCRYPTION_CONFIRMED`
- `PLAINTEXT_CONFIRMED`
- `OPAQUE_HIGH_ENTROPY`
- `CUSTOM_ENCRYPTION_POSSIBLE`
- `ENCAPSULATED_ENCRYPTION`
- `MIXED`
- `INSUFFICIENT_EVIDENCE`

必须包含：

- 分类依据；
- 反例和限制；
- 标准 TLS/DTLS/QUIC 元数据；
- 代表帧；
- 可否验证 IXIT 声明中的具体算法；
- 是否需要密钥、协议说明或厂商 dissector。

### 6.6 TrafficDeclaration

```json
{
  "declaration_id": "11-ComMech-03",
  "source": {
    "artifact": "ixit.json",
    "table": "11-ComMech",
    "row": 3
  },
  "raw_text_sha256": "...",
  "purpose": "设备注册和心跳",
  "direction": "OUTBOUND",
  "transport": ["TCP"],
  "application_protocol": ["vendor-private"],
  "local_ports": [],
  "remote_ports": [443],
  "remote_hosts": ["cloud.example.test"],
  "encryption_expected": true,
  "encryption_protocol": ["TLS"],
  "minimum_version": "1.2",
  "algorithm_claims": [],
  "normalization_warnings": []
}
```

自由文本中不能确定的字段必须为 `null` 或空列表，并写入 warning；禁止由模型补全未声明内容。

### 6.7 DeclarationAlignment

```json
{
  "alignment_id": "alignment-0001",
  "declaration_id": "11-ComMech-03",
  "flow_ids": ["flow-000001"],
  "overall": "MISMATCH",
  "dimensions": {
    "direction": "MATCH",
    "transport": "MATCH",
    "application_protocol": "INSUFFICIENT_EVIDENCE",
    "remote_host": "MATCH",
    "remote_port": "MISMATCH",
    "encryption": "MATCH"
  },
  "reason": "声明端口为 443，实测连接端口为 8443",
  "frame_refs": [101, 103, 106],
  "confidence": 0.96
}
```

---

## 7. 私有协议识别策略

### 7.1 一级：tshark 原生识别

收集：

- `frame.protocols`
- `_ws.col.Protocol`
- 具体协议字段
- expert info
- malformed 指标
- TCP/UDP stream ID
- TLS/DTLS/QUIC 元数据

不得只保存 `_ws.col.Protocol`；应保留协议栈和关键证据字段。

### 7.2 二级：非标准端口 Decode-As

对仅显示 TCP/UDP/Data 的高价值 Flow，生成候选：

- 端口提示；
- Payload Magic；
- ALPN/SNI；
- 已声明协议；
- 常见 IoT 协议特征。

受控尝试 `tshark -d` 后比较：

- 成功解析帧比例；
- 有效字段比例；
- malformed/expert error 比例；
- 是否产生稳定请求/响应结构。

只有解码质量超过阈值且无明显冲突时，候选才可提升为 `PROBABLE`；不能仅因端口相同判为 `CONFIRMED`。

### 7.3 三级：未知协议指纹和聚类

为未知 Flow 计算稳定指纹：

- transport；
- 端口角色；
- 目的地址类别；
- 包长度方向序列的归一化摘要；
- Payload 前缀模式；
- entropy 区间；
- 周期性；
- 会话持续时间；
- 首包方向；
- DNS/SNI/证书关联。

输出 `unknown_cluster_id`，使不同时间出现的同类私有协议可以被归为同一组。聚类名称默认使用：

```text
unknown-tcp-cluster-001
unknown-udp-cluster-004
```

AI 可以提出语义候选，但显示名称不得覆盖稳定 cluster ID。

### 7.4 四级：自动活动窗口

在不要求用户打标签的前提下，自动检测：

- 新 Flow 大量出现；
- 流量突发；
- 长静默后的通信恢复；
- 大文件传输；
- 周期心跳；
- DNS → TCP/TLS 建连链；
- 断连与重连；
- 远端地址切换。

活动窗口只输出：

- 时间范围；
- 涉及 Flow；
- 自动推断的现象；
- 置信度。

若没有足够证据，不推断“登录”“升级”等业务名称，统一标记 `UNATTRIBUTED_ACTIVITY`。

### 7.5 厂商协议扩展

支持按 run 或部署级加载：

- Wireshark Lua dissector；
- tshark profile；
- Decode-As 规则；
- 厂商协议字段映射；
- 已批准的解密密钥或 TLS key log。

扩展必须记录名称、版本、SHA-256和加载来源。私有资产通过部署目录注入，不提交公共仓库。

---

## 8. 功能需求

### FR-001 连续抓包输入

系统必须接受一个从开始到结束的连续 `capture.pcap`/`capture.pcapng`，不得要求人工步骤标签。

### FR-002 输入完整性

分析前必须计算 PCAP SHA-256、大小、格式、首末时间和总包数；分析结束时再次验证哈希未变化。

### FR-003 流式处理

后端不得把完整 PCAP、完整 tshark JSON 或完整 PDML 一次性加载到内存。

### FR-004 全流量覆盖

TCP/UDP 形成双向 Flow；ICMP、ARP、ESP、GRE、SCTP及其他可见协议至少形成可查询的观察记录，不因无法五元组会话化而消失。

### FR-005 DUT 相对方向

每条 Flow 必须标记相对 DUT 的 `INBOUND`、`OUTBOUND`、`LATERAL` 或 `UNKNOWN`。

### FR-006 域名与地址关联

系统应关联 DNS 查询、SNI、证书名称和后续目标 IP，并保留关联依据和时间窗口。

### FR-007 协议候选

每条 Flow 必须至少有一个协议状态；未知时明确输出 `UNKNOWN`，不得省略或猜测。

### FR-008 Decode-As

系统应能对受控候选协议执行 Decode-As 复分析，并保存原始识别与复分析结果，不能覆盖原始观察事实。

### FR-009 未知协议聚类

系统必须为未识别 TCP/UDP Flow 生成指纹和 cluster ID，并能跨同一 PCAP 内多个会话聚类。

### FR-010 Payload 安全画像

系统应产生脱敏统计特征；默认不保存完整 Stream，不向 AI 返回认证头、Cookie、Token、密码或个人数据原文。

### FR-011 加密分类

系统必须区分标准加密、明确明文、高熵不透明、自定义加密可能、混合和证据不足。

### FR-012 标准加密元数据

对 TLS/DTLS/QUIC，系统应提取可获得的版本、密码套件、证书、SNI、ALPN、握手成功与失败信息。

### FR-013 算法声明边界

如果 IXIT 声明 AES、SM4 或其他私有算法，但网络侧不能验证，结果必须为 `INSUFFICIENT_EVIDENCE`，并列出所需额外证据。

### FR-014 IXIT 声明提取

系统必须从适用 IXIT 表中生成规范化声明，同时保留表名、行号和原文哈希。

### FR-015 多维对齐

每项声明必须按方向、传输层、应用层、端口、地址、加密和用途分别评价。

### FR-016 未声明通信

观察到无法映射到任何声明的 DUT 通信时，输出 `UNDECLARED_OBSERVED`，并按外连目标、端口、流量大小和敏感性排序。

### FR-017 未观察到的声明

声明存在但本次抓包没有匹配 Flow 时，输出 `NOT_OBSERVED`，不得自动判 FAIL。

### FR-018 AI 只读查询工具

至少提供：

- `traffic_get_inventory`
- `traffic_list_flows`
- `traffic_get_flow`
- `traffic_list_unknown_clusters`
- `traffic_get_unknown_cluster`
- `traffic_get_encryption_assessment`
- `traffic_compare_declarations`
- `traffic_get_frame_details`
- `traffic_get_stream_sample`
- `traffic_try_decode_as`

除 `traffic_try_decode_as` 会生成新的受控分析产物外，其余工具均为只读。

### FR-019 工具收据

每次后端执行、Decode-As、帧详情提取、Stream 样本提取和声明对齐都必须记录 receipt，并引用输入和输出 artifact。

### FR-020 报告接入

统一报告至少展示：

- 声明总数、匹配数、不匹配数、未观察数；
- 未声明通信；
- 未知协议集群；
- 明文确认项；
- 高风险加密不一致；
- 每项结论对应 frame refs。

### FR-021 后端回退

EasyTshark Worker 不可用、超时、崩溃或输出校验失败时，系统必须自动使用 Direct Tshark 后端，并在 manifest 中记录降级原因。

### FR-022 兼容旧证据路径

迁移期继续生成原有 `pcap_analysis/` 文件，直到 M1-M5、Audit 和 Report 全部改为消费新 Bundle，并通过对照测试。

---

## 9. 非功能需求

### NFR-001 安全边界

- 所有输入和输出路径必须位于当前 workspace。
- 子进程使用 argv 数组，不经过 shell 字符串拼接。
- 离线分析不申请管理员/root。
- Worker 禁止主动网络访问。
- Agent 不获得任意路径、任意 tshark 参数或任意 dissector 加载权限。

### NFR-002 数据保密

- PCAP、SQLite、Stream、Payload 样本视为敏感证据。
- 默认 AI Bundle 只含脱敏摘要。
- 原始样本单独放在受限目录，并从报告和 Git 排除。
- 所有文本摘要执行 Cookie、Authorization、Token、密码、邮箱等模式脱敏。

### NFR-003 确定性

相同 PCAP、相同工具版本和相同配置应产生相同 Flow ID、cluster ID和结构化结果；时间戳等运行元数据除外。

### NFR-004 性能

PoC 基准要求：

- 处理 1 GB PCAP 时不整体载入内存；
- 峰值内存目标不超过 512 MB；
- Direct Tshark 基线完成时间记为 `T`；
- EasyTshark Worker 后端生成相同基础 Bundle 的时间不得超过 `1.5T`，或者必须证明其后续查询延迟显著优于 Direct Tshark 结果；
- 默认 AI L0 摘要不超过 100 KB。

最终阈值在参考工作站完成基准后固化。

### NFR-005 可恢复性

每个阶段写临时目录，完整校验后原子替换正式 Bundle。中断后不得留下看似完整的 manifest。

### NFR-006 可观测性

必须记录每个分析阶段的开始、完成、耗时、输入输出数量、警告、失败原因和后端选择。

### NFR-007 版本与供应链

- 记录 tshark 版本和可用 dissector/profile。
- EasyTshark 使用明确 commit/tag 和二进制 SHA-256。
- 保留 Apache-2.0 许可证、版权和修改说明。
- 单独生成第三方依赖清单；不自动打包 Wireshark/tshark。

### NFR-008 跨平台声明

Windows 和 Linux 分别完成真实构建、解析和清理测试后才能声明支持。不得因源码含平台分支就认定功能已验证。

---

## 10. Framework 文件级修改计划

### 10.1 新增数据合约

新增：

```text
contracts/traffic_intelligence.py
```

包含：

- `TrafficCaptureManifest`
- `ObservedPacketRef`
- `ObservedFlow`
- `ObservedProtocolRecord`
- `ProtocolCandidate`
- `PayloadProfile`
- `EncryptionAssessment`
- `UnknownProtocolCluster`
- `AutomaticActivityWindow`
- `TrafficDeclaration`
- `DeclarationAlignment`
- `TrafficIntelligenceBundleIndex`

所有字段使用 Pydantic 校验；枚举值不得使用自由文本替代。

### 10.2 新增分析包

新增：

```text
framework/traffic_intelligence/
├── __init__.py
├── pipeline.py
├── bundle_store.py
├── flow_ids.py
├── sessionizer.py
├── protocol_profiler.py
├── decode_as.py
├── payload_profiler.py
├── encryption_classifier.py
├── activity_segmenter.py
├── declaration_extractor.py
├── declaration_matcher.py
├── redaction.py
├── agent_tools.py
└── backends/
    ├── base.py
    ├── direct_tshark.py
    └── easytshark_batch.py
```

职责边界：

- backend 只负责把 PCAP 转换为标准帧/Flow staging 数据；
- profiler 不感知 EasyTshark 私有 API；
- matcher 不执行 tshark；
- Agent 工具只能通过 `BundleStore` 读取已校验产物。

### 10.3 修改 Traffic 阶段

修改：

```text
pipelines/etsi/pipeline.py
```

在当前 PCAP 大小验证之后：

1. 保留旧 `_run_pcap_analyzer()`；
2. 新增 `_run_traffic_intelligence()`；
3. 两者在迁移期都成功后才把 Traffic 标记为 COMPLETE；
4. 新引擎稳定后，将旧分析器改为由新 Bundle 派生兼容文件；
5. 最终删除重复 tshark 扫描，但保留兼容测试。

### 10.4 修改工具注册

修改：

```text
framework/tools.py
framework/execution_policy.py
pipelines/etsi/modules.py
```

新增 `traffic_intelligence` 工具类别，并只注册受限的结构化参数。工具执行器必须绑定当前 workspace，不接受调用方传入绝对路径。

`traffic_try_decode_as` 需要额外策略：

- 只允许预定义 dissector；
- 只允许当前 `capture.pcap`；
- 只允许当前 Flow 对应端口；
- 参数列表运行；
- 输出写入新的 attempt 目录；
- 不覆盖原始识别结论。

### 10.5 修改 Preflight 与配置

修改：

```text
framework/preflight.py
framework/runtime_config.py
.env.template
skills/path-mapping.json
```

新增可选配置：

```text
TRAFFIC_ANALYZER_BACKEND=auto|direct_tshark|easytshark_batch
TRAFFIC_AI_PAYLOAD_POLICY=metadata_only|bounded_redacted|disabled
TRAFFIC_MAX_STREAM_SAMPLE_BYTES=4096
TRAFFIC_EASYTSHARK_TIMEOUT_SECONDS=1800
```

路径映射只增加通用模板键：

```text
TOOL.EASYTSHARK_ANALYZER
```

真实路径继续由部署者私有 `PATH_MAPPING` 或系统 PATH 提供。不得把 endpoint、Token 或工作区写入 path mapping。

Preflight 新增：

- tshark 版本；
- capinfos/editcap 可用性；
- EasyTshark Worker 可用性和版本；
- Lua/plugin profile 目录是否配置；
- 后端选择结果与回退能力。

### 10.6 修改条款映射与 Agent 消费

修改：

```text
framework/clause_tool_map.json
framework/phase_engine.py
skills/etsi-ts103701-report/references/module-split.md
skills/etsi-ts103701-report/references/pcap-analyzer-reference.md
```

重点接入：

- 通信加密相关条款；
- 软件/服务暴露与端口相关条款；
- CSP/外连目标相关条款；
- 固件更新通道；
- 个人数据传输；
- 断连重连和网络弹性；
- 未声明接口和通信机制。

Prompt 中禁止要求 Agent直接读取完整 `flows.jsonl`；必须先读 inventory 和 alignment，再按 flow ID 下钻。

### 10.7 修改报告与 Web

修改：

```text
framework/reporting.py
web/server.py
web/static/index.html
```

新增报告区块：

- 通信声明对齐概览；
- 未声明通信；
- 未观察声明；
- 协议与端口不一致；
- 加密不一致；
- 未知私有协议集群；
- 证据不足和所需补充材料。

条款 `EvidenceItem` 使用 `flowIds` / `frameNumbers` 保存工具实际返回的结构化引用。
报告器在主 Bundle 完整性校验通过后解析这些引用并生成最小 PCAP 切片请求；只有
条款没有结构化 Traffic Intelligence 引用时，才回退旧 `pcap_analysis/_index.json`。
禁止从自然语言 description 猜测帧号。

Web 仅提供结果浏览和按 flow 下钻，不增加人工步骤标签界面。

### 10.8 修改忽略与保密规则

修改：

```text
.gitignore
docs/FILE_CLASSIFICATION_STANDARD.md
```

确认以下内容不会进入 Git：

```text
*.pcap
*.pcapng
*.cap
*.sqlite
*.sqlite3
traffic-intelligence/raw/
traffic-intelligence/restricted/
vendor-dissectors/private/
```

规范化摘要和测试用合成 PCAP 可以单独白名单。

---

## 11. EasyTshark Fork 修改计划

EasyTshark 的改造在独立 fork 中完成，不与 framework Git 历史混在一起。

### 11.1 抽离核心库

将当前 `TSharkManager` 拆分为：

- `CaptureManager`：保留给 EasyTshark 桌面版，framework 初期不使用；
- `OfflineAnalyzer`：只处理已有 PCAP；
- `SessionIndex`：会话和 SQLite；
- `Exporter`：JSONL/manifest 导出；
- `TsharkProcessRunner`：安全 argv 执行和超时控制。

### 11.2 新增 Batch CLI

新增独立可执行文件：

```text
easytshark-analyzer
```

要求：

- 不启动 HTTP；
- 不需要 UI PID；
- 不检查桌面单例；
- 不写 APPDATA/HOME；
- 不请求管理员权限；
- 所有输出位于显式 `--output`；
- 所有临时文件位于 `--output/.tmp`；
- 支持取消、超时和非零退出码；
- 完成后写 `manifest.json`，最后一步设置 `complete=true`；
- 默认不导出完整 Payload。

### 11.3 扩充字段

EasyTshark staging 输出至少增加：

- `frame.protocols`
- `tcp.stream` / `udp.stream`
- TCP flags、重传、乱序信息
- DNS query/response/A/AAAA/CNAME
- HTTP method/host/URI/status/content-type
- TLS/DTLS/QUIC handshake 元数据
- SNI、ALPN、证书摘要
- TCP/UDP Payload 长度
- expert/malformed 状态
- VLAN、MAC 和 IP 版本
- ICMP/ARP/ESP/GRE/SCTP 等非 TCP/UDP观察记录

### 11.4 修复安全边界

- 禁止 shell 字符串执行；
- 过滤条件和路径全部使用参数化 argv；
- 规范化并校验输入/输出路径；
- 移除分析模式下任意保存路径；
- 移除外部服务调用和无关模板代码；
- 增加恶意文件名、过滤器和畸形 PCAP测试。

### 11.5 测试与发布

Fork 必须新增：

- C++ 单元测试；
- 固定合成 PCAP 的 golden tests；
- Windows/Linux CI；
- Release tag；
- 二进制 SHA-256；
- SBOM/第三方许可证清单；
- framework 支持矩阵。

---

## 12. 输出目录

```text
<workspace>/
├── capture.pcap
├── traffic_state.json
├── pcap_analysis/                         # 迁移期兼容输出
├── traffic-intelligence-derived/          # 独立 manifest 的受控复分析
│   └── decode-as-attempts/
└── traffic-intelligence/
    ├── manifest.json
    ├── inventory.json
    ├── flows.jsonl
    ├── non-session-observations.jsonl
    ├── flow-frame-index.jsonl
    ├── endpoints.json
    ├── dns-correlations.json
    ├── protocol-candidates.jsonl
    ├── encryption-assessments.jsonl
    ├── unknown-protocol-clusters.json
    ├── automatic-activity-windows.json
    ├── declarations.json
    ├── declaration-alignments.json
    ├── summary-for-ai.json
    ├── payload-profiles/
    ├── frame-details/
    ├── backend-staging/
    ├── raw/                               # 默认不允许 Agent 访问
    └── restricted/                        # Payload/Stream，默认不生成
```

`manifest.json` 是完整性入口；任何消费者在读取其他文件前必须确认：

- `complete=true`
- schema version 支持
- capture hash 一致
- 文件清单和哈希一致

---

## 13. Agent 工具契约

### 13.1 traffic_get_inventory

输入：无。
输出：协议、端点、Flow、加密分类、未知集群和对齐结果的计数与高风险摘要。

### 13.2 traffic_list_flows

允许过滤：

- DUT方向；
- transport；
- port；
- endpoint；
- protocol candidate；
- encryption class；
- unknown cluster；
- alignment status；
- 分页大小，必须有上限。

### 13.3 traffic_get_flow

按 `flow_id` 返回单个 Flow、协议依据、加密依据、声明映射和代表帧。

### 13.4 traffic_get_frame_details

只允许读取当前 PCAP 中指定 frame，数量有上限；结果脱敏并保存为 artifact。

### 13.5 traffic_get_stream_sample

默认禁用。启用时：

- 必须给出 flow ID；
- 限制方向和字节数；
- 自动脱敏；
- 不返回二进制原文；
- 记录访问 receipt。

### 13.6 traffic_try_decode_as

只有在协议候选不足时使用。返回新 attempt ID、解析覆盖率、错误率、字段完整度和代表帧，不直接改写原始 Flow。

---

## 14. 实施阶段

当前公开源码状态（2026-09-12；2026-09-14 补充公司部署状态）：A 的核心合约/原子 Bundle/无 Payload TCP golden 已完成，
B 的 Direct Tshark 与 EasyTshark Batch 适配器及失败回退已完成；D、E、F 的框架侧
实现与离线回归已完成；G 的兼容迁移和公开仓库数据泄露审查已完成离线部分。
公开仓库没有收录 EasyTshark Batch CLI、完整合成协议语料、A/B 实测数据或真机 UAT 的
私有证据。用户已于 2026-09-14 确认公司电脑部署成功，并已完成 5 轮实际全量测试；不得因
公开仓库缺少这些私有材料而推断其未完成。框架仍提供 `scripts/benchmark_traffic_backends.py`
和无 Payload 的标准化指标报告；公开默认配置继续固定 Direct Tshark，以便在不具备私有
Worker 与私有证据时安全复现框架行为。

### 阶段 A：合约、合成 PCAP 与比较基线

交付物：

- `contracts/traffic_intelligence.py`
- Bundle 目录和原子写入器
- 合成测试 PCAP集合
- Direct/EasyTshark 共用 backend interface
- A/B 评测脚本和指标定义

测试 PCAP至少覆盖：

- HTTP 明文；
- HTTPS/TLS 1.2 和 1.3；
- UDP/DTLS 或 QUIC；
- 非标准端口 HTTP/MQTT；
- 私有明文二进制样本；
- 高熵但非标准 TLS样本；
- 混合明文/加密同一端点；
- DNS → SNI → IP关联；
- 心跳与流量突发；
- 未声明端口；
- 畸形或截断 PCAP。

阶段门：合约和 fixtures 不依赖真实客户 PCAP，不含敏感数据。

### 阶段 B：两个最小后端

Direct Tshark 后端先生成：

- 帧基本索引；
- TCP/UDP Flow；
- 非会话观察记录；
- 协议栈；
- 基本 TLS/DNS/HTTP元数据。

EasyTshark Fork 同期实现最小 Batch CLI并生成相同字段。

阶段门：同一合成 PCAP 的包数、Flow键、首末帧和字节统计达到定义的一致性要求。

### 阶段 C：后端 A/B 决策

指标：

- 帧覆盖率；
- Flow覆盖率；
- 非 TCP/UDP覆盖率；
- 协议字段保留率；
- 会话统计一致性；
- 运行时间；
- 峰值内存；
- 产物大小；
- 查询延迟；
- 崩溃/取消/畸形输入行为；
- 跨平台可构建性。

决策规则：

- EasyTshark后端不得降低信息覆盖率；
- 若只带来 UI价值而没有索引、性能或维护优势，则不作为运行依赖；
- 若其会话数据库显著改善大 PCAP 查询与复用成本，则保留为首选可选后端；
- Direct Tshark永远保留为基线和回退后端。

### 阶段 D：协议画像与加密分类

交付：

- Decode-As候选器；
- Payload profiler；
- Unknown cluster；
- TLS/DTLS/QUIC元数据；
- 多态加密分类；
- 自动活动窗口。

阶段门：未知协议不能被错误提升为已确认协议；非 TLS高熵样本不能被标成明确明文或明确安全加密。

### 阶段 E：IXIT 声明提取与对齐

交付：

- `TrafficDeclaration`提取；
- 端口、方向、目标、协议和加密的逐维 matcher；
- 未声明通信和未观察声明；
- frame refs；
- 条款映射更新。

阶段门：预置的端口、方向、加密和目标不一致案例必须全部检出；用途不明时必须保留 `INSUFFICIENT_EVIDENCE`。

### 阶段 F：Agent、审计与报告接入

交付：

- 只读 Agent tools；
- M1-M5 recipe更新；
- Audit输入更新；
- Report区块；
- Web结果浏览。

阶段门：Agent可以从 L0 摘要定位异常，再下钻到 Flow 和 frame；不需要读取整份 PCAP或完整 Flow列表。

### 阶段 G：兼容迁移与真机 UAT

交付：

- 新旧 `pcap_analysis`结果对照；
- 当前条款回归；
- 连续整段真机抓包测试；
- 停止/取消/超时/断电恢复；
- 数据泄露审计；
- 性能基准；
- 发布和升级文档。

阶段门：新引擎接管正式证据前，旧报告关键条款不得出现无解释回归。

---

## 15. 验收场景

### AC-001 无人工标签的完整运行

**Given** 用户只点击一次开始，连续完成所有设备操作，再点击完成
**When** Traffic Intelligence 分析结束
**Then** 系统生成完整 Flow资产、未知集群、加密评估和声明对齐结果，不请求补录步骤标签

### AC-002 非标准端口标准协议

**Given** HTTP或 MQTT运行在非标准端口
**When** 原生 dissector 未识别但 Decode-As产生高质量解析
**Then** 输出 `PROBABLE`候选、解析覆盖率、错误率和代表帧，不仅依据端口命名协议

### AC-003 私有明文协议

**Given** TCP Payload含稳定 Magic和可打印字段，但没有已知 dissector
**When** 分析完成
**Then** 系统输出未知 cluster、明文依据、Payload结构特征和代表帧，不编造厂商协议名称

### AC-004 私有高熵协议

**Given** Payload呈高熵且不是标准 TLS/DTLS/QUIC
**When** 分析完成
**Then** 分类为 `OPAQUE_HIGH_ENTROPY`或 `CUSTOM_ENCRYPTION_POSSIBLE`，不声称具体算法已确认

### AC-005 标准 TLS 声明一致

**Given** IXIT声明 TLS 1.2以上、端口443
**When** 实测为 TLS 1.3端口443
**Then** 版本、端口、加密维度为 MATCH，并引用 ClientHello/ServerHello帧

### AC-006 端口不一致

**Given** IXIT声明远端端口443
**When** 实测目标相同但端口为8443
**Then** 远端目标为 MATCH、端口为 MISMATCH，overall不得掩盖维度差异

### AC-007 未声明外连

**Given** DUT主动连接未出现在任何声明中的远端地址
**When** 分析完成
**Then** 输出 `UNDECLARED_OBSERVED`，包含方向、端口、协议/加密候选和frame refs

### AC-008 声明未观察

**Given** IXIT声明一个通信机制，但连续抓包未捕获匹配 Flow
**When** 对齐完成
**Then** 输出 `NOT_OBSERVED`，不自动生成 FAIL

### AC-009 后端回退

**Given** EasyTshark Worker崩溃或超时
**When** backend设置为 `auto`
**Then** 自动使用 Direct Tshark，记录降级原因，Bundle仍可完整校验

### AC-010 敏感数据控制

**Given** PCAP含 Cookie、Authorization和密码字段
**When** AI读取 L0/L1和默认 Stream样本
**Then** 输出不含其原值，receipt和报告同样不含原值

### AC-011 可重复性

**Given** 相同 PCAP、工具版本和配置
**When** 连续运行两次
**Then** Flow ID、cluster ID、协议候选和对齐结果相同

### AC-012 工作区隔离

**Given** 两个不同 run分别分析 PCAP
**When** 并行或顺序执行
**Then** 数据库、临时文件、Flow ID和结果文件不交叉，不写入 APPDATA/HOME

---

## 16. 测试计划

### 16.1 单元测试

- Flow ID双向归一化；
- DUT方向判断；
- DNS/SNI/IP关联；
- entropy和可打印比例；
- Magic稳定性；
- 包长/方向序列摘要；
- 加密状态机；
- 声明解析；
- 多维 matcher；
- 脱敏；
- manifest和文件哈希校验。

### 16.2 Golden PCAP 测试

每份合成 PCAP配套期望：

- 包数；
- Flow数；
- 协议候选；
- 加密分类；
- 未知 cluster；
- declaration alignment；
- 代表帧。

### 16.3 后端一致性测试

同一 PCAP分别经两个后端处理，比较规范化后：

- Flow键集合；
- 首末帧；
- 包数/字节数；
- stream关联；
- 协议栈；
- TLS/DNS/HTTP字段。

差异必须进入 allowlist并说明原因，不能静默忽略。

### 16.4 安全测试

- 路径穿越；
- 恶意文件名；
- 恶意 Decode-As参数；
- Lua插件越界；
- 超大/截断/畸形 PCAP；
- Payload秘密泄露；
- 报告脱敏；
- Git跟踪敏感后缀检查；
- Worker无网络出口验证。

### 16.5 性能测试

至少使用小、中、大三档合成或脱敏 PCAP，记录：

- 总耗时；
- 各阶段耗时；
- 峰值内存；
- 临时磁盘；
- Bundle大小；
- 单 Flow查询延迟；
- 未知集群分析耗时。

### 16.6 需求追踪矩阵

| 需求 | 主要落点 | 实施阶段 | 验证入口 |
|---|---|---|---|
| FR-001 | `TrafficCollectStage`、`TrafficIntelligencePipeline` | G | AC-001、连续真机 UAT |
| FR-002～FR-006 | manifest、两个 backend、sessionizer | A～B | Golden PCAP、完整性与方向测试、AC-011～AC-012 |
| FR-007～FR-013 | protocol/payload profiler、Decode-As、encryption classifier | D | AC-002～AC-005、AC-010 |
| FR-014～FR-017 | declaration extractor/matcher | E | AC-005～AC-008 |
| FR-018～FR-020 | Agent tools、reporting、Web 结果浏览 | F | 工具契约测试、报告脱敏测试、AC-007、AC-010 |
| FR-021 | backend selector、manifest fallback metadata | B～C | AC-009、崩溃/超时/非法输出测试 |
| FR-022 | Pipeline 兼容适配层 | G | 新旧证据对照和现有条款回归 |
| NFR-001～NFR-002 | execution policy、redaction、`.gitignore`、文件分级规范 | 全阶段 | 安全测试、Git 泄露扫描、AC-010、AC-012 |
| NFR-003 | 稳定 ID、排序和序列化规则 | A～D | AC-011、重复运行快照对比 |
| NFR-004 | backend 与 Bundle 基准程序 | C | 小/中/大 PCAP 性能测试 |
| NFR-005～NFR-006 | BundleWriter、manifest、receipt、阶段日志 | A、F | 中断恢复、哈希校验、故障注入 |
| NFR-007～NFR-008 | EasyTshark fork 发布流程和支持矩阵 | B～C、G | SBOM/许可证检查、Windows/Linux CI 与 UAT |

---

## 17. 风险与控制

| 风险 | 影响 | 控制 |
|---|---|---|
| EasyTshark没有独立协议识别能力 | 集成后分析准确率无提升 | 统一合约 + Direct Tshark A/B基线 |
| 多次 tshark扫描导致耗时增加 | 大 PCAP分析过慢 | 两阶段提取、共享 staging、只对候选流下钻 |
| AI错误命名私有协议 | 形成虚假认证结论 | candidate/basis/confidence模型，AI只能输出 hypothesis |
| `!tls`被错误认为明文 | 加密结论失真 | 多态 EncryptionAssessment |
| 连续抓包无法确定业务用途 | 部分声明用途无法对齐 | 自动活动窗口；用途维度保留证据不足，不影响端口/加密等客观维度 |
| PCAP含凭据和个人数据 | 数据泄露 | 分级产物、默认metadata-only、脱敏、禁止Git |
| EasyTshark全局状态污染run | 证据串线 | Batch Worker + workspace参数 + 退出即销毁 |
| 第三方依赖和许可证不清 | 发布风险 | 独立fork、SBOM、NOTICE、外部tshark依赖 |
| 后端输出差异 | 报告不稳定 | Golden fixtures、统一规范化、差异allowlist |

---

## 18. 默认产品决策

以下默认值无需测试人员额外选择：

- 采集模式：一次连续完整抓包；
- 人工标签：关闭且不提供必填入口；
- 分析后端：`auto`；
- 默认首选：在 A/B 决策完成前使用 Direct Tshark；
- EasyTshark：可选 Batch Worker，失败自动回退；
- Payload策略：`metadata_only`；
- 完整 Stream：默认不生成；
- 未知协议：稳定 cluster ID，不自动命名；
- 私有算法：无确定证据时为 `INSUFFICIENT_EVIDENCE`；
- 报告：展示摘要、差异和frame refs，不嵌入原始Payload；
- 原始 PCAP：只存 workspace，作为共享证据原件。

---

## 19. Definition of Done

全部满足才算落地完成：

1. 连续完整抓包无需人工步骤标签即可生成可校验 Bundle。
2. TCP、UDP和非会话协议均不会从资产清单消失。
3. 已知协议结论具备确定性依据；未知协议具备稳定 cluster和画像。
4. 标准加密、明确明文、高熵不透明和证据不足被严格区分。
5. IXIT声明可以追溯到原表行和原文哈希。
6. 协议、端口、方向、目标和加密可以逐维度对齐。
7. 未声明通信和未观察声明不会混为一类。
8. Agent可从摘要下钻到 Flow和代表帧，不需要读取完整 PCAP。
9. 所有分析、下钻和复分析均有 Tool Receipt和artifact引用。
10. EasyTshark与Direct Tshark完成同合约A/B验证，后端选择有数据依据。
11. EasyTshark不可用时原生后端可独立工作。
12. 敏感Payload、凭据、PCAP和SQLite不会进入Git或默认报告。
13. 现有ETSIPipeline全量测试通过，关键条款结果无未解释回归。
14. Windows/Linux支持声明分别经过真实构建和UAT验证。
