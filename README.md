# ETSI Agent Framework

> 面向 IoT 产品安全合规的**可信验证平台**。
> 以可分离的检测编排、流量分析、证据治理与独立审查能力，构建可追溯、可复核、可交付的合规证据链。

## 项目定位

ETSI Agent Framework 是一套**检测执行与证据治理框架**。当前以 ETSI TS 103 701 / ETSI EN 303 645 作为首个已落地、已验证的规则包和交付模板；它不是框架能力的永久边界。框架本体关注检测编排、证据链、流量事实、审查与数据边界，标准特有的条款目录、测试方法、裁决规则和报告口径则应收敛在相应的 pipeline 与规则包中。

它解决的不只是“测出一个结论”，而是让每一项结论在交付复核、客户质询和后续追溯时都能说明：测了什么、如何测、依据何在，以及敏感测试数据如何始终留在受控边界内。

框架将分散的工具执行、人工操作和流量事实组织为受控状态机：输入和环境先被固化，操作与工具调用形成收据，原始或派生证据通过哈希和索引关联到具体条款，独立审查再判断结论是否被充分支持。最终交付的不是“模型认为通过”，而是一套可回溯的验证记录和可复核的证据链。

| 核心能力 | 对合规交付的价值 |
|---|---|
| **受控检测编排** | 以阶段、门禁、恢复语义和工作区边界管理长流程，避免一次 Agent 对话失控或中断后丢失上下文。 |
| **证据可追溯性** | 输入 hash、工具收据、结构化 Evidence、审计结果和报告共享同一索引链，可定位到条款、Flow 与帧。 |
| **流量智能分析** | 将 PCAP 转换为最小化的 Flow、协议、加密和声明对齐事实，支持 AI 查询但不把原始 Payload 暴露给模型。 |
| **独立审查机制** | Work 与 Audit 使用物理隔离的 Prompt 和受限文件接口，降低“执行者按审查偏好自证”的风险。 |
| **数据分级与发布边界** | 私有 DUT、PCAP、认证流量、密钥和运行 Bundle 留在受控工作区；公开仓库只保留可复现代码、合成 fixture 与脱敏文档。 |

## 设计原则

1. **证据优先于叙述**：结论必须能回到输入、工具收据和原始/派生产物；证据不足时保留 `INCONCLUSIVE`，而不是由模型补全。
2. **最小权限与最小暴露**：Agent 只获得当前阶段需要的知识和工具；敏感流量按元数据、引用和受控下钻处理。
3. **独立性优先于自评**：执行 Agent 不读取审查策略，审查 Agent 不接受执行 Agent 的自述作为事实。
4. **真实运行与公开源码分离**：公开仓库说明框架能力和安全边界，不携带任何客户、设备或认证环境数据。

## 快速开始

```bash
py -3.11 -m venv .venv
# 激活 venv 后：
pip install -e ".[web,dev]"
# 安装锁定版本的 Playwright MCP 本地运行时（不提交 node_modules）
Push-Location tools/playwright-mcp; npm ci; Pop-Location
# 配置环境（.env 会在入口自动加载，见 .env.template）
python -m pytest tests/ -v
```

## 两个 Agent 角色

| Agent | 知道审计存在？ | 有工具？ | 加载审计标准？ |
|-------|:---:|:---:|:---:|
| **Work Agent** | ❌ | ✅ 受限只读 | ❌ |
| **Audit Agent** | — | ❌ 只读检索 | ✅ |

## Traffic Intelligence

流量阶段采用一次连续无标签操作窗：操作者只需“开始 → 完成全部设备操作 → 完成”，
不逐步骤勾选或补录时间点。`tshark` 是帧级事实来源，框架把结果整理为带完整性
manifest 的 Flow、协议候选、加密评估、未知协议簇、DNS 关联和 IXIT 声明对齐。

- Direct Tshark 是默认后端和永久回退基线。
- EasyTshark 通过无界面、无网络、无原始 Payload 的 Batch Worker 合约可选接入；
  当前仓库包含框架适配器和可执行 A/B 基准。公司部署的具体 Worker、性能与真机结果
  只保留在私有验收记录中，不以公开源码内容反推其完成状态。
- `scripts/pcap_analyzer.py` 只保留为兼容输出，不是 Agent 的主流量入口。
- UNKNOWN、高熵或未发现 TLS 均不能单独证明私有协议语义或已加密。
- 条款证据用结构化 `flowIds` / `frameNumbers` 引用已校验 Bundle。

原始 PCAP、Payload、SQLite、TLS key log、私有 dissector、密钥和运行 Bundle 均被排除在公开源码仓库之外。测试中唯一的 PCAP 形态 fixture 是两帧、零 Payload、仅使用保留测试地址的十六进制合成握手。

发布前可运行 `python scripts/audit_public_release.py`；它只输出风险文件与行号，不回显疑似敏感内容。

## 文档阅读顺序与状态

| 文档 | 定位 | 使用方式 |
|---|---|---|
| 本 README | 当前概览与公开边界 | 首先阅读。 |
| [Traffic Intelligence / EasyTshark 落地方案](docs/TRAFFIC_INTELLIGENCE_EASYTSHARK_INTEGRATION_PLAN.md) | 当前流量技术设计与公开源码契约 | 涉及 PCAP、协议、加密、EasyTshark 时以此为准；私有部署结果以验收记录为准。 |
| [NEXT_STEPS_实施计划.md](NEXT_STEPS_实施计划.md) | 当前增量状态 + 历史实施记录 | 只将顶部“当前状态”视为现状；下文保留决策背景与待办。 |
| [ARCHITECTURE.md](ARCHITECTURE.md) | 历史架构设计、ADR、数据合约与隔离机制 | 不作为完整的当前实现清单；其顶部说明列出当前事实来源。 |
| [FRAMEWORK_当前架构全景.html](FRAMEWORK_当前架构全景.html) | 可视化架构快照 | Traffic Intelligence 段反映当前主链，其余部分可能保留历史快照说明。 |
| [文件分级与公开边界](docs/FILE_CLASSIFICATION_STANDARD.md) | 公开仓库数据与文件分类 | 发布、导入真机资料前必读。 |
| [错误教训.md](错误教训.md) | 教训与回归台账 | 历史记录，不是当前能力声明。 |

## 当前状态

- **2026-09-01 状态**：项目已迁移在工作环境做适配部署，确定成功完成 **5 轮实际全量测试**。
  原始 DUT 证据、PCAP、认证流量、凭据和正式结果包按公开边界留在私有工作区，未上传 GitHub，无安全风险问题。
- M0 概念性测试闭环：已实现并真实运行（62/62，L1 PASS，L2 审计 3 轮 REJECT）
- Traffic Intelligence 框架侧：主 Bundle、Direct Tshark、可选 EasyTshark Worker
  适配、Agent 查询、报告和兼容迁移已完成；公开仓库不收录公司部署的实测 A/B 数据或正式证据包。
- 功能测试（M1–M5）：已由用户在其授权环境中完成。真实 DUT 结果、PCAP、认证流量与凭据不进入公开仓库；需要正式交付时，应从私有工作区的原始证据重新生成报告。
