# ETSI Agent Framework

> ETSI TS 103 701 认证检测管线框架 — 物理隔离的多 Agent 编排系统

## 是什么

一个 **Python Agent 编排框架**，解决多 Agent 协作中的 **Goodhart's Law 污染问题**：当工作 Agent 知道审计 Agent 的存在和评判标准时，它会从"做好测试"退化为"迎合审计"。

核心解法：**物理隔离** — Work Agent 和 Audit Agent 的 system prompt 不共享任何字节，通过文件系统异步通信。

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

原始 PCAP、Payload、SQLite、TLS key log、私有 dissector、密钥和运行 Bundle 均被
排除在公开源码仓库之外。测试中唯一的 PCAP 形态 fixture 是两帧、零 Payload、仅使用
保留测试地址的十六进制合成握手。

发布前可运行 `python scripts/audit_public_release.py`；它只输出风险文件与行号，不回显
疑似敏感内容。

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

- **2026-09-14 当前状态**：项目已在工作环境跑好，并已完成 **5 轮实际全量测试**。
  原始 DUT 证据、PCAP、认证流量、凭据和正式结果包按公开边界留在私有工作区，未上传 GitHub。
- M0 概念性测试闭环：已实现并真实运行（62/62，L1 PASS，L2 审计 3 轮 REJECT）
- Traffic Intelligence 框架侧：主 Bundle、Direct Tshark、可选 EasyTshark Worker
  适配、Agent 查询、报告和兼容迁移已完成；公开仓库不收录公司部署的实测 A/B 数据或
  正式证据包。
- 功能测试（M1–M5）：已由用户在其授权环境中完成。真实 DUT 结果、PCAP、认证流量与
  凭据不进入公开仓库；需要正式交付时，应从私有工作区的原始证据重新生成报告。
