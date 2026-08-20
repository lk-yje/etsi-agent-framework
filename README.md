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
# 配置环境（.env 会在入口自动加载，见 .env.template）
python -m pytest tests/ -v
```

## 两个 Agent 角色

| Agent | 知道审计存在？ | 有工具？ | 加载审计标准？ |
|-------|:---:|:---:|:---:|
| **Work Agent** | ❌ | ✅ 受限只读 | ❌ |
| **Audit Agent** | — | ❌ 只读检索 | ✅ |

## 设计文档

- 架构设计、ADR、数据合约、隔离机制：[ARCHITECTURE.md](ARCHITECTURE.md)
- 当前实施计划（新会话先读）：[NEXT_STEPS_实施计划.md](NEXT_STEPS_实施计划.md)
- 当前架构全景：[FRAMEWORK_当前架构全景.html](FRAMEWORK_当前架构全景.html)
- 教训与回归台账：[错误教训.md](错误教训.md)

## 当前状态

- M0 概念性测试闭环：已实现并真实运行（62/62，L1 PASS，L2 审计 3 轮 REJECT）
- 功能测试（M1–M5）：等待内网真机 + Burp 认证流量 + Traffic 阶段
- 离线回归基线：`163 passed, 3 skipped`
