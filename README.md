# Z9Null Monitor CLI

面向 Codex、Claude Code 等 AI Agent 的 Android syscall 动态分析 CLI。

本仓库将承载 Z9Null Monitor 的主机端 CLI。CLI 通过 ADB、root shell 和
KernelPatch 模块采集目标进程的 syscall 运行时证据，并以稳定、可查询的
JSON/JSONL 与二进制产物提供给 Agent。

## 项目边界

- 提供设备与 KernelPatch 环境检查。
- 按包名、UID、PID 和 syscall 集合执行有界采集。
- 解析、过滤和导出 Z9Null Monitor 事件。
- 保持无交互、结构化输出和稳定退出码。
- 不包装或编排 IDA、GumTrace、Frida、Reqable。
- 不在 CLI 内嵌大模型。

## 状态

仓库已独立建立，业务代码尚未迁入。后续实现将从最小的
`doctor`、`status`、`capture`、`query`、`stop` 命令开始。
