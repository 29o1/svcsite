# Z9Null Monitor CLI

面向 Codex、Claude Code 等 AI Agent 的 Android syscall 动态分析 CLI。

CLI 通过 ADB、root shell 和 KernelPatch Module（KPM）采集目标进程的
syscall 运行时证据，并以稳定、可查询的 JSON/JSONL 与二进制产物提供给
Agent。

## 项目定位

Z9Null Monitor 是独立的 syscall 观测工具，不负责包装或编排 IDA、
GumTrace、Frida、Reqable，也不在 CLI 内嵌大模型。Agent 根据分析目标自行
决定何时调用本工具。

```text
Codex / Claude Code / Human
              │
           z9mon CLI
              │ ADB + root + kpatch ctl0
              ▼
    Android ARM64 KernelPatch KPM
              │
              ▼
       binary event artifacts
```

## 当前能力

- `doctor`：检查 ADB、设备、ABI、root、kpatch 和 SuperKey 配置。
- `status`：读取 `z9null_monitor` KPM 状态。
- `stop`：幂等地暂停 KPM 监控。
- `capture`：按包名/UID 完成一次有界采集并生成独立 session。
- `query`：对 session 做有界过滤、聚合或 JSONL 导出。
- `address resolve`：把运行时地址归一化为模块、基址和模块内偏移。
- 采集目标 UID 下所有进程的 `/proc/<pid>/maps`，并自动补充事件地址信息。
- 二进制 v1 事件解析、损坏重同步、截断检测和序列缺口统计。
- 本地二开 KPM 源码及可复现构建入口。

## 安装

要求 Python 3.11 或更高版本：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

克隆仓库时需要初始化固定版本的 KernelPatch：

```bash
git submodule update --init --recursive
```

## SuperKey

默认从权限为 `0600` 的文件读取：

```bash
mkdir -p ~/.config/z9mon
install -m 600 /dev/null ~/.config/z9mon/superkey
${EDITOR:-vi} ~/.config/z9mon/superkey
```

也可以使用 `Z9MON_SUPERKEY_FILE` 指定其他文件，或以
`Z9MON_SUPERKEY` 作为备用来源。CLI 不输出 SuperKey。

## 使用

```bash
z9mon doctor --device SERIAL --json
z9mon status --device SERIAL --json
z9mon stop --device SERIAL --json
```

默认要求 `z9null_monitor` 已加载；模块缺失时返回稳定错误
`MODULE_NOT_LOADED`。只有显式提供 `--load-module` 时才会替换并加载模块：

```bash
z9mon capture \
  --device SERIAL \
  --package io.example.target \
  --duration 15 \
  --preset reverse-basic \
  --launch \
  --output ./captures \
  --load-module ./kpm/z9null_monitor.kpm \
  --json
```

首次模块加载会安装内核 hook；CLI 为该步骤保留至少 60 秒的单命令等待时间，
其余设备命令仍使用 `--timeout`（默认 15 秒）。

后续采集可省略 `--load-module`：

```bash
z9mon capture \
  --device SERIAL \
  --package io.example.target \
  --duration 15 \
  --preset reverse-basic \
  --restart \
  --output ./captures \
  --json
```

`--launch` 启动目标但不先清理状态；`--restart` 会先 `force-stop` 再启动，
不会清除 App 数据。KPM 按目标 UID 采集，因此同 UID 的进程都会进入原始
session，随后可按 PID/TID 查询。

自定义 syscall 会覆盖 preset，可重复或使用逗号分隔：

```bash
z9mon capture \
  --package io.example.target \
  --duration 10 \
  --syscall openat,read,ptrace \
  --json
```

自定义项限定为 KPM 中已声明正确参数个数的 Tier1/Tier2 syscall；例如
`openat`、`write`、`sendmsg`、`execveat`。不对任意 syscall 动态猜测参数
个数，未支持项返回 `SYSCALL_UNSUPPORTED`。

每次采集生成：

```text
captures/SESSION_ID/
├── manifest.json
├── events.bin
├── summary.json
├── modules.json
└── maps/
    ├── post-launch-PID.maps
    └── pre-stop-PID.maps
```

`modules.json` 保留启动后和停止前的进程映射快照；若事件中出现尚未覆盖的
PID，还会尝试生成 recovery 快照。maps 获取失败只记录 warning，不会让一次
已完成的 syscall 采集失败。

查询不会修改设备状态：

```bash
z9mon query ./captures/SESSION_ID --stats --json
z9mon query ./captures/SESSION_ID \
  --syscall openat,read \
  --contains /proc/ \
  --limit 50 \
  --json
z9mon query ./captures/SESSION_ID \
  --syscall connect \
  --limit 100 \
  --format jsonl

z9mon address resolve ./captures/SESSION_ID \
  --pid 12345 \
  --address 0x7a12345678 \
  --json
```

当 session 含有 `modules.json` 时，`query` 会保留原始 `pc`、`caller`、
`clone_fn` 和 backtrace 地址，并增加对应的 `*_resolved` 字段。解析结果只做
运行时地址归一化（`module`、`module_id`、`module_base`、`module_offset`）。
`module` 是适合展示的 basename；`module_id` 组合完整规范化路径、设备号和
inode，用于区分不同 App 中同名的 `base.apk` 或 `.so`。旧版 `modules.json`
缺少该字段时会在查询阶段自动推导。v0.3.1 不拉取 ELF，也不提供符号名或源码
行信息；旧 session 没有 `modules.json` 时仍可查询。

`--json` 模式下 stdout 只包含一个紧凑 JSON 对象。诊断信息写入 stderr，
并使用稳定的错误代码和进程退出码。

## 构建 KPM

先设置 Android SDK/NDK，再执行：

```bash
make kpm
```

默认使用仓库中的 `KernelPatch` submodule，也可显式覆盖：

```bash
make kpm KP_DIR=/absolute/path/to/KernelPatch
```

## 验证

```bash
make check
```

`make check` 对提交内的 Python 源码执行语法检查。设备端验收命令为：

```bash
z9mon capture \
  --package TARGET \
  --duration 15 \
  --preset reverse-basic \
  --launch \
  --output ./captures \
  --json
```

## 来源

KPM 基于 `XiaoWaaay/SVCMonitors` 的本地二次开发版本迁移而来，Python CLI
为本仓库新增实现。详细来源、基准提交和修改边界见
[UPSTREAM.md](UPSTREAM.md)。
