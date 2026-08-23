---
name: z9mon
description: Use when analyzing Android app runtime behavior at the syscall level on a rooted arm64 device — attributing file, network, or proc access to processes, threads, native modules, and module offsets through bounded syscall capture and query results designed for agent consumption.
---

# z9mon — Android syscall 动态证据 CLI

对目标 app 或精确 PID 采集 syscall 事件，把 PC、返回地址和 FP 回溯解析到
`.so` 模块及偏移。证据到模块偏移为止，不提供符号名。

验证基线：Pixel 6 / Android 14 / arm64-v8a + root + KernelPatch + SuperKey。

```bash
# 仓库内运行
PYTHONPATH=src python3 -m z9mon <command> --json
# 已安装
z9mon <command> --json
```

如果 `z9mon` 不在 `PATH`，定位本仓库后用绝对 `PYTHONPATH` 调用，或报告工具
不可用。不要读取 SuperKey 内容，也不要退回到裸 `kpatch kpm ctl0`。

## 唯一工作流

`capture` 是任务级写操作，`query` 是纯离线读操作：

```text
doctor/status（按需预检） → capture → query
```

### 1. 预检

```bash
z9mon doctor --device SERIAL --json
z9mon status --device SERIAL --json
```

`status` 和 `stop` 可安全重试。正常空闲状态是 `enabled == false` 且
`events_buffered == 0`。

### 2. 采集

```bash
z9mon capture \
  --device SERIAL \
  --package com.example.app \
  --duration 15 \
  --target-mode launch \
  --output ./captures \
  --json
```

- `--package PKG` 和 `--pid PID` 二选一。
- PID 是精确 TGID 过滤，只支持默认的 `attach` 模式。
- package 可使用 `attach`、`launch` 或 `restart`。
- 结果中的 `data.session` 是绝对 session 路径。
- session 只有 `manifest.json`、`events.bin` 和 `maps/`；摘要在
  `manifest.json` 的 `summary` 字段中。
- maps 获取失败只产生 warning，不影响已经采集的 syscall 证据。

如果 capture 返回 `MODULE_NOT_LOADED` 或 `MODULE_VERSION_UNSUPPORTED`，且能确定
当前仓库 KPM 的绝对路径，则用同一条 capture 加上
`--kpm /absolute/path/to/z9null_monitor.kpm` 重试一次。该参数按 sha256 收敛，
已一致时不会替换。不要猜测 KPM 路径，也不要主动绕过显式加载。

### 3. 查询

```bash
z9mon query /absolute/path/to/SESSION \
  --syscall openat,read \
  --contains /proc/ \
  --limit 20 \
  --json
```

一次 query 固定返回：

- `events`：具体 syscall、进程/线程、参数和已解析回溯；
- `callsites`：按频次排列的 syscall × module × module_offset；
- `counts`：匹配数、返回数和截断数；
- `quality`：内核丢弃、序列缺口和解析器状态。

`--limit` 默认 20，同时约束 `events` 和 `callsites`。还可用 `--pid`、`--tid`
或 `--module-id` 缩小结果。`module_id` 从首次查询的 event resolved 字段或
callsites 中取得：

```bash
z9mon query "$S" --module-id "$MID" --limit 20 --json
```

## 逆向分析要点

```text
events[].process.pid / tid / comm        哪个进程、线程
events[].description                     syscall 参数，如路径和 flags
events[].registers.caller_callsite       原始返回地址 - 4
events[].backtrace_callsites_resolved[]  FP 链上的模块和偏移
callsites[]                               高频 syscall 调用点
```

判断哪个库发起调用时，优先看 `backtrace_callsites_resolved` 中最深的非 libc
模块。把 `module_id` 和 `module_offset` 交给静态分析工具继续定位。`module` 只是
展示名；不同 APK 或库可能同名，比较映射时必须使用 `module_id` 或完整 `path`。

原始 `caller` 和 backtrace 值是 ARM64 返回地址；派生 callsite 已减 4。不要把
syscall PC 当作返回地址。

## 常用任务

查某路径由谁访问：

```bash
z9mon capture --device S --package PKG --duration 15 --target-mode launch --json
z9mon query "$S" --syscall openat --contains /proc/meminfo --limit 10 --json
```

查某个库的高频调用点：

```bash
z9mon query "$S" --limit 20 --json
z9mon query "$S" --module-id "$MID" --limit 20 --json
```

采集独立 root 进程：

```bash
z9mon capture --device S --pid PID --duration 10 \
  --syscall openat,read,connect,sendto --json
z9mon query "$S" --pid PID --limit 20 --json
```

下结论前检查：

```text
quality.kernel_dropped == 0
quality.sequence.gaps == 0
quality.parser.invalid_records == 0
```

## 错误处置

| code | 动作 |
|---|---|
| `MODULE_NOT_LOADED` | capture 加已知的绝对 `--kpm` 路径后重试 |
| `MODULE_VERSION_UNSUPPORTED` | 同上 |
| `SYSCALL_UNSUPPORTED` | 去掉该 syscall，不枚举试探 |
| `MAPS_UNAVAILABLE` | 仅 warning，继续查询 syscall 证据 |
| `SUPERKEY_*` / `DEVICE_*` | 原样报告给用户 |
| `USAGE_ERROR` | 修正参数 |

## 约定

- Agent 调用一律使用 `--json`；stdout 必须恰好一个 JSON 对象。
- 不打印、记录或写入 SuperKey。
- 不直接读取或解析 `events.bin`，使用有界 `query`。
- capture 必须以 monitoring disabled 且 `events_buffered == 0` 结束。
