---
name: z9mon
description: Use when analyzing Android app runtime behavior at the syscall level on a rooted arm64 device — attributing file/network/proc access to specific native libraries, ranking syscall callsites inside one .so, verifying which process or thread performs an action, or capturing bounded syscall evidence for reverse-engineering conclusions. Provides deterministic JSON CLI output designed for agent consumption.
---

# z9mon — Android syscall 动态证据 CLI

对目标 app（按 UID 过滤）采集 syscall 事件，把 PC/返回地址/FP 回溯解析到
`.so` 模块和偏移，产出可离线复查的会话。证据到模块/偏移为止，无符号名。
验证基线：Pixel 6 / Android 14 / arm64-v8a + root + KernelPatch + SuperKey
（`~/.config/z9mon/superkey`，0600）。

```bash
# 仓库内运行
PYTHONPATH=src python3 -m z9mon <command> --json
# 已安装
z9mon <command> --json
```

---

## 工作流

**采集是唯一写操作，查询纯离线读。**

```
doctor/status（只读预检）
  → capture（改变设备状态）
    → query stats（总览）
      → query events + 过滤（定位现象）
        → query callsites --module-id（归因到库）
          → address resolve（验证单个地址）
```

### 1. 预检

```bash
PYTHONPATH=src python3 -m z9mon doctor --device SERIAL --json   # 全链路体检
PYTHONPATH=src python3 -m z9mon status --device SERIAL --json   # 模块状态
```

看 `data.status`：`enabled` 应为 false、`events_buffered` 应为 0。
`status`/`stop` 可安全重试。

### 2. 采集

```bash
PYTHONPATH=src python3 -m z9mon capture \
  --device SERIAL \
  --package com.example.app \
  --duration 15 \
  --target-mode launch \
  --output ./captures \
  --json
```

- `--target-mode`：`launch`（冷启动）/ `attach`（附加运行中）/ `restart`（强停再启）。
- 结果取 `data.session`，产物：`manifest.json`、`events.bin`、`summary.json`、
  `maps/`（映射快照，地址解析直接读它）。
- `MAPS_UNAVAILABLE` 警告不影响 syscall 证据有效性。

### 3. 查询

```bash
S=/absolute/path/to/SESSION

# 总览：by_syscall / by_module / quality（先看这个）
PYTHONPATH=src python3 -m z9mon query $S --mode stats --json

# 过滤事件
PYTHONPATH=src python3 -m z9mon query $S \
  --syscall openat --contains /proc/ --limit 20 --json

# 调用点归因：某库内按频次排名
PYTHONPATH=src python3 -m z9mon query $S \
  --mode callsites --module-id MODULE_ID --json

# 单地址解析
PYTHONPATH=src python3 -m z9mon address resolve $S \
  --pid PID --address 0xADDRESS --json
```

`module_id` 从 `stats` 的 `by_module` 或事件 `resolved` 字段拿，形如
`file:fe:31:62129:/data/app/.../libaegon.so`。

---

## 事件字段

```text
process.pid / tid / comm        哪个进程哪个线程
registers.caller_callsite       系统调用返回地址-4（通常是 libc syscall 包装）
registers.caller_callsite_resolved.module_offset    libc 偏移（单对象）
backtrace_callsites_resolved[]  FP 链：caller 之上的模块+偏移（JNI/自研库在这层）
description                     解码后的参数（路径、flags 等）
```

判断"哪个库发起的调用"：看 `backtrace_callsites_resolved` 里最深的非 libc
模块；`module_offset` 是地址级证据，可直接对接静态分析。

---

## 任务配方

**A. 某路径被谁访问**：

```bash
z9mon capture --device S --package PKG --duration 15 --target-mode launch --json
z9mon query $S --syscall openat --contains /proc/meminfo --limit 10 --json
# 读 events[].backtrace_callsites_resolved[].module
```

**B. 某库在做什么、调用点在哪**：

```bash
z9mon query $S --mode stats --json          # by_module 找 module_id
z9mon query $S --mode callsites --module-id "$MID" --json
# callsites[] 按 count 降序：syscall × module_offset × 次数 × 采样地址
```

**C. 验证静态分析中的地址**：

```bash
z9mon address resolve $S --pid PID --address 0x74fbe2b5d4 --json
# mapping.module / module_offset / permissions / snapshot_id
```

**D. 判断证据质量**（下结论前必查）：

```text
query stats: quality.parser.invalid_records == 0   解析无坏记录
query stats: quality.sequence.gaps == 0             事件无缺口
capture 结果: summary.kernel_dropped == 0           内核无丢弃
三者同时成立，事件数才是可信的总量。
```

---

## 错误处置

| code | 动作 |
|---|---|
| `MODULE_NOT_LOADED` | capture 时加 `--kpm /abs/z9null_monitor.kpm` 收敛 |
| `MODULE_VERSION_UNSUPPORTED` | 同上 |
| `SYSCALL_UNSUPPORTED` | 换预设或去掉该 syscall，不枚举试探 |
| `MAPS_UNAVAILABLE` | 仅警告，继续查询 |
| `SUPERKEY_*` / `DEVICE_*` | 原样报给用户 |
| `USAGE_ERROR` | 修参数 |

---

## 约定

- Agent 调用一律 `--json`；stdout 恰好一个 JSON 对象。
- 不把 SuperKey 打印、记录或写入产物。
- 查询有界：默认 limit 20，优先 `--mode stats`，不直接读 `events.bin`。
- 模块对比用 `module_id` 或完整 `path`；`module` 只是展示名，同名 so 会撞。
- 保留原始运行时地址；`callsite` 已减 4，不要把 syscall PC 当返回地址。
- 模块部署默认 `--kpm` 收敛（sha256 相同跳过）；`--load-module` 无条件替换。
