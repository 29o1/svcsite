---
name: svcsite
description: Use for Android ARM64 reverse engineering when an agent needs bounded syscall evidence, process or thread attribution, or module-offset callsites from a rooted KernelPatch device.
---

# svcsite — Android syscall 动态证据

对目标 app 或精确 PID 采集 syscall 事件，将 PC、返回地址和 FP 回溯解析到
映射模块（APK、共享库或可执行文件）及偏移。证据到模块偏移为止，不提供符号名。

验证基线：Pixel 6 / Android 14 / arm64-v8a + root + KernelPatch + SuperKey。

```bash
svcsite <command> --json
PYTHONPATH=/absolute/path/to/svcsite/src python3 -m svcsite <command> --json
```

如果无法定位命令或仓库，报告工具不可用。不要读取 SuperKey 内容，也不要退回到
裸 `kpatch kpm ctl0`。

## 硬性约束

- Agent 调用一律使用 `--json`；stdout 必须恰好一个 JSON 对象。
- `capture` 是设备写操作，`query` 是纯离线读操作。
- 不打印、记录或写入 SuperKey。
- 模块加载必须显式使用已知绝对路径的 `--kpm`。
- 不直接读取或自行解析 `events.bin`，使用有界 `query`。
- 成功的 capture 保证 monitoring disabled 且 `events_buffered == 0`。

## 工作流

```text
doctor/status（按需） → capture → query
```

### 1. 预检

```bash
svcsite doctor --device SERIAL --json
svcsite status --device SERIAL --json
```

`status` 和 `stop` 可安全重试。仅在上一次采集中断或 status 显示仍在监控时调用
`stop`，随后重新检查状态。正常空闲状态是 `enabled == false` 且
`events_buffered == 0`。

### 2. 采集

```bash
svcsite capture --device SERIAL --package com.example.app --duration 15 \
  --target-mode launch --output ./captures --json
```

- `--package PKG` 和 `--pid PID` 二选一。
- package 按 UID 过滤，可能采集同 UID 的多个进程；可使用 `attach`、`launch`
  或 `restart`。
- PID 是精确 TGID 过滤，只支持 `attach`。
- 从成功结果的 `data.session` 读取绝对路径，后续记为 `SESSION`。
- session 包含 `manifest.json`、`events.bin` 和 `maps/`；摘要位于 manifest。

如果 capture 返回 `MODULE_NOT_LOADED` 或 `MODULE_VERSION_UNSUPPORTED`，且能确定
当前仓库 KPM 的绝对路径，则给同一条 capture 添加
`--kpm /absolute/path/to/svcsite.kpm` 并重试一次。该参数按 sha256 收敛，
已一致时不会替换。不要猜测 KPM 路径或反复重试。

maps 获取失败只产生 warning：syscall 行为证据仍有效，但模块归属可能不完整，
不得据此断言具体调用模块。

### 3. 查询

```bash
svcsite query "$SESSION" --syscall openat,read --contains /proc/ \
  --limit 20 --json
```

一次 query 返回：

- `events`：具体 syscall、进程、线程、参数和回溯。
- `callsites`：按频次排列的 syscall × module × module_offset。
- `counts`：匹配数、返回数和截断数。
- `quality`：内核丢弃、序列缺口和解析器状态。

`--limit` 默认 20，同时限制 events 和 callsites。使用 `--pid`、`--tid`、
`--contains` 或 `--module-id` 缩小结果。`module_id` 从首次查询的 resolved
字段或 callsites 中取得，再按精确值过滤：

```bash
svcsite query "$SESSION" --module-id "$MODULE_ID" --limit 20 --json
```

## 证据解释

```text
events[].process                         进程、线程、UID 和 comm
events[].description                     syscall 参数，如路径和 flags
events[].registers.pc_resolved           syscall 指令位置，通常位于系统库
events[].registers.caller_callsite_resolved
                                          syscall wrapper 的直接调用位置
events[].backtrace_callsites_resolved[]  从近到远的 FP-chain 调用位置
callsites[]                               聚合后的高频调用位置
```

从靠近 syscall 的帧开始，选择第一个已解析的目标模块或非系统模块；不要默认选择
回溯最外层。无法解析时不要推断模块归属。

`module` 只是展示名；不同 APK 或库可能同名，比较映射时使用 `module_id` 或完整
`path`。原始 caller 和 backtrace 值是 ARM64 返回地址；派生 callsite 已减 4。
不要把 syscall PC 当作返回地址。

## 证据质量

```text
quality.kernel_dropped                   0 为完整；null 为未知；大于 0 为不完整
quality.sequence.gaps                    应为 0
quality.parser.invalid_records           应为 0
quality.parser.skipped_bytes             应为 0
quality.parser.truncated_bytes           应为 0
```

任一已知质量指标异常时，在结论中明确限制，不要把缺失视为未发生。

## 错误处置

| code | 动作 |
|---|---|
| `MODULE_NOT_LOADED` / `MODULE_VERSION_UNSUPPORTED` | 使用已知绝对 `--kpm` 路径重试 capture 一次 |
| `SYSCALL_UNSUPPORTED` | 去掉该 syscall，不枚举试探 |
| `MAPS_UNAVAILABLE` | 保留 syscall 结论，不做缺乏证据的模块归属 |
| `MODULES_NOT_FOUND` | 报告 session 缺少映射，不能使用 module 过滤 |
| `SUPERKEY_*` / `DEVICE_*` | 原样报告给用户 |
| `USAGE_ERROR` | 按 CLI 参数修正一次 |
