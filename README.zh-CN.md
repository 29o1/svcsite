# svcsite

[English](README.md) | 简体中文

基于 KernelPatch 与 ADB 的 Android ARM64 系统调用追踪工具。
面向自动化脚本与 AI Agent 设计，提供高吞吐、零符号依赖的内核级动态观测能力，输出严格保证为标准 JSON。

### 核心特性

- **内核层无感知拦截**：利用 KernelPatch (KPM) 在内核层拦截 ARM64 系统调用，无需对目标应用进行重打包或注入 ptrace。
- **调用点深度定位**：记录调用参数、真实返回值（Return Hook）、截断的 I/O 数据预览，以及最高 16 层的 FP 栈回溯。
- **模块偏移对齐**：结合采集期间的 `/proc/<pid>/maps` 快照，自动将原始地址解析为对应的共享库与相对偏移（如 `libnative.so+0x1a2b4`）。
- **离线关联分析**：采集完成后离线查询会话，支持调用点频次排行、FD 跨调用关联（文件路径与 Socket Endpoint 溯源）以及丢包率检查。
- **针对性调用集合**：默认监听 16 个核心调用；也支持针对反调试、网络请求、设备指纹等场景按需指定 syscall。

> 典型分析场景与边界说明参见 [SKILL.md](SKILL.md)。

---

## 准备工作

### 环境要求
- **宿主机**：macOS，Python 3.11+，已配置 ADB，已安装 Android NDK（推荐 r29）。
- **设备端**：已获取 Root 的 Android ARM64 设备（基线环境：Pixel 6 / Android 14），且已安装 KernelPatch (`kpatch`)。

### 1. 安装与编译
```bash
git clone --recurse-submodules https://github.com/29o1/svcsite.git
cd svcsite
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# 编译内核模块 (svcsite.kpm)
make kpm NDK_DIR="/path/to/android-ndk-r29"
```

### 2. 配置 SuperKey
将设备的 KernelPatch SuperKey 写入本地配置文件，并严格限制权限（svcsite 绝不会将密钥输出到终端、日志或会话产物中）：
```bash
mkdir -p ~/.config/svcsite
echo "你的_SUPERKEY" > ~/.config/svcsite/superkey
chmod 600 ~/.config/svcsite/superkey
```

---

## 使用流程

### 第一步：检查设备连通性
先确认 root、`kpatch` 和 SuperKey 是否工作正常：
```bash
svcsite doctor --device SERIAL --json
```

### 第二步：运行采集
启动一次限时追踪（采集完成后内核会自动停止监控并排空缓存）：
```bash
# 示例：冷启动目标应用，并采集 15 秒
svcsite capture --device SERIAL \
  --package com.example.app \
  --target-mode launch \
  --duration 15 \
  --kpm "$PWD/kpm/svcsite.kpm" \
  --output ./captures \
  --json
```

**常用选项**：
- **监控目标**：`--package` 会监控该应用 UID 下的所有进程；如果只想追踪特定单进程，改用 `--pid <PID> --target-mode attach`。
- **生命周期**：`--target-mode` 支持 `launch`（冷启动）、`restart`（杀进程后冷启动）和 `attach`（直接附着到当前运行的应用）。
- **系统调用筛选**：默认监听 16 个常用调用。若只需关注特定行为，可用 `--syscall openat,read,close` 进行覆盖。
- **模块加载**：带上 `--kpm` 会自动将模块推送到设备；若设备上已加载且 SHA-256 一致，会自动跳过刷入。

### 第三步：离线分析结果
从上一步输出的 `data.session` 获取保存路径，离线解析数据（无需连接手机）：
```bash
svcsite query /path/to/captures/SESSION_ID --limit 20 --json
```

#### 典型输出示例 (`query`)
```json
{
  "status": "ok",
  "data": {
    "callsites": [
      {
        "module": "libnative.so",
        "module_offset": "0x1a2b4",
        "path": "/data/app/.../libnative.so",
        "syscall": { "name": "openat", "nr": 56 },
        "count": 12
      }
    ],
    "quality": {
      "dropped_events": 0,
      "status": "clean"
    }
  }
}
```

---

## 辅助与运维

如果在采集过程中异常中断，可以通过以下命令检查或重置内核状态：
```bash
# 查看当前设备上的监控状态及缓冲区堆积数
svcsite status --device SERIAL --json

# 强制停止监控并复位缓冲区
svcsite stop --device SERIAL --json
```

---

## 开发者与 Agent 参考

- **Agent 交互与规范**：参见 [`AGENTS.md`](AGENTS.md)
- **分析场景组合与证据限制**：参见 [`SKILL.md`](SKILL.md)
- **运行单元测试**：`make check`
