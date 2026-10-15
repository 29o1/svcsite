# svcsite

English | [简体中文](README.zh-CN.md)

An Android ARM64 syscall tracer and callsite analysis tool built on KernelPatch and ADB.
Designed for automation scripts and AI agents, providing deterministic, zero-symbol-dependency kernel-level dynamic observation with strict JSON outputs.

### Key Features

- **Kernel-Level Interception**: Hooks ARM64 syscalls inside the kernel via KernelPatch (KPM), requiring no app recompilation, ptrace attachment, or userspace runtime tampering.
- **Deep Callsite Attribution**: Records syscall arguments, real return values (via return hooks), truncated I/O previews, and up to 16 return addresses from the frame pointer (FP) backtrace.
- **Module & Offset Resolution**: Correlates runtime `/proc/<pid>/maps` snapshots to resolve raw addresses to shared libraries and relative offsets (e.g., `libnative.so+0x1a2b4`).
- **Offline Session Query**: Query saved captures offline with ranked callsite counts, cross-event file descriptor provenance (tracking paths and socket endpoints), and drop detection.
- **Targeted Syscall Selection**: Starts with 16 basic syscalls by default; custom lists can be specified for anti-debugging, network, or device fingerprinting analysis.

> For scenario recipes and evidence boundaries, see [SKILL.md](SKILL.md).

---

## Prerequisites & Setup

### Requirements
- **Host**: macOS, Python 3.11+, ADB, Android NDK (r29 recommended).
- **Device**: Rooted Android ARM64 device (tested on Pixel 6 / Android 14) with KernelPatch (`kpatch`) installed.

### 1. Install & Build
```bash
git clone --recurse-submodules https://github.com/29o1/svcsite.git
cd svcsite
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Build the kernel module (svcsite.kpm)
make kpm NDK_DIR="/path/to/android-ndk-r29"
```

### 2. Configure SuperKey
Save your KernelPatch SuperKey with `0600` permissions (svcsite guarantees the key is never leaked into stdout, logs, or capture artifacts):
```bash
mkdir -p ~/.config/svcsite
echo "YOUR_SUPERKEY" > ~/.config/svcsite/superkey
chmod 600 ~/.config/svcsite/superkey
```

---

## Quick Start

### Step 1: Preflight Check
Verify ADB, root, `kpatch`, and SuperKey connectivity:
```bash
svcsite doctor --device SERIAL --json
```

### Step 2: Run a Bounded Capture
Start a timed capture while interacting with the target app (monitoring stops and kernel buffers drain automatically when complete):
```bash
# Example: Launch target app and record for 15 seconds
svcsite capture --device SERIAL \
  --package com.example.app \
  --target-mode launch \
  --duration 15 \
  --kpm "$PWD/kpm/svcsite.kpm" \
  --output ./captures \
  --json
```

**Common Options**:
- **Target Selection**: `--package` tracks all processes under the app UID; for a single process, use `--pid <PID> --target-mode attach`.
- **Target Lifecycle**: `--target-mode` supports `launch` (cold start), `restart` (force-stop then launch), and `attach` (attach to existing process).
- **Syscall Selection**: Omitting `--syscall` monitors the 16 default calls; specifying `--syscall` overrides the set.
- **Module Deployment**: `--kpm` pushes and loads the module; it automatically skips re-installation if the on-device SHA-256 matches.

### Step 3: Offline Analysis
Take `data.session` from the capture output and query it offline without needing the device:
```bash
svcsite query /path/to/captures/SESSION_ID --limit 20 --json
```

#### Sample Query Output
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

## Maintenance & Recovery

If a capture is interrupted unexpectedly, inspect or reset the device monitoring state:
```bash
# Check monitor status and buffered events count
svcsite status --device SERIAL --json

# Force stop monitoring and flush kernel buffer
svcsite stop --device SERIAL --json
```

---

## References & Development

- **Agent Integration Contract**: See [`AGENTS.md`](AGENTS.md)
- **Scenario Recipes & Boundaries**: See [`SKILL.md`](SKILL.md)
- **Unit Tests**: Run `make check`
