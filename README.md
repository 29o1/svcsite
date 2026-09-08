# svcsite

English | [简体中文](README.zh-CN.md)

Android ARM64 syscall tracing and callsite analysis from the command line.

svcsite uses ADB and a KernelPatch Module (KPM) to record syscall arguments,
PC, LR, and up to 16 return addresses. It resolves addresses to mapped modules
and offsets, with JSON output for scripts and AI agents.

## Requirements

- macOS, Python 3.11+, and ADB
- Rooted Android ARM64 device with KernelPatch, `kpatch`, and a SuperKey
- `make` and Android NDK (build tested with r29)

Validated on a Pixel 6 running Android 14 on arm64-v8a.

## Installation and build

Replace `NDK_DIR` below with your installed NDK directory:

```bash
git clone --recurse-submodules https://github.com/29o1/svcsite.git
cd svcsite
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
make kpm NDK_DIR="/absolute/path/to/android-ndk-r29"
```

The build produces `kpm/svcsite.kpm`. Keep the virtual environment active
when running `svcsite`.

## SuperKey

Save the SuperKey as a single line in a `0600` file. These preparation
commands preserve existing contents:

```bash
mkdir -p ~/.config/svcsite
(umask 077 && touch ~/.config/svcsite/superkey)
chmod 600 ~/.config/svcsite/superkey
${EDITOR:-vi} ~/.config/svcsite/superkey
```

Use `--key-file` to select another file. The key is excluded from command
output, logs, and capture artifacts.

## Quick start

Run from the repository root. Replace `SERIAL` with the serial from
`adb devices` and `io.example.target` with your app's package name. Check the
environment, then capture for 15 seconds while interacting with the app:

```bash
svcsite doctor --device SERIAL --json
svcsite capture --device SERIAL --package io.example.target \
  --target-mode launch --duration 15 --output ./captures \
  --kpm "$PWD/kpm/svcsite.kpm" --json
```

Pass `--kpm` for the first load or an update. svcsite compares SHA-256 values
and skips installation when the device module already matches.

Copy `data.session` from the capture result and query it offline:

```bash
SESSION='/absolute/path/to/captures/SESSION_ID'
svcsite query "$SESSION" --limit 20 --json
```

Query returns `events`, ranked `callsites`, `counts`, and `quality` under
`data`. `--limit` defaults to 20 and bounds both lists. Filters include
`--syscall`, `--contains`, `--pid`, `--tid`, and `--module-id`.

A completed capture stops monitoring and drains buffered events. To check
status or clean up after an interruption:

```bash
svcsite status --device SERIAL --json
svcsite stop --device SERIAL --json
```

Specify exactly one of `--package` (UID filtering, possibly multiple processes)
or `--pid` (one exact process, attach only). `--target-mode` supports `attach`
(default), `launch`, and `restart` (force-stop, then launch).

Capture defaults to the 16 syscalls in `reverse-basic`. Use
`--syscall openat,read` to select a different set supported by the KPM.

## Output and references

Sessions contain `manifest.json`, `events.bin`, and snapshots under `maps/`.
Mapping failures leave syscall records usable but may prevent module attribution.
Check `quality` for event loss; list truncation by `--limit` only affects display.

`--json` emits one compact JSON object. Failures include a stable `error.code`
and a non-zero exit status. See `svcsite capture --help` and
`svcsite query --help` for options, or [`SKILL.md`](SKILL.md) for AI agent
integration and evidence interpretation. Run `make check` for host-side checks.
