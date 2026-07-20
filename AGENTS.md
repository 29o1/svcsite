# Z9Null Monitor CLI agent instructions

## Scope

This project exposes Android ARM64 syscall evidence through a deterministic
CLI. It does not wrap other reverse-engineering tools and does not embed an
LLM.

## Target environment

- Host: macOS
- Python: 3.11+
- Device baseline: Pixel 6, Android 14, arm64-v8a
- Transport: ADB
- Privilege/module layer: root shell, kpatch, KernelPatch KPM

## Command contract

- Use `--json` for Agent calls.
- stdout must contain exactly one JSON object in JSON mode.
- Diagnostics belong on stderr.
- Errors require stable `code` values and non-zero exit codes.
- Never print, log, or place the SuperKey in an artifact.
- Return absolute paths for generated artifacts.
- Keep event queries bounded by a caller-provided limit.
- `status` and `stop` should be safe to retry.
- Module loading must remain an explicit operation.

## Development commands

```bash
make check
make kpm
```

Run device checks without modifying monitor state:

```bash
PYTHONPATH=src python3 -m z9mon doctor --device SERIAL --json
PYTHONPATH=src python3 -m z9mon status --device SERIAL --json
```

`stop`, future `capture`, and future module-loading commands affect device
state. Use them only when the task requests that effect.

## Source boundaries

- `src/z9mon/`: host-side Python implementation.
- `kpm/`: locally modified KPM derived from the upstream documented in
  `UPSTREAM.md`.
- `KernelPatch/`: pinned upstream Git submodule; do not edit it locally.

Do not migrate the legacy Android UI or PC Web Viewer into this repository.
