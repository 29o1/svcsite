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
- Module loading must remain an explicit operation. `--load-module` replaces
  unconditionally; `--kpm` converges (skips replacement when the deployed
  sha256 already matches) and may also come from config `kpm_path`.
- Treat `capture` as the task-level write operation and `query` as read-only.
- A capture must finish with monitoring disabled and `events_buffered == 0`.
- Capture maps for every process under the target UID after launch and before
  stop. Maps failures are warnings and must not invalidate syscall evidence.
- Prefer `query --mode stats` or a narrow `query --limit N` over reading
  `events.bin` directly.
- Query defaults to compact address details and 20 events. Use
  `--detail full` only when mapping bounds and permissions are required.
- Use `query --mode callsites --module-id MODULE_ID` to rank unique syscall
  callsites for one exact mapped binary.
- Preserve raw runtime addresses. Resolved module/base/offset fields are
  additive, and sessions without mapping data remain queryable.
- Preserve raw ARM64 return addresses. Derived callsites subtract four bytes
  and remain additive; do not treat the syscall PC itself as a return address.
- Keep binary v1 sessions readable while new captures use binary v2 with up to
  16 FP-chain return addresses.
- Treat `module` as a display name only. Use `module_id` or the full `path`
  when comparing mappings because unrelated APKs and libraries can share a
  basename.
- Custom syscall selection is restricted to KPM Tier1/Tier2 hooks with a
  statically declared arity; handle `SYSCALL_UNSUPPORTED` rather than retrying
  arbitrary syscall numbers.
- `bench run` is operator tooling: it converges the module via `--kpm`, runs
  repeated captures, changes device state for minutes, and writes reports under
  `./bench`. Reports carry fingerprints (git, module, device) but never the
  SuperKey. `bench compare` is offline and read-only; its human table goes to
  stderr while stdout keeps the single-JSON contract.

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

Run one bounded capture:

```bash
PYTHONPATH=src python3 -m z9mon capture \
  --device SERIAL \
  --package TARGET \
  --duration 15 \
  --target-mode launch \
  --output ./captures \
  --json
```

If the module is absent, report `MODULE_NOT_LOADED`; use
`--load-module /absolute/path/to/z9null_monitor.kpm` when unconditional module
replacement was requested, or `--kpm /absolute/path/to/z9null_monitor.kpm` to
converge (replace only when the deployed sha256 differs). Explicit module
loading has a minimum 60-second per-command wait because it installs kernel
hooks; `stop`, `capture`, and module loading affect device state.

Benchmark the current build against a controlled workload:

```bash
PYTHONPATH=src python3 -m z9mon bench run \
  --device SERIAL \
  --kpm /absolute/path/to/z9null_monitor.kpm \
  --json
```

Compare two bench reports (offline, read-only):

```bash
PYTHONPATH=src python3 -m z9mon bench compare \
  /absolute/path/to/bench/OLD_RUN/report.json \
  /absolute/path/to/bench/NEW_RUN/report.json \
  --json
```

Read a bounded result:

```bash
PYTHONPATH=src python3 -m z9mon query \
  /absolute/path/to/SESSION \
  --syscall openat,read \
  --contains /proc/ \
  --limit 50 \
  --json
```

Capture artifacts are `manifest.json`, `events.bin`, `summary.json`, and
raw snapshots under `maps/`. Address resolution parses the raw `maps/`
snapshots; legacy sessions that carry `modules.json` are resolved from it.
JSONL is produced only by `query --format jsonl`.

Resolve one address without modifying device state:

```bash
PYTHONPATH=src python3 -m z9mon address resolve \
  /absolute/path/to/SESSION \
  --pid PID \
  --address 0xADDRESS \
  --json
```

## Source boundaries

- `src/z9mon/`: host-side Python implementation.
- `kpm/`: locally modified KPM derived from the upstream documented in
  `UPSTREAM.md`.
- `KernelPatch/`: pinned upstream Git submodule; do not edit it locally.

Do not migrate the legacy Android UI or PC Web Viewer into this repository.
