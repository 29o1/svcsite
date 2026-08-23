"""Report rendering and git fingerprinting for bench runs."""

from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Any

from svcsite.bench.metrics import METRIC_SPECS, format_metric_value, lookup


def git_info() -> dict[str, Any] | None:
    root = Path(__file__).resolve().parents[3]
    try:
        sha = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if sha.returncode != 0:
            return None
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return {
            "sha": sha.stdout.strip(),
            "dirty": bool(status.stdout.strip()),
        }
    except (OSError, subprocess.TimeoutExpired):
        return None


def report_markdown(
    run_id: str,
    fingerprint: dict[str, Any],
    aggregate_data: dict[str, Any],
    noise: dict[str, float],
) -> str:
    git = fingerprint.get("git") or {}
    module = fingerprint.get("module") or {}
    device = fingerprint.get("device") or {}
    parameters = fingerprint.get("parameters") or {}
    lines = [
        f"# svcsite bench report — {run_id}",
        "",
        f"- generated: `{fingerprint.get('generated_at')}`",
        f"- svcsite: `{fingerprint.get('svcsite_version')}`"
        f" git `{(git.get('sha') or 'n/a')[:12]}"
        f"{' (dirty)' if git.get('dirty') else ''}`",
        f"- device: `{device.get('model')}` ({device.get('android_version')},"
        f" `{device.get('abi')}`) serial `{device.get('serial')}`",
        f"- module: loaded `{module.get('loaded_version')}`"
        f" deploy `{module.get('deploy_action')}`"
        f" sha256 `{str(module.get('kpm_sha256') or '-')[:12]}`",
        f"- workload: `{parameters.get('package')}`"
        f" {parameters.get('duration')}s x {parameters.get('trials')} trials"
        f" ({parameters.get('target_mode')})",
        "",
        "| metric | value | noise |",
        "|---|---|---|",
    ]
    for key, label, unit, _ in METRIC_SPECS:
        value = format_metric_value(lookup(aggregate_data, key), unit)
        band_value = noise.get(key)
        band = (
            format_metric_value(band_value, unit)
            if band_value is not None
            else "-"
        )
        lines.append(f"| {label} ({unit}) | {value} | {band} |")
    return "\n".join(lines) + "\n"
