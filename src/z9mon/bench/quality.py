"""Evidence-quality and integrity metrics derived from session artifacts."""

from __future__ import annotations

import json
from pathlib import Path
import statistics
from typing import Any

from z9mon.bench.metrics import percentile
from z9mon.maps import ModuleIndex
from z9mon.protocol import open_event_stream
from z9mon.query import event_callsites


def compute_quality_metrics(session_dir: str | Path) -> dict[str, Any]:
    session = Path(session_dir)
    module_index = ModuleIndex.from_session(session)
    total = 0
    resolved_events = 0
    attributed_events = 0
    frames_total = 0
    frames_resolved = 0
    depths: list[int] = []
    unique_callsites: set[tuple[int, str | None, str | None]] = set()

    with open_event_stream(session / "events.bin") as stream:
        for event in stream:
            total += 1
            depth = len(event.backtrace)
            depths.append(depth)
            frames_total += depth
            callsites = (
                event_callsites(event, module_index) if module_index else []
            )
            if callsites:
                resolved_events += 1
            attributed = False
            for callsite in callsites:
                resolved = callsite["resolved"]
                if callsite["frame"] == "backtrace":
                    frames_resolved += 1
                if str(resolved.get("module_id", "")).startswith("file:"):
                    attributed = True
                unique_callsites.add(
                    (
                        event.nr,
                        resolved.get("module_id"),
                        resolved.get("module_offset"),
                    )
                )
            if attributed:
                attributed_events += 1
        parser_quality = stream.quality()

    summary: dict[str, Any] = {}
    manifest_path = session / "manifest.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            loaded = (
                manifest.get("summary") if isinstance(manifest, dict) else None
            )
            if isinstance(loaded, dict):
                summary = loaded
        except (OSError, json.JSONDecodeError):
            summary = {}
    sequence = summary.get("sequence", {})
    parser = summary.get("parser", parser_quality)

    resolution_available = module_index is not None
    return {
        "counts": {"events": total, "frames": frames_total},
        "evidence": {
            "callsite_resolve_rate": (
                round(resolved_events / total, 4)
                if total and resolution_available
                else None
            ),
            "frame_resolve_rate": (
                round(frames_resolved / frames_total, 4)
                if frames_total and resolution_available
                else None
            ),
            "module_attribution_rate": (
                round(attributed_events / total, 4)
                if total and resolution_available
                else None
            ),
            "backtrace_depth_median": int(statistics.median(depths))
            if depths
            else None,
            "backtrace_depth_p90": int(percentile(depths, 0.9)) if depths else None,
            "unique_callsites": len(unique_callsites) if resolution_available else None,
            "signal_ratio": (
                round(len(unique_callsites) / total, 4)
                if total and resolution_available
                else None
            ),
            "address_resolution_available": resolution_available,
        },
        "integrity": {
            "kernel_dropped": int(summary.get("kernel_dropped", 0)),
            "sequence_gaps": int(sequence.get("gaps", 0)),
            "sequence_missing": int(sequence.get("missing", 0)),
            "parser_invalid": int(parser.get("invalid_records", 0)),
        },
    }
