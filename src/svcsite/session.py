from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
from typing import Any, Mapping

from svcsite.errors import EXIT_DATA, SvcSiteError
from svcsite.protocol import open_event_stream


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def create_session_directory(output_root: str | Path, target_label: str) -> Path:
    root = Path(output_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    safe_target = "".join(
        character if character.isalnum() or character in "._-" else "_"
        for character in target_label
    )
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    path = root / f"{timestamp}-{safe_target}"
    path.mkdir(mode=0o700)
    return path


def write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as stream:
        stream.write(encoded)
        stream.write("\n")
        temporary = Path(stream.name)
    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def summarize_event_file(
    path: str | Path,
    syscall_names: Mapping[int, str],
    *,
    kernel_dropped: int | None,
) -> tuple[dict[str, Any], set[int]]:
    by_syscall: Counter[str] = Counter()
    by_pid: Counter[str] = Counter()
    by_tid: Counter[str] = Counter()
    observed_pids: set[int] = set()
    previous: int | None = None
    gaps = 0
    missing = 0

    with open_event_stream(path) as stream:
        for event in stream:
            by_syscall[syscall_names.get(event.nr, f"sys_{event.nr}")] += 1
            by_pid[str(event.tgid)] += 1
            by_tid[str(event.pid)] += 1
            observed_pids.add(event.tgid)
            if previous is not None:
                delta = (event.seq - previous) & 0xFFFFFFFF
                if delta > 1:
                    gaps += 1
                    missing += delta - 1
            previous = event.seq
        parser_quality = stream.quality()

    return (
        {
            "event_count": parser_quality["events"],
            "kernel_dropped": kernel_dropped,
            "sequence": {"gaps": gaps, "missing": missing},
            "parser": parser_quality,
            "by_syscall": dict(sorted(by_syscall.items())),
            "by_pid": dict(sorted(by_pid.items(), key=lambda item: int(item[0]))),
            "by_tid": dict(sorted(by_tid.items(), key=lambda item: int(item[0]))),
        },
        observed_pids,
    )


def resolve_session(path_value: str | Path) -> tuple[Path, Path, dict[str, Any]]:
    path = Path(path_value).expanduser().resolve()
    if path.is_dir():
        session_dir = path
        events_path = path / "events.bin"
        manifest_path = path / "manifest.json"
    elif path.is_file():
        session_dir = path.parent
        events_path = path
        manifest_path = session_dir / "manifest.json"
    else:
        raise SvcSiteError(
            "SESSION_NOT_FOUND",
            "capture session was not found",
            EXIT_DATA,
            {"path": str(path)},
        )

    if not events_path.is_file():
        raise SvcSiteError(
            "EVENTS_NOT_FOUND",
            "events.bin was not found",
            EXIT_DATA,
            {"path": str(events_path)},
        )

    manifest: dict[str, Any] = {}
    if manifest_path.is_file():
        try:
            loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                manifest = loaded
        except (OSError, json.JSONDecodeError) as exc:
            raise SvcSiteError(
                "MANIFEST_INVALID",
                "manifest.json could not be read",
                EXIT_DATA,
                {"path": str(manifest_path), "reason": str(exc)},
            ) from exc
    return session_dir, events_path, manifest
