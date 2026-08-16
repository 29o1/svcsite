from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat

from z9mon.errors import EXIT_CONFIG, Z9MonError


DEFAULT_KEY_FILE = Path("~/.config/z9mon/superkey").expanduser()
DEFAULT_CONFIG_FILE = Path("~/.config/z9mon/config.json").expanduser()


@dataclass(frozen=True)
class SuperKey:
    value: str
    source: str


def _validate_value(value: str, source: str) -> SuperKey:
    normalized = value.strip()
    if not normalized:
        raise Z9MonError(
            "SUPERKEY_EMPTY",
            "SuperKey is empty",
            EXIT_CONFIG,
            {"source": source},
        )
    if any(character in normalized for character in ("\0", "\r", "\n")):
        raise Z9MonError(
            "SUPERKEY_INVALID",
            "SuperKey contains an unsupported control character",
            EXIT_CONFIG,
            {"source": source},
        )
    return SuperKey(normalized, source)


def _read_key_file(path: Path) -> SuperKey:
    try:
        file_stat = path.stat()
    except FileNotFoundError as exc:
        raise Z9MonError(
            "SUPERKEY_FILE_NOT_FOUND",
            "SuperKey file was not found",
            EXIT_CONFIG,
            {"path": str(path)},
        ) from exc
    except OSError as exc:
        raise Z9MonError(
            "SUPERKEY_FILE_UNREADABLE",
            "SuperKey file could not be inspected",
            EXIT_CONFIG,
            {"path": str(path), "reason": str(exc)},
        ) from exc

    if not stat.S_ISREG(file_stat.st_mode):
        raise Z9MonError(
            "SUPERKEY_FILE_INVALID",
            "SuperKey path is not a regular file",
            EXIT_CONFIG,
            {"path": str(path)},
        )

    mode = stat.S_IMODE(file_stat.st_mode)
    if mode & 0o077:
        raise Z9MonError(
            "SUPERKEY_FILE_PERMISSIONS",
            "SuperKey file must not be accessible by group or others",
            EXIT_CONFIG,
            {"path": str(path), "mode": f"{mode:04o}", "required": "0600"},
        )

    if hasattr(os, "getuid") and file_stat.st_uid != os.getuid():
        raise Z9MonError(
            "SUPERKEY_FILE_OWNER",
            "SuperKey file must be owned by the current user",
            EXIT_CONFIG,
            {"path": str(path)},
        )

    try:
        value = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise Z9MonError(
            "SUPERKEY_FILE_UNREADABLE",
            "SuperKey file could not be read",
            EXIT_CONFIG,
            {"path": str(path), "reason": str(exc)},
        ) from exc

    return _validate_value(value, f"file:{path}")


def read_config(
    config_file: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Read the optional JSON config file; missing files are empty configs."""

    env = os.environ if environ is None else environ
    configured = config_file or env.get("Z9MON_CONFIG")
    path = Path(configured).expanduser() if configured else DEFAULT_CONFIG_FILE
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Z9MonError(
            "CONFIG_INVALID",
            "config file could not be read",
            EXIT_CONFIG,
            {"path": str(path), "reason": str(exc)},
        ) from exc
    if not isinstance(loaded, dict):
        raise Z9MonError(
            "CONFIG_INVALID",
            "config file must contain a JSON object",
            EXIT_CONFIG,
            {"path": str(path)},
        )
    return loaded


def resolve_kpm_path(
    explicit: str | None,
    *,
    config_file: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> str | None:
    """Resolve the converge target: --kpm wins, then config kpm_path."""

    if explicit and explicit.strip():
        return explicit.strip()
    configured = read_config(config_file, environ).get("kpm_path")
    if isinstance(configured, str) and configured.strip():
        return configured.strip()
    return None


def read_superkey(
    key_file: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> SuperKey:
    env = os.environ if environ is None else environ

    configured_path = key_file or env.get("Z9MON_SUPERKEY_FILE")
    if configured_path:
        return _read_key_file(Path(configured_path).expanduser())

    if DEFAULT_KEY_FILE.exists():
        return _read_key_file(DEFAULT_KEY_FILE)

    environment_value = env.get("Z9MON_SUPERKEY")
    if environment_value is not None:
        return _validate_value(environment_value, "env:Z9MON_SUPERKEY")

    raise Z9MonError(
        "SUPERKEY_NOT_CONFIGURED",
        "Configure a 0600 SuperKey file or Z9MON_SUPERKEY",
        EXIT_CONFIG,
        {"default_path": str(DEFAULT_KEY_FILE)},
    )
