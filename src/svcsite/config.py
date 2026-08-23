from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import stat

from svcsite.errors import EXIT_CONFIG, SvcSiteError


DEFAULT_KEY_FILE = Path("~/.config/svcsite/superkey").expanduser()


@dataclass(frozen=True)
class SuperKey:
    value: str
    source: str


def _validate_value(value: str, source: str) -> SuperKey:
    normalized = value.strip()
    if not normalized:
        raise SvcSiteError(
            "SUPERKEY_EMPTY",
            "SuperKey is empty",
            EXIT_CONFIG,
            {"source": source},
        )
    if any(character in normalized for character in ("\0", "\r", "\n")):
        raise SvcSiteError(
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
        raise SvcSiteError(
            "SUPERKEY_FILE_NOT_FOUND",
            "SuperKey file was not found",
            EXIT_CONFIG,
            {"path": str(path)},
        ) from exc
    except OSError as exc:
        raise SvcSiteError(
            "SUPERKEY_FILE_UNREADABLE",
            "SuperKey file could not be inspected",
            EXIT_CONFIG,
            {"path": str(path), "reason": str(exc)},
        ) from exc

    if not stat.S_ISREG(file_stat.st_mode):
        raise SvcSiteError(
            "SUPERKEY_FILE_INVALID",
            "SuperKey path is not a regular file",
            EXIT_CONFIG,
            {"path": str(path)},
        )

    mode = stat.S_IMODE(file_stat.st_mode)
    if mode & 0o077:
        raise SvcSiteError(
            "SUPERKEY_FILE_PERMISSIONS",
            "SuperKey file must not be accessible by group or others",
            EXIT_CONFIG,
            {"path": str(path), "mode": f"{mode:04o}", "required": "0600"},
        )

    if hasattr(os, "getuid") and file_stat.st_uid != os.getuid():
        raise SvcSiteError(
            "SUPERKEY_FILE_OWNER",
            "SuperKey file must be owned by the current user",
            EXIT_CONFIG,
            {"path": str(path)},
        )

    try:
        value = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SvcSiteError(
            "SUPERKEY_FILE_UNREADABLE",
            "SuperKey file could not be read",
            EXIT_CONFIG,
            {"path": str(path), "reason": str(exc)},
        ) from exc

    return _validate_value(value, f"file:{path}")


def read_superkey(
    key_file: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> SuperKey:
    env = os.environ if environ is None else environ

    configured_path = key_file or env.get("SVCSITE_SUPERKEY_FILE")
    if configured_path:
        return _read_key_file(Path(configured_path).expanduser())

    if DEFAULT_KEY_FILE.exists():
        return _read_key_file(DEFAULT_KEY_FILE)

    environment_value = env.get("SVCSITE_SUPERKEY")
    if environment_value is not None:
        return _validate_value(environment_value, "env:SVCSITE_SUPERKEY")

    raise SvcSiteError(
        "SUPERKEY_NOT_CONFIGURED",
        "Configure a 0600 SuperKey file or SVCSITE_SUPERKEY",
        EXIT_CONFIG,
        {"default_path": str(DEFAULT_KEY_FILE)},
    )
