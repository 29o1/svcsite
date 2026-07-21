from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Any, Mapping


EVENT_MAGIC = 0x45435653
EVENT_VERSION = 2
FIXED_RECORD_SIZE = 284
MAX_RECORD_SIZE = 2048
MAX_DESCRIPTION_SIZE = 1023

_MAGIC_BYTES = struct.pack("<I", EVENT_MAGIC)
_RECORD_LAYOUTS = {
    1: (struct.Struct("<IHHIIiiii12QII7Q16sHH"), 7),
    2: (struct.Struct("<IHHIIiiii12QII16Q16sHH"), 16),
}
assert _RECORD_LAYOUTS[1][0].size == 212
assert _RECORD_LAYOUTS[2][0].size == FIXED_RECORD_SIZE


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _signed_u64(value: int) -> int:
    return value - (1 << 64) if value & (1 << 63) else value


@dataclass(frozen=True)
class Event:
    version: int
    flags: int
    record_length: int
    seq: int
    nr: int
    tgid: int
    pid: int
    uid: int
    pc: int
    caller: int
    fp: int
    sp: int
    clone_fn: int
    ret_raw: int
    arguments: tuple[int, ...]
    backtrace: tuple[int, ...]
    comm: str
    description: str

    @property
    def ret(self) -> int:
        return _signed_u64(self.ret_raw)

    def to_dict(self, syscall_names: Mapping[int, str] | None = None) -> dict[str, Any]:
        name = syscall_names.get(self.nr) if syscall_names else None
        return {
            "seq": self.seq,
            "syscall": {"nr": self.nr, "name": name or f"sys_{self.nr}"},
            "process": {
                "pid": self.tgid,
                "tid": self.pid,
                "uid": self.uid,
                "comm": self.comm,
            },
            "registers": {
                "pc": _hex(self.pc),
                "caller": _hex(self.caller),
                "fp": _hex(self.fp),
                "sp": _hex(self.sp),
                "clone_fn": _hex(self.clone_fn),
                "args": [_hex(value) for value in self.arguments],
                "ret": self.ret,
                "ret_hex": _hex(self.ret_raw),
            },
            "backtrace": [_hex(value) for value in self.backtrace],
            "description": self.description,
        }


@dataclass(frozen=True)
class ParseResult:
    events: tuple[Event, ...]
    skipped_bytes: int
    invalid_records: int
    truncated_bytes: int

    def quality(self) -> dict[str, int]:
        return {
            "events": len(self.events),
            "skipped_bytes": self.skipped_bytes,
            "invalid_records": self.invalid_records,
            "truncated_bytes": self.truncated_bytes,
        }


def parse_events(data: bytes) -> ParseResult:
    events: list[Event] = []
    skipped_bytes = 0
    invalid_records = 0
    truncated_bytes = 0
    offset = 0

    while offset < len(data):
        marker = data.find(_MAGIC_BYTES, offset)
        if marker < 0:
            skipped_bytes += len(data) - offset
            break
        skipped_bytes += marker - offset
        offset = marker

        if len(data) - offset < 12:
            truncated_bytes = len(data) - offset
            break

        _, version, _, record_length = struct.unpack_from("<IHHI", data, offset)
        layout = _RECORD_LAYOUTS.get(version)
        if layout is None or record_length > MAX_RECORD_SIZE:
            invalid_records += 1
            offset += 1
            continue
        fixed_record, max_backtrace = layout
        fixed_record_size = fixed_record.size
        if record_length < fixed_record_size:
            invalid_records += 1
            offset += 1
            continue
        if len(data) - offset < record_length:
            truncated_bytes = len(data) - offset
            break

        values = fixed_record.unpack_from(data, offset)
        comm_index = 23 + max_backtrace
        description_length = values[comm_index + 1]
        if (
            description_length > MAX_DESCRIPTION_SIZE
            or fixed_record_size + description_length > record_length
        ):
            invalid_records += 1
            offset += 1
            continue

        comm = values[comm_index].split(b"\0", 1)[0].decode(
            "utf-8", errors="replace"
        )
        desc_start = offset + fixed_record_size
        description = data[
            desc_start : desc_start + description_length
        ].decode("utf-8", errors="replace")
        bt_depth = min(values[21], max_backtrace)
        events.append(
            Event(
                version=values[1],
                flags=values[2],
                record_length=values[3],
                seq=values[4],
                nr=values[5],
                tgid=values[6],
                pid=values[7],
                uid=values[8],
                pc=values[9],
                caller=values[10],
                fp=values[11],
                sp=values[12],
                clone_fn=values[13],
                ret_raw=values[14],
                arguments=tuple(values[15:21]),
                backtrace=tuple(values[23 : 23 + bt_depth]),
                comm=comm,
                description=description,
            )
        )
        offset += record_length

    return ParseResult(
        events=tuple(events),
        skipped_bytes=skipped_bytes,
        invalid_records=invalid_records,
        truncated_bytes=truncated_bytes,
    )
