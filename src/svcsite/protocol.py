from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import mmap
from pathlib import Path
import struct
from typing import Any, Iterator, Mapping

from svcsite.hexutil import hex_str


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


def _signed_u64(value: int) -> int:
    return value - (1 << 64) if value & (1 << 63) else value


@dataclass(frozen=True)
class Event:
    version: int
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
                "pc": hex_str(self.pc),
                "caller": hex_str(self.caller),
                "fp": hex_str(self.fp),
                "sp": hex_str(self.sp),
                "clone_fn": hex_str(self.clone_fn),
                "args": [hex_str(value) for value in self.arguments],
                "ret": self.ret,
                "ret_hex": hex_str(self.ret_raw),
            },
            "backtrace": [hex_str(value) for value in self.backtrace],
            "description": self.description,
        }


class EventStream(Iterator[Event]):
    """Incrementally decode events from a bytes-like object."""

    def __init__(self, data: Any) -> None:
        self._data = data
        self._offset = 0
        self.events = 0
        self.skipped_bytes = 0
        self.invalid_records = 0
        self.truncated_bytes = 0

    def __iter__(self) -> EventStream:
        return self

    def __next__(self) -> Event:
        data = self._data
        while self._offset < len(data):
            marker = data.find(_MAGIC_BYTES, self._offset)
            if marker < 0:
                self.skipped_bytes += len(data) - self._offset
                self._offset = len(data)
                break
            self.skipped_bytes += marker - self._offset
            self._offset = marker

            if len(data) - self._offset < 12:
                self.truncated_bytes = len(data) - self._offset
                self._offset = len(data)
                break

            _, version, _, record_length = struct.unpack_from(
                "<IHHI", data, self._offset
            )
            layout = _RECORD_LAYOUTS.get(version)
            if layout is None or record_length > MAX_RECORD_SIZE:
                self.invalid_records += 1
                self._offset += 1
                continue
            fixed_record, max_backtrace = layout
            fixed_record_size = fixed_record.size
            if record_length < fixed_record_size:
                self.invalid_records += 1
                self._offset += 1
                continue
            if len(data) - self._offset < record_length:
                self.truncated_bytes = len(data) - self._offset
                self._offset = len(data)
                break

            values = fixed_record.unpack_from(data, self._offset)
            comm_index = 23 + max_backtrace
            description_length = values[comm_index + 1]
            if (
                description_length > MAX_DESCRIPTION_SIZE
                or fixed_record_size + description_length > record_length
            ):
                self.invalid_records += 1
                self._offset += 1
                continue

            comm = values[comm_index].split(b"\0", 1)[0].decode(
                "utf-8", errors="replace"
            )
            desc_start = self._offset + fixed_record_size
            description = data[
                desc_start : desc_start + description_length
            ].decode("utf-8", errors="replace")
            bt_depth = min(values[21], max_backtrace)
            event = Event(
                version=values[1],
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
            self._offset += record_length
            self.events += 1
            return event

        raise StopIteration

    def quality(self) -> dict[str, int]:
        return {
            "events": self.events,
            "skipped_bytes": self.skipped_bytes,
            "invalid_records": self.invalid_records,
            "truncated_bytes": self.truncated_bytes,
        }


@contextmanager
def open_event_stream(path: str | Path) -> Iterator[EventStream]:
    source = Path(path)
    with source.open("rb") as file:
        if source.stat().st_size == 0:
            yield EventStream(b"")
            return
        with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
            yield EventStream(data)
