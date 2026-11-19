"""Memory-mapped reader for ttd-capa's version 2 .ttdb reports."""
from __future__ import annotations

import mmap
import shlex
import struct
from dataclasses import dataclass
from pathlib import Path

KINDS = ('', 'int', 'bool', 'handle', 'enum', 'float', 'double', 'str', 'wstr',
         'strbuf', 'wstrbuf', 'buf', 'int*', 'struct*', 'fnptr', 'guid', 'ptr', 'str*', 'wstr*')
CALL = struct.Struct('<QIIIIIIIHHQ')


@dataclass(frozen=True)
class Parameter:
    name: str
    type: str
    kind: str
    value: int
    string: str = ''
    flags: str = ''
    data: bytes = b''
    data_total: int = 0
    deref: int | None = None
    out: bool = False
    at_return: bool = False

    def __str__(self):
        value = self.string and repr(self.string) or self.flags or hex(self.deref if self.deref is not None else self.value)
        if self.data:
            value += ' [' + self.data[:32].hex(' ') + (' …' if len(self.data) > 32 else '') + ']'
        if self.data_total > len(self.data):
            value += f' (first {len(self.data)} of {self.data_total} bytes)'
        return f'{self.name or self.kind}: {value}'


@dataclass(frozen=True)
class Call:
    index: int
    ret: int
    tid: int
    sequence: int
    steps: int
    module: str
    api: str
    param_offset: int
    param_count: int
    decoded: bool
    search: bytes
    return_address: int

    @property
    def position(self):
        return f'{self.sequence:X}:{self.steps:X}'


class Report:
    def __init__(self, path):
        self.path = Path(path)
        self._file = self.path.open('rb')
        try:
            self._map = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
            data = self._map
            if len(data) < 128 or data[:8] != b'TTDBEHV1' or struct.unpack_from('<I', data, 8)[0] != 2:
                raise ValueError('unsupported .ttdb header')
            self.arch = struct.unpack_from('<I', data, 12)[0]
            (self.call_count, self.param_bytes, self.pid, self.calls_off, self.params_off,
             self.strings_off, self.strings_size, self.blob_off, self.blob_size,
             self.decoded_count) = struct.unpack_from('<10Q', data, 16)
            regions = ((self.calls_off, self.call_count * CALL.size),
                       (self.params_off, self.param_bytes), (self.strings_off, self.strings_size),
                       (self.blob_off, self.blob_size))
            if any(start < 128 or size > len(data) or start > len(data) - size for start, size in regions):
                raise ValueError('invalid .ttdb region')
        except Exception:
            self.close()
            raise

    def close(self):
        if hasattr(self, '_map'):
            self._map.close()
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _string(self, offset):
        if offset >= self.strings_size:
            raise ValueError('invalid string offset')
        start = self.strings_off + offset
        end = self._map.find(b'\0', start, self.strings_off + self.strings_size)
        if end < 0:
            raise ValueError('unterminated string')
        return self._map[start:end].decode('utf-8', 'replace')

    def _blob(self, offset, length):
        if offset > self.blob_size or length > self.blob_size - offset:
            raise ValueError('invalid blob offset')
        start = self.blob_off + offset
        return self._map[start:start + length]

    def call(self, index):
        if not 0 <= index < self.call_count:
            raise IndexError(index)
        (ret, tid, seq, steps, mod, api, param, search, count, search_len,
         retaddr) = CALL.unpack_from(self._map, self.calls_off + index * CALL.size)
        return Call(index, ret, tid, seq, steps, self._string(mod), self._string(api),
                    param, count & 0x7fff, bool(count & 0x8000), self._blob(search, search_len), retaddr)

    def parameters(self, call):
        if not call.param_count:
            return []
        if call.param_offset >= self.param_bytes:
            raise ValueError('invalid parameter offset')
        offset = self.params_off + call.param_offset
        end = self.params_off + self.param_bytes
        result = []
        for _ in range(call.param_count):
            if offset + 18 > end:
                raise ValueError('truncated parameter')
            kind, bits, name, typ, value = struct.unpack_from('<BBIIQ', self._map, offset)
            offset += 18
            extra = 8 * bool(bits & 4) + 8 * bool(bits & 8) + 16 * bool(bits & 16) + 8 * bool(bits & 32)
            if offset + extra > end:
                raise ValueError('truncated parameter data')
            deref = None
            string = flags = ''
            data = b''
            total = 0
            if bits & 4:
                deref, = struct.unpack_from('<Q', self._map, offset); offset += 8
            if bits & 8:
                pos, size = struct.unpack_from('<II', self._map, offset); offset += 8
                string = self._blob(pos, size).decode('utf-8', 'replace')
            if bits & 16:
                pos, size, total = struct.unpack_from('<IIQ', self._map, offset); offset += 16
                data = self._blob(pos, size)
            if bits & 32:
                pos, size = struct.unpack_from('<II', self._map, offset); offset += 8
                flags = self._blob(pos, size).decode('utf-8', 'replace')
            result.append(Parameter(self._string(name), self._string(typ),
                                    KINDS[kind] if kind < len(KINDS) else '', value,
                                    string, flags, data, total, deref, bool(bits & 1), bool(bits & 2)))
        return result

    def query(self, expression):
        terms = shlex.split(expression)
        for index in range(self.call_count):
            call = self.call(index)
            if all(_matches(call, term) for term in terms):
                yield index


def _numeric(value, condition):
    try:
        if condition.startswith('!'):
            return value != int(condition[1:], 0)
        for op in ('>=', '<=', '>', '<'):
            if condition.startswith(op):
                n = int(condition[len(op):], 0)
                return {'>=': value >= n, '<=': value <= n, '>': value > n, '<': value < n}[op]
        if '-' in condition:
            a, b = condition.split('-', 1)
            return int(a, 0) <= value <= int(b, 0)
        return value == int(condition, 0)
    except ValueError:
        return False


def _matches(call, term):
    key, sep, value = term.partition(':')
    if sep:
        if key in ('module', 'api'):
            actual = getattr(call, key).lower()
            value = value.lower()
            return actual.startswith(value[:-1]) if value.endswith('*') else actual == value
        if key in ('tid', 'ret', 'retaddr'):
            return _numeric(getattr(call, {'retaddr': 'return_address'}.get(key, key)), value)
    return term.lower().encode('utf-8') in call.search
