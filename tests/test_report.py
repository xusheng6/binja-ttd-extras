import struct
from pathlib import Path

from report import Report


def test_report_and_query(tmp_path):
    strings = b'\0kernel32\0WriteFile\0buffer\0PVOID\0'
    blob = b'kernel32!writefile abc\0abc\0xyz'
    header = bytearray(128)
    header[:8] = b'TTDBEHV1'
    struct.pack_into('<II', header, 8, 2, 0)
    calls_off, params_off, strings_off, blob_off = 128, 176, 202, 202 + len(strings)
    struct.pack_into('<10Q', header, 16, 1, 26, 123, calls_off, params_off,
                     strings_off, len(strings), blob_off, len(blob), 1)
    call = struct.pack('<QIIIIIIIHHQ', 1, 4, 0x123, 0x45, 1, 10, 0, 0, 0x8001 | 1,
                       len(b'kernel32!writefile abc'), 0x401000)
    param = struct.pack('<BBIIQII', 7, 8, 20, 27, 0x1234, 23, 3)
    path = tmp_path / 'sample.ttdb'
    path.write_bytes(header + call + param + strings + blob)
    with Report(path) as report:
        item = report.call(0)
        assert item.position == '123:45'
        assert item.api == 'WriteFile'
        assert item.return_address == 0x401000
        assert report.parameters(item)[0].string == 'abc'
        assert list(report.query('module:kernel32 api:WriteFile ret:!0')) == [0]
        assert list(report.query('ret:0')) == []


def test_rejects_bad_region(tmp_path):
    path = tmp_path / 'bad.ttdb'
    header = bytearray(128)
    header[:8] = b'TTDBEHV1'
    struct.pack_into('<I', header, 8, 2)
    struct.pack_into('<Q', header, 40, 9999)
    struct.pack_into('<Q', header, 16, 1)
    path.write_bytes(header)
    try:
        Report(path)
    except ValueError:
        pass
    else:
        assert False
