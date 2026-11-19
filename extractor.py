"""Locate and run the ttd-capa extractor without bundling Microsoft DLLs."""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def find_extractor():
    configured = os.environ.get('BINJA_TTD_EXTRACTOR')
    if configured:
        path = Path(configured)
        if not path.is_file():
            raise FileNotFoundError(path)
        return path
    candidates = [ROOT / 'ttd-capa' / 'ttd' / 'bin' / 'x64' / 'Release' / 'ttdcapa-extract.exe',
                  ROOT / 'bin' / 'ttdcapa-extract.exe']
    return next((path for path in candidates if path.is_file()), None)


def find_replay_dlls():
    configured = os.environ.get('BINJA_TTD_REPLAY_DLLS')
    if configured:
        path = Path(configured)
        if not (path / 'TTDReplay.dll').is_file():
            raise FileNotFoundError(path / 'TTDReplay.dll')
        return path
    try:
        from binaryninja.settings import Settings
        dbgeng = Settings().get_string('debugger.x64dbgEngPath')
        if dbgeng and (Path(dbgeng) / 'TTD' / 'TTDReplay.dll').is_file():
            return Path(dbgeng) / 'TTD'
    except Exception:
        pass
    if sys.platform == 'win32':
        command = ['powershell', '-NoProfile', '-Command',
                   "Join-Path (Get-AppxPackage Microsoft.WinDbg).InstallLocation 'amd64\\ttd'"]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        path = Path(result.stdout.strip())
        if result.returncode == 0 and (path / 'TTDReplay.dll').is_file():
            return path
    return None


def command(trace, output=None, max_buffer=65536):
    if sys.platform != 'win32':
        raise RuntimeError('TTD extraction requires Windows')
    exe = find_extractor()
    if exe is None:
        raise FileNotFoundError('Build the ttd-capa submodule or set BINJA_TTD_EXTRACTOR')
    trace = Path(trace).resolve()
    if not trace.is_file():
        raise FileNotFoundError(trace)
    output = Path(output).resolve() if output else trace.with_suffix('.ttdb')
    args = [str(exe), str(trace), '-b', str(output), '--progress', '--max-buffer', str(max_buffer)]
    dlls = find_replay_dlls()
    if dlls:
        args += ['--ttd-dlls', str(dlls)]
    index = exe.parent / 'win32-index.bin'
    if not index.is_file():
        index = ROOT / 'ttd-capa' / 'ttd' / 'data' / 'win32-index.bin'
    if index.is_file():
        args += ['--win32-index', str(index)]
    return args
