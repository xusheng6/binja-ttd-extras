# binja-ttd-extras

A standalone Binary Ninja plugin for browsing Windows API calls recorded in a Time Travel Debugging trace. It implements the TTD Behavior feature from [debugger PR #1155](https://github.com/Vector35/debugger/pull/1155) without requiring changes to the debugger plugin. The extractor remains the standalone [`ttd-capa`](https://github.com/Vector35/ttd-capa) executable, included as a Git submodule.

## Install

Clone recursively into your Binary Ninja user plugin directory under `binja-ttd-extras`, then restart Binary Ninja:

```shell
git clone --recursive https://github.com/xusheng6/binja-ttd-extras.git binja-ttd-extras
```

The plugin requires Binary Ninja with the Vector35 debugger plugin and Python UI support (PySide6). Open a binary and select **Tools → TTD Extras → Behavior**. Load an existing `.ttdb` report on any platform. Filter with terms such as `module:kernel32 api:WriteFile ret:!0`, inspect arguments, and double-click a call to time travel in the matching active TTD session.

On Windows, **Extract…** selects a `.run` trace and writes `<trace>.ttdb`. Build the submodule executable first (or copy the Windows CI artifact into `bin/`):

```powershell
cd ttd-capa\ttd
nuget restore packages.config -PackagesDirectory packages
msbuild ttdcapa-extract.vcxproj /p:Configuration=Release /p:Platform=x64
```

The plugin finds the build at `ttd-capa/ttd/bin/x64/Release/ttdcapa-extract.exe`. Set `BINJA_TTD_EXTRACTOR` to override it. It finds the Microsoft replay DLLs through the debugger's DbgEng setting or the installed WinDbg package; `BINJA_TTD_REPLAY_DLLS` overrides that path. Microsoft DLLs are not redistributed.

The report reader is independent of Binary Ninja and can be used in Python:

```python
from report import Report
with Report('sample.ttdb') as report:
    for index in report.query('api:CreateFileW'):
        call = report.call(index)
        print(call.position, call.api, report.parameters(call))
```

## CI

Linux CI tests the report reader and compiles the plugin Python. Windows CI builds and smoke tests the `ttd-capa` extractor, then publishes it as a workflow artifact. A real TTD trace and Binary Ninja installation are required for end-to-end UI testing.

## License

Apache-2.0. The `ttd-capa` submodule retains its own license.
