"""Python API compatible with the TTD Behavior report workflow."""
from .report import Report, Parameter
from .extractor import command, find_extractor, find_replay_dlls

TTDApiCallParam = Parameter


class TTDApiCall:
    def __init__(self, report, call, with_params=True):
        self.index = call.index
        self.tid = call.tid
        self.position_sequence = call.sequence
        self.position_steps = call.steps
        self.position = call.position
        self.module = call.module
        self.api = call.api
        self.ret = call.ret
        self.return_address = call.return_address
        self.decoded = call.decoded
        self.params = report.parameters(call) if with_params else []
        self.param_summary = ', '.join(map(str, self.params)) if with_params else call.search.decode('utf-8', 'replace')


class TTDBehaviorReport(Report):
    def query(self, expression='', *, with_params=True):
        for index in super().query(expression):
            yield TTDApiCall(self, self.call(index), with_params)


def extract(trace, output=None, *, max_buffer=65536):
    """Extract a report on Windows and return it. The extractor must be built or configured."""
    import subprocess
    args = command(trace, output, max_buffer)
    subprocess.run(args, check=True)
    from pathlib import Path
    return TTDBehaviorReport(output or Path(trace).with_suffix('.ttdb'))


extractor_path = find_extractor
ttd_replay_directory = find_replay_dlls
