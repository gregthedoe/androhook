from saz import SazWriter
from har import har_write
from raw_flow import FlowWriter

__all__ = ['CombinedFlowWriter', 'FlowWriter', 'SazWriter', 'har_write']


class CombinedFlowWriter(object):
    def __init__(self, flow_filename, saz_filename, output_to_stdout):
        self._flow_writer = FlowWriter(flow_filename) if flow_filename else None
        self._saz_writer = SazWriter(saz_filename) if saz_filename else None
        self._output_to_stdout = output_to_stdout

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        if self._flow_writer:
            self._flow_writer.close()
        if self._saz_writer:
            self._saz_writer.close()

    def write(self, flow):
        if self._flow_writer:
            self._flow_writer.write(flow)
        if self._saz_writer:
            self._saz_writer.write(flow)
        if self._output_to_stdout:
            print(flow)

    def __call__(self, flow):
        self.write(flow)
