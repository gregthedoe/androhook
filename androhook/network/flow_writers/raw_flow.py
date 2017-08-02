from mitmproxy.contrib import tnetstring


class FlowWriter(object):
    def __init__(self, filename):
        self._filename = filename
        self._file = open(filename, 'w')

    def close(self):
        self._file.close()

    def write(self, flow):
        d = flow.get_state()
        tnetstring.dump(d, self._file)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

