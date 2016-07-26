#!/usr/bin/env python

import sys
import zipfile

from datetime import datetime
from lxml import etree
from mitmproxy.flow import FlowReader
from netlib.http.http1 import assemble_request, assemble_response

_CONTENT_TYPES_CONTENT = """<?xml version="1.0" encoding="utf-8" ?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="htm" ContentType="text/html" />
<Default Extension="xml" ContentType="application/xml" />
<Default Extension="txt" ContentType="text/plain" />
</Types>"""


class SazWriter(object):
    def __init__(self, filename, process=None):
        self._filename = filename
        self._count = 1
        self._file = None
        self._process = None
        self._file = zipfile.ZipFile(self._filename, 'w', zipfile.ZIP_DEFLATED)
        self._write_content_types_file()

    def close(self):
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _write_content_types_file(self):
        self._file.writestr('[Content_Types].xml', _CONTENT_TYPES_CONTENT)

    def write(self, flow):
        request = assemble_request(flow.request)
        response = assemble_response(flow.response)
        self._file.writestr("raw/{session}_c.txt".format(session=self._count), request)
        self._file.writestr("raw/{session}_s.txt".format(session=self._count), response)
        metadata = self._create_metadata(flow)
        if metadata:
            self._file.writestr("raw/{session}_m.xml".format(session=self._count), metadata)
        self._count += 1

    def _create_metadata(self, flow):
        session = etree.Element("Session", dict(SID=str(self._count), BitFlags="0"))
        session_timers = dict(ClientConnected=_format_timestamp(flow.request.timestamp_start),
                              ClientBeginRequest=_format_timestamp(flow.request.timestamp_start),
                              GotRequestHeaders=_format_timestamp(flow.request.timestamp_start),
                              ClientDoneRequest=_format_timestamp(flow.request.timestamp_end),
                              TCPConnectTime="0", GatewayTime="0", DNSTime="0", HTTPSHandshakeTime="0",
                              ServerConnected=_format_timestamp(flow.request.timestamp_start),
                              FiddlerBeginRequest=_format_timestamp(flow.request.timestamp_start),
                              ServerGotRequest=_format_timestamp(flow.request.timestamp_end),
                              ServerBeginResponse=_format_timestamp(flow.response.timestamp_start),
                              GotResponseHeaders=_format_timestamp(flow.response.timestamp_start),
                              ServerDoneResponse=_format_timestamp(flow.response.timestamp_end),
                              ClientBeginResponse=_format_timestamp(flow.response.timestamp_start),
                              ClientDoneResponse=_format_timestamp(flow.response.timestamp_end))
        etree.SubElement(session, "SessionTimers", session_timers)
        etree.SubElement(session, "PipeInfo")
        session_flags = etree.SubElement(session, "SessionFlags")
        etree.SubElement(session_flags, "SessionFlag", dict(N="x-clientip", V=flow.client_conn.address.address[0]))
        etree.SubElement(session_flags, "SessionFlag",
                         dict(N="x-clientport", V=str(flow.client_conn.address.address[1])))
        etree.SubElement(session_flags, "SessionFlag", dict(N="x-hostip", V=flow.server_conn.address.address[0]))
        if self._process:
            etree.SubElement(session_flags, "SessionFlag", dict(N="x-processinfo", V=self._process))
        return etree.tostring(session, pretty_print=True, encoding='UTF-8', xml_declaration=True)


def _format_timestamp(timestamp):
    return datetime.utcfromtimestamp(timestamp).isoformat() + '+00:00'


def saz_write(input_filename, output_filename):
    with open(input_filename) as input_file, SazWriter(output_filename) as output_file:
        flow_reader = FlowReader(input_file)
        for fl in flow_reader.stream():
            if fl.response:
                output_file.write(fl)


def main():
    if len(sys.argv) < 3:
        print "usage: %s input_dump_file output_saz_file" % sys.argv[0]
        sys.exit(0)
    saz_write(sys.argv[1], sys.argv[2])


if __name__ == '__main__':
    main()
