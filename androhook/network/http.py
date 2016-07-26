import logging
import time
from io import BytesIO

from mitmproxy import models
from netlib.exceptions import HttpException
from netlib.http import http1

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def read_http_body(io, expected_size):
    """
    Read a (possibly malformed) HTTP body.

    :rtype: (body: bytes, is_malformed: bool)
    """
    body_start = io.tell()
    try:
        content = b"".join(http1.read_body(io, expected_size, None))
        if io.read():  # leftover?
            raise HttpException()
        return content, False
    except HttpException:
        io.seek(body_start)
        return io.read(), True


def parse_http_request(ts, sent):
    try:
        sent = BytesIO(sent)
        request = http1.read_request_head(sent)
        body_size = http1.expected_http_body_size(request)
        request.data.content, malformed = read_http_body(sent, body_size)
        if malformed:
            request.headers["X-Mitmproxy-Malformed-Body"] = "1"
        return request
    except HttpException as e:
        log.warning("{!r} (timestamp: {})".format(e, ts))


def parse_http_response(ts, recv, request):
    try:
        recv = BytesIO(recv)
        response = http1.read_response_head(recv)
        body_size = http1.expected_http_body_size(request, response)
        response.data.content, malformed = read_http_body(recv, body_size)
        if malformed:
            response.headers["X-Mitmproxy-Malformed-Body"] = "1"
        return response
    except HttpException as e:
        log.warning("{!r} (timestamp: {})".format(e, ts))


class TransactionError(Exception):
    pass


class HttpTransaction(object):
    """
    An HTTP transaction.

    Each transaction is composed out of several consecutive write operations (send the request)
    followed by several consecutive read operations (read the response).
    """
    def __init__(self, src_address, dst_address, timestamp_ssl_setup):
        self._sent_chunks = []
        self._response_chunks = []
        self.request_done = False
        self.response_done = False
        self._finished = False
        self._request = None
        self._response = None
        self._request_timestamp_start = None
        self._request_timestamp_end = None
        self._response_timestamp_start = None
        self._response_timestamp_end = None
        self._timestamp_ssl_setup = timestamp_ssl_setup
        self._src_address = src_address
        self._dst_address = dst_address

    def add_write_data(self, data):
        if self.request_done:
            raise TransactionError("Should not handle writes after request is done")
        self._sent_chunks.append(data)
        if self._request_timestamp_start is None:
            self._request_timestamp_start = time.time()
        self._request_timestamp_end = time.time()

    def add_read_data(self, data):
        if not self.request_done:
            self.request_done = True
        self._response_chunks.append(data)
        if self._response_timestamp_start is None:
            self._response_timestamp_start = time.time()
        self._response_timestamp_end = time.time()

    @property
    def request(self):
        if self._request is None:
            self._make_request()
        return self._request

    def _make_request(self):
        if self._request is None:
            sent = ''.join(self._sent_chunks)
            request = parse_http_request(self._request_timestamp_start, sent)
            self._request = models.HTTPRequest.wrap(request)
            self._request.timestamp_start = self._request_timestamp_start
            self._request.timestamp_end = self._request_timestamp_end
            self._request.host = request.host or request.headers.get('Host', None) or self._dst_address[0]
            self._request.port = request.port or self._dst_address[1]
            self._request.scheme = request.scheme or "https"

    @property
    def response(self):
        if self._response is None:
            self._make_response()
        return self._response

    def _make_response(self):
        recv = ''.join(self._response_chunks)
        response = parse_http_response(self._response_timestamp_end, recv, self.request)
        if response:
            self._response = models.HTTPResponse.wrap(response)
            self._response.timestamp_start = self._response_timestamp_start
            self._response.timestamp_end = self._response_timestamp_end

    def finish(self):
        """
        Finish a transaction.
        """
        if not self.request_done:
            self.request_done = True
        if not self.response_done:
            self.response_done = True
        self._finished = True

    @property
    def finished(self):
        return self._finished

    @property
    def flow(self):
        if any(_ is None for _ in (self._request_timestamp_start, self._request_timestamp_end,
                                   self._response_timestamp_start, self._response_timestamp_end,
                                   self._timestamp_ssl_setup)):
            s = " ".join("%s=%s" % item for item in dict(request_start=self._request_timestamp_start,
                                                         request_end=self._request_timestamp_end,
                                                         response_start=self._response_timestamp_start,
                                                         response_end=self._response_timestamp_end,
                                                         ssl_setup=self._timestamp_ssl_setup).iteritems())
            log.error(s)
        client_conn = models.ClientConnection.from_state(dict(address=dict(address=self._src_address, use_ipv6=False),
                                                              clientcert=None,
                                                              ssl_established=True,
                                                              timestamp_start=self._request_timestamp_start,
                                                              timestamp_end=self._request_timestamp_end,
                                                              timestamp_ssl_setup=self._timestamp_ssl_setup
                                                              ))

        server_conn = models.ServerConnection.from_state(dict(address=dict(address=self._dst_address, use_ipv6=False),
                                                              cert=None,
                                                              sni=None,
                                                              source_address=dict(address=self._src_address,
                                                                                  use_ipv6=False),
                                                              peer_address=dict(address=self._src_address,
                                                                                use_ipv6=False),
                                                              ssl_established=True,
                                                              timestamp_start=self._response_timestamp_start,
                                                              timestamp_tcp_setup=self._timestamp_ssl_setup,
                                                              timestamp_ssl_setup=self._timestamp_ssl_setup,
                                                              timestamp_end=self._response_timestamp_end,
                                                              via=None))

        flow = models.HTTPFlow(client_conn, server_conn)
        flow.request = self.request
        flow.response = self.response
        return flow
