from __future__ import absolute_import
import logging
import os
import time

from androhook.network.http import TransactionError, HttpTransaction

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class SslSession(object):
    """
    Handles the state of a single SSL session.

    It assumes the each transaction is an HTTP transaction
    """
    def __init__(self, ssl_pointer, flow_handler=None):
        """
        Initialize a new SSL session.

        :param ssl_pointer: The SSL native pointer used by the openssl library. Used as a session indentifier.
        :param flow_handler: A callable object to call on each finished flow
        """
        self._ssl_pointer = ssl_pointer
        self._transaction = None
        self._flow_handler = flow_handler
        self.local_address = ("", 0)
        self.remote_address = ("", 443)
        self._timestamp_ssl_setup = time.time()  # default time

    def on_write(self, data):
        if not data:
            return
        try:
            if self._transaction:
                if self._transaction.request_done:
                    self._transaction.finish()
                if self._transaction.finished:
                    self._handle_finish_transaction()
            if not self._transaction:
                self._transaction = HttpTransaction(self.local_address, self.remote_address, self._timestamp_ssl_setup)
            self._transaction.add_write_data(data)
        except TransactionError as e:
            log.error("Transaction error: {msg} in session: {session}".format(msg=e.message, session=self._ssl_pointer))

    def on_read(self, data):
        if not data:
            return
        self._transaction.add_read_data(data)

    def on_finish(self):
        self._handle_finish_transaction()

    def _handle_finish_transaction(self):
        if self._transaction:
            if not self._transaction.finished:
                self._transaction.finish()
            flow = self._transaction.flow
            if self._flow_handler:
                self._flow_handler(flow)
            self._transaction = None

    def on_handshake_finish(self):
        self._timestamp_ssl_setup = time.time()


class SslSocketHandler(object):
    """
    Handles all the SSL_* calls from a single process.
    """
    def __init__(self, flow_handler):
        self.process = None
        self.flow_handler = flow_handler
        self.sessions = {}
        self._function_handlers = {
            # function_name: (function_handler, function_args, pass_data)
            'SSL_new': (self.on_new, ('ssl_ctx_pointer', 'ssl_pointer'), False),
            'SSL_set_fd': (self.on_set_fd, ('ssl_pointer', 'fd', 'local_address', 'peer_address'), False),
            'SSL_do_handshake': (self.on_do_handshake, ('ssl_pointer', 'retval'), False),
            'SSL_shutdown': (self.on_shutdown, ('ssl_pointer', 'retval'), False),
            'SSL_renegotiate': (self.on_renegotiate, ('ssl_pointer', 'retval'), False),
            'SSL_free': (self.on_free, ('ssl_pointer',), False),
            'SSL_write': (self.on_write, ('ssl_pointer',), True),
            'SSL_read': (self.on_read, ('ssl_pointer',), True),
        }

    def on_message(self, message, data):
        if message['type'] == 'error':
            log.error("[!] " + message['stack'])
        elif message['type'] == 'send':
            msg = message['payload']
            if not isinstance(msg, dict):
                log.debug(msg)
            else:  # elif isinstance(msg, dict):
                if msg["type"] == "function_call":
                    function_name = msg["name"]
                    function_handler, arg_names, pass_data = self._function_handlers[function_name]
                    args = [msg.get(arg_name, None) for arg_name in arg_names]
                    if pass_data:
                        args.append(data)
                    function_handler(*args)
                else:
                    log.debug(msg)
        else:
            log.debug(message)

    def on_new(self, ssl_ctx_pointer, ssl_pointer):
        if ssl_pointer not in self.sessions:
            log.debug("New session: {session}".format(session=ssl_pointer))
            self.sessions[ssl_pointer] = SslSession(ssl_pointer, self.flow_handler)
        else:
            log.debug("Repeating SSL session: {session}".format(session=ssl_pointer))

    def on_free(self, ssl_pointer):
        session = self.sessions.pop(ssl_pointer, None)
        if session:
            log.debug("Free session: {session}".format(session=ssl_pointer))
            session.on_finish()
        else:
            log.debug("Free non existing session: {session}".format(session=ssl_pointer))

    def on_shutdown(self, ssl_pointer, retval):
        session = self.sessions.pop(ssl_pointer, None)
        if session:
            log.debug("Shutdown session: {session}".format(session=ssl_pointer))
            session.on_finish()
        else:
            log.debug("shutdown non existing session: {session}".format(session=ssl_pointer))

    def on_renegotiate(self, ssl_pointer, retval):
        log.debug("Renegotiate session: {session}, {retval}".format(session=ssl_pointer, retval=retval))

    def on_set_fd(self, ssl_pointer, fd, local_address, peer_address):
        try:
            self.sessions[ssl_pointer].local_address = (
                str(local_address['ip'].rsplit(":", 1)[1]), local_address['port'])
            self.sessions[ssl_pointer].remote_address = (
                str(peer_address['ip'].rsplit(":", 1)[1]), peer_address['port'])
        except KeyError:
            log.debug("set_fd in non existing session: {session}".format(session=ssl_pointer))

    def on_do_handshake(self, ssl_pointer, retval):
        try:
            if int(retval, 16) == 1:
                self.sessions[ssl_pointer].on_handshake_finish()
        except KeyError:
            log.debug(
                    "do_handshake in non existing session: {session}, {retval}".format(session=ssl_pointer, retval=retval))

    def on_read(self, ssl_pointer, data):
        try:
            self.sessions[ssl_pointer].on_read(data)
            log.debug("Read session: {session}".format(session=ssl_pointer))
        except KeyError:
            log.debug("read in non existing session: {session}".format(session=ssl_pointer))

    def on_write(self, ssl_pointer, data):
        try:
            self.sessions[ssl_pointer].on_write(data)
            log.debug("Write session: {session}".format(session=ssl_pointer))
        except KeyError:
            log.debug("write in non existing session: {session}".format(session=ssl_pointer))

    @staticmethod
    def get_script():
        js_filepath = os.path.join(os.path.dirname(__file__), 'injected_js', 'ssl_hooks.js')
        with open(js_filepath) as js_file:
            return js_file.read()

    def finish(self):
        for session in self.sessions.itervalues():
            session.on_finish()
        self.sessions = {}
