import threading
import frida
import logging
from string import Template

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
_RPC_INIT_TEMPLATE = Template("""\
                (function () {
                "use strict";
                rpc.exports = {
                    init() {
                        $script
                    }
                };
                }).call(this);""")


def inject(session, script_to_inject, message_handler=None):
    """
    Inject a script into an attached process.

    If given register a message handler to handle message from the injected code.
    :param session: An attached process session
    :param script_to_inject: The JS to inject. Will be wrapped with an exported init RPC.
    :param message_handler: An optional message handler to handle script's sent messages.
    """
    full_script = _RPC_INIT_TEMPLATE.safe_substitute(script=script_to_inject)
    script = session.create_script(full_script)
    if message_handler:
        script.on('message', message_handler)
    script.load()
    script.exports.init()


class Injector(object):
    """
    A generic injector of frida scripts.

    It allows injecting into running and newly spawned processes (usually applications).
    """
    def __init__(self, handlers, device=None):
        """
        Initialize the Injector with a mapping apps to handlers.

        :param handlers: A mapping between a process we want to hook and a handler.
        Each handler provides the script we want to inject and an optional on_message function.
        :type handlers: dict
        :param device: An attached device or None if you want to attach to the USB device.
        :type device: frida.core.Device
        """
        self.device = device or frida.get_usb_device()
        self.handlers = handlers
        self._pending = []
        self.active_sessions = []
        self._do_spawn_gating = False
        self._event = threading.Event()

    def start(self, only_new=True):
        """
        Start hooking processes.
        :param only_new: If True only newly spawned processes will be hooked, any running process will be ignored
        """
        self.device.on('spawned', self._on_spawned)
        if not only_new:
            log.debug("Injecting to not spawned process")
            for target, handler in self.handlers.items():
                self._try_inject(target, handler)

        self.device.enable_spawn_gating()
        self._do_spawn_gating = True
        for spawned in self.device.enumerate_pending_spawns():
            self._handle_spawned(spawned)
        while self._do_spawn_gating:
            while len(self._pending) == 0:
                logging.debug('Waiting for spawn event')
                self._event.wait(0.5)
                self._event.clear()
            spawn = self._pending.pop()
            self._handle_spawned(spawn)

    def stop(self):
        log.debug("stopping")
        self._do_spawn_gating = False
        for session, handler in self.active_sessions:
            session.detach()
            if hasattr(handler, "finish"):
                handler.finish()
        self.active_sessions = []

    def _try_inject(self, target, handler):
        try:
            process = self.device.get_process(target)
            session = self.device.attach(target)
            if hasattr(handler, 'process'):
                handler.process = process
            message_handler = handler.on_message if hasattr(handler, 'on_message') else None
            inject(session, handler.get_script(), message_handler)
            self.active_sessions.append((session, handler))
        except frida.ProcessNotFoundError:
            pass

    def _handle_spawned(self, spawned):
        if spawned is not None:
            target = spawned.identifier
            pid = spawned.pid
            if target in self.handlers:
                log.info("Instrumenting {name}({pid})".format(name=target, pid=pid))
                self._try_inject(target, self.handlers[target])
            else:
                log.info("Not instrumenting {name}({pid})".format(name=target, pid=pid))
            self.device.resume(pid)

    def _on_spawned(self, spawn):
        log.debug("On spawn: %s" % spawn)
        self._pending.append(spawn)
        self._event.set()
