#!/usr/bin/python
"""
AndroHook injector module.
Allows injection of javascript code into Frida via an easy API.
"""
import threading
import traceback
import argparse
import tempfile
import logging
import shutil
import pprint
import json
import os

import frida

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

PACKAGE_FILENAME = "package.json"
NODE_MODULE_DIRNAME = "node_module_template"
FRIDA_COMPILE_COMMAND_LINE = "nodejs ./node_modules/frida-compile/bin/compile.js {0} -o {1}"

def copytree(src, dst, symlinks=False, ignore=None):
    """
    Wraps shutil.copytree() and allows to copy a single file
    """
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            shutil.copytree(s, d, symlinks, ignore)
        else:
            shutil.copy2(s, d)

def frida_compile(directory, output_script):
    """
    Uses frida-compile utility, written in nodejs, in order to compile the given
    directory as a nodejs module into a single script which can be injected.
    """
    cwd = os.getcwd()
    os.chdir(os.path.dirname(__file__))
    os.system(FRIDA_COMPILE_COMMAND_LINE.format(directory, output_script))
    os.chdir(cwd)

def inject(session, script_path, message_handler=None):
    """
    Inject a script into an attached process.

    If given register a message handler to handle message from the injected code.
    :param session: An attached process session
    :param script_path: The JS to inject. Will be wrapped with an exported init RPC.
    :param message_handler: An optional message handler to handle script's sent messages.
    """
    # Preparing node_module directory

    # Copying template module with all system libraries
    user_node_module = tempfile.mkdtemp()
    # script_path = os.path.abspath(script_path)

    try:
        copytree(os.path.join(os.path.dirname(__file__), NODE_MODULE_DIRNAME), user_node_module)

        if os.path.isfile(script_path):
            # Injecting a single file

            # Copying user's own script
            basename = os.path.basename(script_path)
            shutil.copyfile(script_path, os.path.join(user_node_module, basename))

            # Generating a package.json
            json.dump({"main": basename}, open(os.path.join(user_node_module, PACKAGE_FILENAME), "wb"))

            script_path = basename
        else:
            # Injecting a node module
            copytree(script_path, user_node_module)
            script_path = "."

        # Compiling created module into a single file
        temp_filename = tempfile.mkstemp()[1]
        script_path = os.path.join(user_node_module, script_path)
        frida_compile(script_path, temp_filename)

        # Injecting
        script = session.create_script(source=open(temp_filename, "rb").read())

    except:
        traceback.print_exc()

    # Delete temporary created node module
    shutil.rmtree(user_node_module)

    if message_handler:
        script.on('message', message_handler)

    script.load()


class BaseAppHandler(object):
    """
    Generic handler for an application RPC
    """
    @staticmethod
    def on_message(message, data):
        """
        Called upon every received RPC message
        """
        if message['type'] == 'error':
            print message['stack']
        else:
            pprint.pprint(message)

    @staticmethod
    def enable_jit():
        """
        Should JIT be enabled upon session creation
        """
        return True

    @staticmethod
    def get_script():
        """
        Returns script filename
        """
        raise Exception("Unimplemented")


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
            LOG.debug("Injecting to not spawned process")
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
        LOG.debug("stopping")
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
            if handler.enable_jit():
                session.enable_jit()
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
                LOG.info("Instrumenting {name}({pid})".format(name=target, pid=pid))
                self._try_inject(target, self.handlers[target])
            else:
                LOG.debug("Not instrumenting {name}({pid})".format(name=target, pid=pid))
            self.device.resume(pid)

    def _on_spawned(self, spawn):
        LOG.debug("On spawn: %s" % spawn)
        self._pending.append(spawn)
        self._event.set()


def main():
    """
    Main program. 
    Simple and generic injecter that parses supplied args and injects
    accordingly.
    """
    parser = argparse.ArgumentParser(description='AndroHook Simple Injector.')

    parser.add_argument('--script', '-s', dest='script', help='Script to inject', required=True)
    parser.add_argument('--package', '-p', dest='package', help='Package name of the process to be injected to',
                        required=True)
    parser.add_argument('--inject-only-new', dest='inject_only_new', action='store_true', 
                        default=False,
                        help='Package name of the process to be injected to')
    parser.add_argument('--disable-jit', dest='disable_jit', action='store_true',
                        default=False,
                        help='Package name of the process to be injected to')

    args = parser.parse_args()

    if not os.path.exists(args.script):
        print "Given script path doesn't exist"
        return False

    class AppHandler(BaseAppHandler):
        """
        Generic handler with user's settings
        """
        @staticmethod
        def get_script():
            js_filepath = args.script
            print "Injecting", js_filepath, "..."
            return js_filepath

        @staticmethod
        def enable_jit():
            return not(args.disable_jit)

    injector = Injector(handlers={args.package: AppHandler})
    try:
        injector.start(args.inject_only_new)
    except KeyboardInterrupt as e:
        injector.stop()

    return True


if __name__ == "__main__":
    print "Starting injector..."
    main()
