#!/usr/bin/env python

import argparse
from androhook.injector import Injector
from androhook.network.ssl import SslSocketHandler
from androhook.network.flow_writers import CombinedFlowWriter


def intercept(package, flow_filename, saz_filename, quiet=False, inject_only_new=True):
    flow_writer = CombinedFlowWriter(flow_filename, saz_filename, not quiet)
    ssl_handler = SslSocketHandler(flow_writer)
    injector = Injector(handlers={package: ssl_handler})
    try:
        injector.start(inject_only_new)
    except KeyboardInterrupt as e:
        injector.stop()
        flow_writer.close()


def main():
    description = "Intercept HTTPS traffic of a package and save to mitmproxy flow file"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("package_name", help="Package's name we want to intercept")
    parser.add_argument("--flow", help="Mitmproxy's flow dump file name")
    parser.add_argument("--saz", help="Fiddler's SAZ file name")
    parser.add_argument("-q", "--quiet", action="store_true", default=False, help="Don't output flows to stdout")
    parser.add_argument("--inject-only-new", action="store_true", default=False,
                        help="Inject only to new packages")
    options = parser.parse_args()
    intercept(options.package_name, options.flow, options.saz, options.quiet, options.inject_only_new)

if __name__ == "__main__":
    main()
