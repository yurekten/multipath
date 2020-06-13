#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, os

from ryu.cmd import manager
from ryu.base.app_manager import AppManager


def main():
    sys.argv.append('--ofp-tcp-listen-port')
    sys.argv.append('6653')
    sys.argv.append('--enable-debugger')

    sys.argv.append('--observe-links')
    sys.argv.append('multipath')

    # sys.argv.append('ryu.app.rest_topology')
    # sys.argv.append('ryu.app.ws_topology')
    # sys.argv.append('ryu.app.ofctl_rest')
    # sys.argv.append('ryu.app.gui_topology.gui_topology')

    manager.main()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt as err:
        print("closing kindly")
    finally:
        app_mgr = AppManager.get_instance()
        app_mgr.close()
