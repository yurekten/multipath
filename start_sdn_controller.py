#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, os

from ryu.cmd import manager


def main():

    sys.argv.append('--ofp-tcp-listen-port')
    sys.argv.append('6653')
    #sys.argv.append('--verbose')
    sys.argv.append('--enable-debugger')
    sys.argv.append('--observe-links')
    #sys.argv.append('ryu.app.ofctl_rest')
    sys.argv.append('ryu_multipath')

    #sys.argv.append('da.arp_handler')
    #sys.argv.append('da.simple_switch_snort')
    #sys.argv.append('flowmanager.flowmanager')
    #sys.argv.append('ryu.app.gui_topology.gui_topology')

    manager.main()


if __name__ == '__main__':
    main()