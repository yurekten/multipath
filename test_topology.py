from mininet.net import Containernet
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.node import OVSSwitch, RemoteController, OVSKernelSwitch
from subprocess import call
from functools import partial
from networkx import nx
from ryu.topology import switches
import time
import requests
import json
import os

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6653
OPENFLOW_PROTOCOL = 'OpenFlow14'
IP_BASE = "10.0.88.0/24"
#DPID_BASE = 0x1000
DPID_BASE = 1000
setLogLevel('info')

if __name__ == '__main__':
    try:
        nw_graph = nx.MultiDiGraph()
        service_functions = {}
        call(["mn", "-c"])
        dpid = DPID_BASE
        myController = RemoteController('c0', port=CONTROLLER_PORT)

        mySwitch = partial(OVSKernelSwitch, protocols=OPENFLOW_PROTOCOL)

        net = Containernet(ipBase=IP_BASE)
        net.addController("c0", controller=RemoteController, link=TCLink, ip=CONTROLLER_IP, port=CONTROLLER_PORT)

        # ----------switches-----------------------------

        dpid = dpid + 1
        s1 = net.addSwitch('s1', dpid="%x" % (dpid))

        dpid = dpid + 1
        s2 = net.addSwitch('s2', dpid="%x" % (dpid))

        new_link = net.addLink(s1, s2)

        dpid = dpid + 1
        s3 = net.addSwitch('s3', dpid="%x" % (dpid))
        new_link = net.addLink(s1, s3)

        dpid = dpid + 1
        s4 = net.addSwitch('s4', dpid="%x" % (dpid))
        new_link = net.addLink(s3, s4)

        dpid = dpid + 1
        s5 = net.addSwitch('s5', dpid="%x" % (dpid))
        new_link = net.addLink(s4, s5)

        new_link = net.addLink(s2, s5)

        h1 = net.addHost('h1')
        new_link = net.addLink(s1, h1)

        h2 = net.addHost('h2')
        new_link = net.addLink(s5, h2)

        info('*** Starting network\n')
        net.start()
        time.sleep(1)

        info('*** Running CLI\n')
        CLI(net)

        info('*** Stopping network')
        net.stop()
    except Exception as err:
        info(err)
        net.stop()
