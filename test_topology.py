from mininet.net import Containernet
from mininet.cli import CLI
from mininet.link import TCLink, OVSLink
from mininet.log import info, setLogLevel
from mininet.node import OVSSwitch, RemoteController, OVSKernelSwitch
from subprocess import call
from functools import partial
from networkx import nx, minimum_spanning_tree
from ryu.topology import switches
import time
import requests
import json
import os
import logging


logger = logging.getLogger(__name__)
logger.setLevel(level=logging.INFO)

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6653
OPENFLOW_PROTOCOL = 'OpenFlow14'
IP_BASE = "10.0.88.0/24"
# DPID_BASE = 0x1000
DPID_BASE = 1000
setLogLevel('info')

class OVSBridgeSTP( OVSKernelSwitch ):
    """Open vSwitch Ethernet bridge with Spanning Tree Protocol
       rooted at the first bridge that is created"""
    def __init__(self, name, failMode='secure', datapath='kernel',
                 inband=False, protocols=OPENFLOW_PROTOCOL,
                 reconnectms=1000, stp=False, batch=False, stp_priority=10,  **params):
        super(OVSBridgeSTP, self).__init__(name, failMode, datapath,
                 inband, protocols, reconnectms, stp, batch, **params)
        self.stp_priority = stp_priority

    def start( self, *args, **kwargs ):
        super(OVSBridgeSTP, self).start(*args, **kwargs)
        self.cmd( 'ovs-vsctl set-fail-mode', self, 'standalone' )
        self.cmd( 'ovs-vsctl set-controller', self )
        self.cmd( 'ovs-vsctl set Bridge', self,
                  'stp_enable=true',
                  'other_config:stp-priority=%d' % self.stp_priority )

if __name__ == '__main__':

    # ---------- clean previous setup  -----------------------------
    call(["mn", "-c"])

    # ----------topology inputs -----------------------------
    switch_names = {1: "lon", 2: "ams", 3: "bru", 4: "par", 5: "ham",
                    6: "fra", 7: "str", 8: "zur", 9: "lyn", 10: "ber",
                    11: "mun", 12: "mil", 13: "pra", 14: "vie", 15: "zag",
                    16: "rom"}
    switch_link_matrix = [(1, 2), (1, 4), (2, 3), (2, 5), (3, 4),
                          (3, 6), (4, 7), (4, 9), (5, 6), (5, 10),
                          (6, 7), (6, 11), (7, 8), (8, 9), (8, 12),
                          (10, 11), (10, 13), (11, 12), (11, 14), (12, 16),
                          (13, 14), (14, 15), (15, 16)]
    host_count_per_switch = 1

    topology = nx.Graph()
    nodes = list(switch_names.keys())
    topology.add_nodes_from(nodes)
    topology.add_edges_from(switch_link_matrix)
    result = minimum_spanning_tree(topology)

    no_flood_links = list(set(switch_link_matrix) - set(result.edges))

    # ---------- initialize network  -----------------------------
    #dpid = DPID_BASE
    OpenFlow14Switch = partial(OVSKernelSwitch, protocols=OPENFLOW_PROTOCOL)
    #STPEnabledSwitch = partial(OVSKernelSwitch, protocols=OPENFLOW_PROTOCOL, failMode="standalone", stp=True)

    net = Containernet(ipBase=IP_BASE)
    net.addController("c0", controller=RemoteController, link=OVSLink, ip=CONTROLLER_IP, port=CONTROLLER_PORT)

    try:
        # ----------switches and hosts -----------------------------
        switches = {}
        links = {}
        for sw_ind in switch_names:
            name = switch_names[sw_ind]
            dpid = DPID_BASE + sw_ind

            params = {'other_config':{'stp-priority' : sw_ind}}
            sw = net.addSwitch(name, dpid="%x" % dpid, cls=OpenFlow14Switch)
            switches[sw_ind] = sw
            for host_index in range(1, host_count_per_switch + 1):
                host = net.addHost(name + '%02d' % host_index)
                net.addLink(sw, host)

        # ---------- create links -----------------------------
        for item in switch_link_matrix:
            sw1 = switches[item[0]]
            sw2 = switches[item[1]]
            link = net.addLink(sw1, sw2)
            links[item] = link
            if item in no_flood_links:
                sw1_port = sw1.ports[link.intf1]
                sw1.dpctl("mod-port", sw1_port , "no-flood")
                sw2_port = sw2.ports[link.intf2]
                sw2.dpctl("mod-port", sw2_port , "no-flood")


        # ----------switches-----------------------------
        info('*** Starting network\n')
        net.start()
        time.sleep(2)
        # ---------- clear flood loops  -----------------------------
        for item in switch_link_matrix:
            sw1 = switches[item[0]]
            sw2 = switches[item[1]]
            link = links[item]
            # if item in no_flood_links:
            #     sw1_port = sw1.ports[link.intf1]
            #     #sw1.dpctl("mod-port", sw1_port , "no-forward")
            #     command = ["ovs-ofctl", "mod-port", sw1.name, str(sw1_port), "no-flood", "-O", "OpenFlow14"]
            #     logger.info(command)
            #     call(command)
            #     sw2_port = sw2.ports[link.intf2]
            #     #sw2.dpctl("mod-port", sw2_port , "no-forward")
            #     command = ["ovs-ofctl", "mod-port", sw2.name, str(sw2_port), "no-flood", "-O", "OpenFlow14"]
            #     logger.info(command)
            #     call(command)
        info('*** Running CLI\n')
        CLI(net)

        info('*** Stopping network')
        net.stop()
    except Exception as err:
        info(err)

        net.stop()
