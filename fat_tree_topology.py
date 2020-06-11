from mininet.net import Containernet
from mininet.topo import Topo
from mininet.node import OVSSwitch
import logging
import os

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class FatTree(Topo):
    CoreSwitchList = []
    AggSwitchList = []
    EdgeSwitchList = []
    HostList = []

    def __init__(self, k):
        " Create Fat Tree topo."
        self.pod = k
        self.iCoreLayerSwitch = int((k / 2) ** 2)
        self.iAggLayerSwitch = int(k * k / 2)
        self.iEdgeLayerSwitch = int(k * k / 2)
        info('*** Adding switches\n')

        self.density = int(k / 2)
        self.iHost = self.iEdgeLayerSwitch * self.density

        self.bw_c2a = 20000
        self.bw_a2e = 9000
        self.bw_h2a = 80

        # Init Topo
        Topo.__init__(self)

        self.createTopo()
        logger.debug("Finished topology creation!")

        self.createLink(bw_c2a=self.bw_c2a,
                        bw_a2e=self.bw_a2e,
                        bw_h2a=self.bw_h2a)
        logger.debug("Finished adding links!")

    #    self.set_ovs_protocol_13()
    #    logger.debug("OF is set to version 1.3!")  

    def createTopo(self):
        self.createCoreLayerSwitch(self.iCoreLayerSwitch)
        self.createAggLayerSwitch(self.iAggLayerSwitch)
        self.createEdgeLayerSwitch(self.iEdgeLayerSwitch)
        self.createHost(self.iHost)

    """
    Create Switch and Host
    """

    def _addSwitch(self, number, level, switch_list):
        for x in range(1, number + 1):
            PREFIX = str(level) + "00"
            if x >= int(10):
                PREFIX = str(level) + "0"
            switch_list.append(self.addSwitch('s' + PREFIX + str(x), failMode= "standalone", stp=True))

    def createCoreLayerSwitch(self, NUMBER):
        logger.debug("Create Core Layer")
        self._addSwitch(NUMBER, 1, self.CoreSwitchList)

    def createAggLayerSwitch(self, NUMBER):
        logger.debug("Create Agg Layer")
        self._addSwitch(NUMBER, 2, self.AggSwitchList)

    def createEdgeLayerSwitch(self, NUMBER):
        logger.debug("Create Edge Layer")
        self._addSwitch(NUMBER, 3, self.EdgeSwitchList)

    def createHost(self, NUMBER):
        logger.debug("Create Host")
        for x in range(1, NUMBER + 1):
            PREFIX = "h00"
            if x >= int(10):
                PREFIX = "h0"
            elif x >= int(100):
                PREFIX = "h"
            self.HostList.append(self.addHost(PREFIX + str(x)))

    """
    Add Link
    """

    def createLink(self, bw_c2a=10000, bw_a2e=1000, bw_h2a=100):
        logger.debug("Add link Core to Agg.")
        end = int(self.pod / 2)
        for x in range(0, self.iAggLayerSwitch, end):
            for i in range(0, end):
                for j in range(0, end):
                    linkopts = dict(bw=bw_c2a)
                    self.addLink(
                        self.CoreSwitchList[i * end + j],
                        self.AggSwitchList[x + i],
                        **linkopts)

        logger.debug("Add link Agg to Edge.")
        for x in range(0, self.iAggLayerSwitch, end):
            for i in range(0, end):
                for j in range(0, end):
                    linkopts = dict(bw=bw_a2e)
                    self.addLink(
                        self.AggSwitchList[x + i], self.EdgeSwitchList[x + j],
                        **linkopts)

        logger.debug("Add link Edge to Host.")
        for x in range(0, self.iEdgeLayerSwitch):
            for i in range(0, self.density):
                linkopts = dict(bw=bw_h2a)
                self.addLink(
                    self.EdgeSwitchList[x],
                    self.HostList[int(self.density * x + i)],
                    **linkopts)


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

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6653
OPENFLOW_PROTOCOL = 'OpenFlow15'
IP_BASE = "10.0.88.0/24"
# DPID_BASE = 0x1000
DPID_BASE = 1000

if __name__ == '__main__':
    try:
        call(["mn", "-c"])
        dpid = DPID_BASE
        myController = RemoteController('c0', port=CONTROLLER_PORT)

        mySwitch = partial(OVSKernelSwitch, protocols=OPENFLOW_PROTOCOL)

        net = Containernet(ipBase=IP_BASE)
        net.addController("c0", controller=RemoteController, link=TCLink, ip=CONTROLLER_IP, port=CONTROLLER_PORT)

        net.buildFromTopo(FatTree(4))

        info('*** Starting network\n')
        net.start()
        time.sleep(1)

        info('*** Running CLI\n')
        CLI(net)

        info('*** Stopping network')
        net.stop()
    except Exception as err:
        print(err)
        net.stop()
