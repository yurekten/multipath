from datetime import datetime
from random import random
from threading import RLock

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4, ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
from ryu.lib import mac, ip, hub
from ryu.topology.api import get_switch, get_link, get_all_switch, get_all_host, get_all_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event
from ryu.ofproto import nicira_ext
import networkx as nx

from collections import defaultdict
from ryu.topology.event import EventSwitchEnter, EventSwitchReconnected
from operator import itemgetter

from ryu.lib import type_desc
import os
import random
import time
import logging

from multipath_manager import FlowMultipathManager

logger = logging.getLogger(__name__)
logger.setLevel(level=logging.WARNING)


class MultipathControllerApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, multipath_enabled=True, *args, **kwargs):
        super(MultipathControllerApp, self).__init__(*args, **kwargs)
        self.multipath_enabled = multipath_enabled

        self.sw_cookie = defaultdict()
        self.unused_cookie = 0x0010000
        self.flow_managers = defaultdict()
        self.datapath_list = {}

        self.flows = defaultdict()
        self.topology = nx.DiGraph()

        self.arp_table = {}
        self.hosts = {}

        self.mac_to_port = {}

        self.no_flood_ports = None

        self.lock = RLock()

        self.activation_delay = 1 # start multipath if flow duration greater than activation_delay
        self.min_packet_in_period = 10

        logger.warning("SDN Controleller started - multipath enabled:  %s" % self.multipath_enabled)

    def _start_flow_manager(self, dst, src):

        with self.lock:

            h1 = self.hosts[src]
            h2 = self.hosts[dst]
            if (h1[0], h1[1], h2[0], h2[1], h1[2], h2[2]) in self.flow_managers:
                return

            dp_list = self.datapath_list

            flow_manager = FlowMultipathManager(self, self.topology, dp_list, h1[0], h1[1], h2[0], h2[1], h1[2], h2[2])
            self.flow_managers[flow_manager.flow_info] = flow_manager
            flow_manager.get_active_path_port_for(dp_list[h1[0]])
            if logger.isEnabledFor(level=logging.WARNING):
                logger.warning(f"Initiate flow manager {flow_manager.flow_info} at {datetime.now()}")

    def flow_manager_is_destroying(self, flow):
        with self.lock:
            if flow.flow_info in self.flow_managers:
                del self.flow_managers[flow.flow_info]
                if logger.isEnabledFor(level=logging.WARNING):
                    logger.warning(f"Terminate flow manager {flow.flow_info}  at {datetime.now()}")

    def _get_next_flow_cookie(self, sw_id):
        if not sw_id in self.sw_cookie:
            self.sw_cookie[sw_id] = defaultdict()
            self.sw_cookie[sw_id]["sw_cookie"] = self.unused_cookie
            self.sw_cookie[sw_id]["last_flow_cookie"] = self.unused_cookie
            self.unused_cookie = self.unused_cookie + 0x0010000

        self.sw_cookie[sw_id]["last_flow_cookie"] = self.sw_cookie[sw_id]["last_flow_cookie"] + 1

        return self.sw_cookie[sw_id]["last_flow_cookie"]

    def _request_flow_packet_count(self, in_port, dst, src, datapath_id):
        datapath = self.datapath_list[datapath_id]
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                             ofp.OFPTT_ALL,
                                             ofp.OFPP_ANY, ofp.OFPG_ANY,
                                             cookie, cookie_mask,
                                             match)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath_id = ev.msg.datapath.id

        max_packet_count = 0
        eth_src = -1
        eth_dst = -1
        in_port = -1

        initial = True
        for flow in body:
            if max_packet_count < flow.packet_count:
                max_packet_count = flow.packet_count
            if initial:
                if "in_port" in flow.match:
                    in_port = flow.match["in_port"]

                if "eth_src" in flow.match:
                    eth_src = flow.match["eth_src"]

                if "eth_src" in flow.match:
                    eth_dst = flow.match["eth_dst"]
                initial = False

    def get_active_path_port_for(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid, eth_src, eth_dst):
        if (src, first_port, dst, last_port, ip_src, ip_dst) in self.flow_managers:
            flow_manager = self.flow_managers[(src, first_port, dst, last_port, ip_src, ip_dst)]
            output_port = flow_manager.get_active_path_port_for(current_dpid)
            return output_port
        return None

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0, flags=0, cookie=0,
                 table_id=0, idle_timeout=0, caller=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        flow_id = cookie
        if cookie == 0:
            flow_id = self._get_next_flow_cookie(datapath.id)

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, idle_timeout=idle_timeout,
                                    instructions=inst, hard_timeout=hard_timeout, flags=flags, cookie=flow_id,
                                    table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, idle_timeout=idle_timeout,
                                    match=match, instructions=inst, hard_timeout=hard_timeout, flags=flags,
                                    cookie=flow_id, table_id=table_id)
        datapath.send_msg(mod)
        if datapath.id not in self.flows:
            self.flows[datapath.id] = defaultdict()
        if caller:
            self.flows[datapath.id][flow_id] = (mod, caller)
        else:
            self.flows[datapath.id][flow_id] = (mod, self)
        return flow_id

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        logger.debug("switch_features_handler is called for %s" % str(ev))
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, flags=0)

        ofp_parser = datapath.ofproto_parser

        actions = []
        match1 = ofp_parser.OFPMatch(eth_type=0x86DD)  # IPv6
        self.add_flow(datapath, 999, match1, actions, flags=0)


    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Port Description Stats for Switch %s" % switch.id)
        if switch.id in self.topology.nodes:

            sw_ports = defaultdict()
            port_bandwidths = defaultdict()
            for port in ev.msg.body:
                sw_ports[port.port_no] = port
                max_bw = 0
                if port.state & 0x01 != 1:  # select port with status different than OFPPS_LINK_DOWN
                    if switch.ofproto.OFP_VERSION <= ofproto_v1_3.OFP_VERSION:
                        if max_bw < port.curr_speed:
                            max_bw = port.curr_speed
                        if logger.isEnabledFor(level=logging.DEBUG):
                            # curr value is feature of port. 2112 (dec) and 0x840 Copper and 10 Gb full-duplex rate support
                            # type 0: ethernet 1: optical 0xFFFF: experimenter
                            logger.debug("Port:%s state:%s - current features=0x%x, current speed:%s kbps"
                                         % (port.port_no, port.state, port.curr, port.curr_speed,))
                    else:
                        for prop in port.properties:
                            # select maximum speed
                            if max_bw < prop.curr_speed:
                                max_bw = prop.curr_speed
                            if logger.isEnabledFor(level=logging.DEBUG):
                                # curr value is feature of port. 2112 (dec) and 0x840 Copper and 10 Gb full-duplex rate support
                                # type 0: ethernet 1: optical 0xFFFF: experimenter
                                logger.debug("Port:%s type:%d state:%s - current features=0x%x, current speed:%s kbps"
                                             % (port.port_no, prop.type, port.state, prop.curr, prop.curr_speed,))
                port_bandwidths[port.port_no] = max_bw
            self.topology.nodes[switch.id]["port_desc_stats"] = sw_ports
            self.topology.nodes[switch.id]["port_bandwidths"] = port_bandwidths

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        # avoid broadcast from LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        if pkt.get_protocol(ipv6.ipv6):
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}

        logger.debug("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)


        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

        elif ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
        else:
            #ignore other packets
            return

        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port, src_ip)

        out_port = None
        if src in self.hosts and dst in self.hosts:
            h1 = self.hosts[src]
            h2 = self.hosts[dst]
            if h1[0] == dpid:
                #if self._can_be_managed_flow(in_port, dst, src, h1[0]):
                out_port = self.get_active_path_port_for(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip, dpid, src, dst)
        if out_port is None:
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if self.multipath_enabled:
                self.add_flow(datapath, 3, match, actions, hard_timeout=self.activation_delay, flags=ofproto.OFPFF_SEND_FLOW_REM)

            self.add_flow(datapath, 1, match, actions, idle_timeout=(self.activation_delay + 2))
        else:
            if self.no_flood_ports is None:
                self._recalculate_flood_ports()
            actions = []
            if dpid in self.no_flood_ports:
                for port, port_info in self.datapath_list[dpid].ports.items():
                    if port_info.state == 4 and port not in self.no_flood_ports[dpid]:
                        if port != in_port:
                            actions.append(parser.OFPActionOutput(port))
            else:
                actions.append(parser.OFPActionOutput(out_port))

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _recalculate_flood_ports(self):
        nodes = list(self.topology.nodes)
        edges =list(self.topology.edges)
        graph = nx.Graph()
        graph.add_nodes_from(nodes)
        graph.add_edges_from(edges)

        spanning_tree = nx.minimum_spanning_tree(graph)

        no_flood_links = list(set(graph.edges) - set(spanning_tree.edges))

        self.no_flood_ports = defaultdict()
        if len(no_flood_links) > 0:
            for link in no_flood_links:
                s1 = link[0]
                s2 = link[1]
                e1 = self.topology.edges.get((s1, s2))["port_no"]
                if s1 not in self.no_flood_ports:
                    self.no_flood_ports[s1] = set()
                self.no_flood_ports[s1].add(e1)

                e2 = self.topology.edges.get((s2, s1))["port_no"]
                if s2 not in self.no_flood_ports:
                    self.no_flood_ports[s2] = set()
                self.no_flood_ports[s2].add(e2)

            logger.warning("Flood Ports is updated using spanning tree: %s" % self.no_flood_ports)

    @set_ev_cls(event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        if logger.isEnabledFor(level=logging.DEBUG):
            logger.debug(ev)
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser

        if switch.id not in self.topology.nodes:
            self.datapath_list[switch.id] = switch
            self.topology.add_node(switch.id, dp=switch)
            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def _switch_leave_handler(self, ev):
        if logger.isEnabledFor(level=logging.INFO):
            logger.debug(ev)
        switch_id = ev.switch.dp.id
        if switch_id in self.topology.nodes:
            self.topology.remove_node(switch_id)

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def _link_add_handler(self, ev):
        if logger.isEnabledFor(level=logging.INFO):
            logger.debug(ev)
        s1 = ev.link.src
        s2 = ev.link.dst
        self.topology.add_edge(s1.dpid, s2.dpid, port_no=s1.port_no)
        self.topology.add_edge(s2.dpid, s1.dpid, port_no=s2.port_no)
        if self.no_flood_ports is not None:
            self._recalculate_flood_ports()


    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        if logger.isEnabledFor(level=logging.INFO):
            logger.debug(ev)
        s1 = ev.link.src
        s2 = ev.link.dst
        if (s1.dpid, s2.dpid) in self.topology.edges:
            self.topology.remove_edge(s1.dpid, s2.dpid)
        if (s2.dpid, s1.dpid) in self.topology.edges:
            self.topology.remove_edge(s2.dpid, s1.dpid)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id in self.flows:
            if msg.cookie in self.flows[dp.id]:
                manager = self.flows[dp.id][msg.cookie]
                manager[1].flow_removed(msg)
                del self.flows[dp.id][msg.cookie]

    def flow_removed(self, msg):
        ofproto = msg.datapath.ofproto
        if self.multipath_enabled:
            if msg.reason == ofproto.OFPRR_HARD_TIMEOUT:
                if msg.packet_count > self.min_packet_in_period:
                    eth_src = None
                    eth_dst = None
                    if "eth_src" in msg.match:
                        eth_src = msg.match["eth_src"]
                    if "eth_dst" in msg.match:
                        eth_dst = msg.match["eth_dst"]

                    if eth_src is not None and eth_dst is not None:
                        self._start_flow_manager(eth_dst, eth_src)

