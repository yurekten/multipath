from random import random

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types
from ryu.lib import mac, ip
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

# Cisco Reference bandwidth = 1 Gbps
REFERENCE_BW = 10000000
DEFAULT_BW = 10000000

MAX_PATHS = 10


class MultipathControllerApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MultipathControllerApp, self).__init__(*args, **kwargs)

        self.sw_cookie = defaultdict()
        self.unused_cookie = 0x0010000
        self.flow_managers = defaultdict()
        self.datapath_list = {}

        self.flows = defaultdict()
        self.topology = nx.DiGraph()

        self.arp_table = {}
        self.hosts = {}
        self.broadcast_messages = defaultdict()


    def _get_next_flow_cookie(self, sw_id):
        if not sw_id in self.sw_cookie:
            self.sw_cookie[sw_id] = defaultdict()
            self.sw_cookie[sw_id]["sw_cookie"] = self.unused_cookie
            self.sw_cookie[sw_id]["last_flow_cookie"] = self.unused_cookie
            self.unused_cookie = self.unused_cookie + 0x0010000

        self.sw_cookie[sw_id]["last_flow_cookie"] = self.sw_cookie[sw_id]["last_flow_cookie"] + 1

        return self.sw_cookie[sw_id]["last_flow_cookie"]

    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):
        first_time = False
        start = time.perf_counter()
        if not (src, first_port, dst, last_port, ip_src, ip_dst) in self.flow_managers:
            first_time = True
            dp_list = self.datapath_list
            flow_manager = FlowMultipathManager(self, self.topology, dp_list, src, first_port, dst, last_port, ip_src, ip_dst)
            self.flow_managers[(src, first_port, dst, last_port, ip_src, ip_dst)] = flow_manager
            if logger.isEnabledFor(level=logging.INFO):
                end = time.perf_counter()
                logger.info(f"initiate flow {(src, first_port, dst, last_port, ip_src, ip_dst)} in {end - start:0.4f} seconds")

        flow_manager = self.flow_managers[(src, first_port, dst, last_port, ip_src, ip_dst)]
        output_port = flow_manager.initiate_paths()
        if first_time and logger.isEnabledFor(level=logging.INFO):
            setup_end = time.perf_counter()
            logger.info(f"flow {(src, first_port, dst, last_port, ip_src, ip_dst)} setup completed in {setup_end - start:0.4f} seconds")

        return output_port

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
        print("Port Description Stats for Switch %s" % switch.id)
        if switch.id in self.topology.nodes:

            sw_ports = defaultdict()
            port_bandwidths = defaultdict()
            for port in ev.msg.body:
                sw_ports[port.port_no] = port
                max_bw = 0
                if port.state & 0x01 != 1:  # select port with status different than OFPPS_LINK_DOWN

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
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        # avoid broadcast from LLDP
        if eth.ethertype == 0x88CC:
            return None

        if pkt.get_protocol(ipv6.ipv6):
            return None

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD
        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    self.arp_table[src_ip] = src
        elif ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            self.arp_table[src_ip] = src
            self.arp_table[dst_ip] = dst
        else:
            return

        if src in self.hosts and dst in self.hosts:
            h1 = self.hosts[src]
            h2 = self.hosts[dst]
            if (dst_ip, src_ip) in self.broadcast_messages:
                self.broadcast_messages[(dst_ip, src_ip)]["ip"] = src_ip

            out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
            self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip)  # reverse


        #if arp_pkt and (self.hosts[src][0] == datapath.id):

        if arp_pkt:
            # print dpid, pkt
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
                h1 = self.hosts[src]
                h2 = self.hosts[dst]
                if (dst_ip, src_ip) in self.broadcast_messages:
                    self.broadcast_messages[(dst_ip, src_ip)]["ip"] = src_ip

                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)

                self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip)  # reverse
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    self.arp_table[src_ip] = src

                if (src_ip, dst_ip) in self.broadcast_messages:
                    if not datapath.id in self.broadcast_messages[(src_ip, dst_ip)]["dp_list"]:
                        self.broadcast_messages[(src_ip, dst_ip)]["dp_list"].append(datapath.id)
                    else:
                        if self.broadcast_messages[(src_ip, dst_ip)]["ip"] is not None:
                            return
                else:
                    self.broadcast_messages[(src_ip, dst_ip)] = defaultdict()
                    self.broadcast_messages[(src_ip, dst_ip)]["time"] = time.time()
                    self.broadcast_messages[(src_ip, dst_ip)]["dp_list"] = [datapath.id]
                    self.broadcast_messages[(src_ip, dst_ip)]["ip"] = None

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        try:
            if out_port is not None:
                datapath.send_msg(out)
        except Exception as err:
            print("out in_port: %s" % in_port)
            raise err

    @set_ev_cls(event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        if logger.isEnabledFor(level=logging.INFO):
            logger.info(ev)
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
            logger.info(ev)
        switch_id = ev.switch.dp.id
        if switch_id in self.topology.nodes:
            self.topology.remove_node(switch_id)

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def _link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        self.topology.add_edge(s1.dpid, s2.dpid, port_no=s1.port_no)
        self.topology.add_edge(s2.dpid, s1.dpid, port_no=s2.port_no)

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
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
