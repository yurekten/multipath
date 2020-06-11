from datetime import datetime
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
logger.setLevel(level=logging.INFO)

# Cisco Reference bandwidth = 1 Gbps
REFERENCE_BW = 10000000
DEFAULT_BW = 10000000

MAX_PATHS = 10

ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
IPV4 = ipv4.ipv4.__name__

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

        self.mac_to_port = {}
        self.ip_to_port = {}
        self.unmanaged_flows = {}
        self.managed_flows = {}

        self.activation_delay = 2 #start if flow is active 2 seconds
        self.flow_stats_sampling_period = 0.3
        self.min_flow_stats_sample = 4
        self.min_packet_in_period = 3

        hub.spawn(self._monitor_initial_flows)

    def _get_next_flow_cookie(self, sw_id):
        if not sw_id in self.sw_cookie:
            self.sw_cookie[sw_id] = defaultdict()
            self.sw_cookie[sw_id]["sw_cookie"] = self.unused_cookie
            self.sw_cookie[sw_id]["last_flow_cookie"] = self.unused_cookie
            self.unused_cookie = self.unused_cookie + 0x0010000

        self.sw_cookie[sw_id]["last_flow_cookie"] = self.sw_cookie[sw_id]["last_flow_cookie"] + 1

        return self.sw_cookie[sw_id]["last_flow_cookie"]



    def _get_managed_flow_state(self, in_port, dst, src, datapath):
        packet_statistics = self.unmanaged_flows[(in_port, dst, src, datapath)]

        last_ind = len(packet_statistics)
        time_diff = (datetime.now() - packet_statistics[0][0]).total_seconds()

        if last_ind >= self.min_flow_stats_sample:
            if time_diff > self.activation_delay:
                index_prev = last_ind - 2
                index_last = last_ind - 1
                packet_count = packet_statistics[index_last][1] - packet_statistics[index_prev][1]

                #logger.debug(f'_can_be_managed_flow for {in_port, dst, src, datapath} stats index {last_ind} and time {time_diff}')
                if packet_count >= self.min_packet_in_period:
                    #logger.debug(f'{in_port, dst, src, datapath} watcher is initiated')
                    return 1
                else:
                    #logger.debug(f'{in_port, dst, src, datapath} watcher is idle expired')
                    return 0
            else:
                return -1
        else:
            if time_diff < self.activation_delay:
                return -1
            else:
                return 0

    def _monitor_initial_flows(self):
        completed = False
        while not completed:
            key_list = list(self.unmanaged_flows.keys())
            for (in_port, dst, src, datapath) in key_list:
                state = self._get_managed_flow_state(in_port, dst, src, datapath)
                if state == -1:
                    self._request_flow_packet_count(in_port, dst, src, datapath)
                    logger.debug(f'In waiting state: OFPFlowStatsRequest is sent fpr {in_port, dst, src, datapath}')
                elif state == 0:
                    del self.unmanaged_flows[(in_port, dst, src, datapath)]
                    logger.debug(f'In expired state: deleted from map {in_port, dst, src, datapath}')
                elif state == 1:
                    del self.unmanaged_flows[(in_port, dst, src, datapath)]
                    dp_list = self.datapath_list
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst]

                    flow_manager = FlowMultipathManager(self, self.topology, dp_list, h1[0], h1[1], h2[0], h2[1], h1[2], h2[2])

                    self.flow_managers[flow_manager.flow_info] = flow_manager
                    flow_manager.get_active_path_port_for(dp_list[h1[0]])

                    if logger.isEnabledFor(level=logging.INFO):
                        logger.info(f"Initiate flow manager {flow_manager.flow_info} at {datetime.now()}")

            hub.sleep(self.flow_stats_sampling_period)

    def flow_manager_is_destroying(self, flow):
        if flow.flow_info in self.flow_managers:
            del self.flow_managers[flow.flow_info]
            if logger.isEnabledFor(level=logging.INFO):
                logger.info(f"Terminate flow manager {flow.flow_info}  at {datetime.now()}")

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
                in_port = flow.match["in_port"]

                if "eth_src" in flow.match:
                    eth_src = flow.match["eth_src"]

                if "eth_src" in flow.match:
                    eth_dst = flow.match["eth_dst"]
                initial = False

        if (in_port, eth_dst, eth_src, datapath_id) in self.unmanaged_flows:
            stat = self.unmanaged_flows[ (in_port, eth_dst, eth_src, datapath_id)]
            stat.append((datetime.now(), max_packet_count))
            logger.debug(f'OFPFlowStatsReply is processed for {in_port, eth_dst, eth_src, datapath_id}: {(datetime.now(), max_packet_count)}')

       # for stat in sorted([flow for flow in body if flow.priority == 1],
       #                    key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])



    def get_active_path_port_for(self, src, first_port, dst, last_port, ip_src, ip_dst, current_dpid, eth_src, eth_dst):
        if (src, first_port, dst, last_port, ip_src, ip_dst) in self.flow_managers:
            flow_manager = self.flow_managers[(src, first_port, dst, last_port, ip_src, ip_dst)]
            output_port = flow_manager.get_active_path_port_for(current_dpid)
            if logger.isEnabledFor(level=logging.INFO):
                logger.info(f"flow manager for {(src, first_port, dst, last_port, ip_src, ip_dst)} is started")
            return output_port


        if (first_port, eth_dst, eth_src, current_dpid) not in self.unmanaged_flows:
            self.unmanaged_flows[(first_port, eth_dst, eth_src, current_dpid)] = []
            self.unmanaged_flows[(first_port, eth_dst, eth_src, current_dpid)].append((datetime.now(), 0))

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
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # avoid broadcast from LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return None

        if pkt.get_protocol(ipv6.ipv6):
            return None

        dst = eth.dst
        src = eth.src
        dpid = datapath.id



        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
            self.ip_to_port[dpid] = {}

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

        self.ip_to_port[dpid][src_ip] = in_port
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

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions, idle_timeout=5)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)



    @set_ev_cls(event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        if logger.isEnabledFor(level=logging.INFO):
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

