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

from flow_multipath import FlowMultipathManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Cisco Reference bandwidth = 1 Gbps
REFERENCE_BW = 10000000
DEFAULT_BW = 10000000

MAX_PATHS = 10


class MultipathControllerApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MultipathControllerApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}
        self.arp_table = {}
        self.hosts = {}
        self.multipath_group_ids = {}
        self.switch_groups = {}
        self.group_ids = []
        self.graph = nx.DiGraph()
        self.optimal_paths = defaultdict()
        self.installed_paths = defaultdict()
        self.flows = defaultdict()
        self.flow_counter = random.randint(0, 2 ** 10)
        self.unused_cookie = 0x0010000
        self.sw_cookie = defaultdict()
        self.path_flows = defaultdict()
        self.flow_managers = defaultdict()


    def get_next_flow_cookie(self, sw_id):
        if not sw_id in self.sw_cookie:
            self.sw_cookie[sw_id] = defaultdict()
            self.sw_cookie[sw_id]["sw_cookie"] = self.unused_cookie
            self.sw_cookie[sw_id]["last_flow_cookie"] = self.unused_cookie
            self.unused_cookie = self.unused_cookie + 0x0010000

        self.sw_cookie[sw_id]["last_flow_cookie"] = self.sw_cookie[sw_id]["last_flow_cookie"] + 1

        return self.sw_cookie[sw_id]["last_flow_cookie"]

    def increment_flow_cookie(self, ):
        self.base_cookie = self.base_cookie + 0x00100

    def add_ports_to_paths(self, paths, first_port, last_port):
        """
        Add the ports that connects the switches for all paths
        """
        paths_p = []
        for path in paths:
            p = {}
            in_port = first_port
            for s1, s2 in zip(path[:-1], path[1:]):
                out_port = self.graph.edges.get((s1, s2))["port_no"]
                p[s1] = (in_port, out_port)
                in_port = self.graph.edges.get((s2, s1))["port_no"]
            p[path[-1]] = (in_port, last_port)
            paths_p.append(p)
        return paths_p

    def generate_openflow_gid(self):
        """
        Returns a random OpenFlow group id
        """
        n = random.randint(0, 2 ** 32)
        while n in self.group_ids:
            n = random.randint(0, 2 ** 32)
        return n



    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):

        if not  (src, first_port, dst, last_port, ip_src, ip_dst) in self.flow_managers:
            flow_manager = FlowMultipathManager(self, self.graph, self.datapath_list, src, first_port, dst, last_port, ip_src, ip_dst)
            self.flow_managers[(src, first_port, dst, last_port, ip_src, ip_dst)] = flow_manager

        flow_manager = self.flow_managers[(src, first_port, dst, last_port, ip_src, ip_dst)]

        status = flow_manager.get_status()
        if status == FlowMultipathManager.ACTIVE:
            return flow_manager.get_output_port()
        elif status == FlowMultipathManager.INITIATED:
            return flow_manager.get_output_port()
        elif status == FlowMultipathManager.NOT_ACTIVE:
            return flow_manager.initiate_paths()
        else:
            assert status <=  FlowMultipathManager.NOT_ACTIVE, "Not defined state"

    def deneme(self, src, first_port, dst, last_port, ip_src, ip_dst):
        if (src, first_port, dst, last_port, ip_src, ip_dst) in self.installed_paths:
            current_path = self.installed_paths[(src, first_port, dst, last_port, ip_src, ip_dst)]["paths_with_ports"]
            return current_path[0][src][1]

        computation_start = time.time()
        paths = self.get_optimal_paths(src, dst)
        pw = []
        for path in paths:
            pw.append(self.get_path_cost(path))

        sum_of_pw = sum(pw) * 1.0
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        self.installed_paths[(src, first_port, dst, last_port, ip_src, ip_dst)] = defaultdict()
        self.installed_paths[(src, first_port, dst, last_port, ip_src, ip_dst)]["paths_with_ports"] = paths_with_ports
        first_path= random.randint(0, len(paths_with_ports)-1)
        self.installed_paths[(src, first_port, dst, last_port, ip_src, ip_dst)]["installed_flows"] = [first_path]

        self.path_flows[(src, first_port, dst, last_port, ip_src, ip_dst)] = []
        for current_path in paths_with_ports:
            flows = defaultdict()
            self.path_flows[(src, first_port, dst, last_port, ip_src, ip_dst)].append(flows)
            for node in current_path:
                dp = self.datapath_list[node]
                ofp = dp.ofproto
                ofp_parser = dp.ofproto_parser
                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=ip_src,
                    ipv4_dst=ip_dst
                )
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806,
                    arp_spa=ip_src,
                    arp_tpa=ip_dst
                )
                actions = [ofp_parser.OFPActionOutput(current_path[node][1])]
                flows[node] = (dp, match_ip, match_arp, actions)
                #installed_path = self.path_flows[(src, first_port, dst, last_port, ip_src, ip_dst)][first_path]

        for node in self.path_flows[(src, first_port, dst, last_port, ip_src, ip_dst)][first_path]:
            dp, match_ip, match_arp, actions = self.path_flows[(src, first_port, dst, last_port, ip_src, ip_dst)][first_path][node]
            flow_id = self.add_flow(dp, 32768, match_ip, actions, hard_timeout=0)
            flow_id = self.add_flow(dp, 32768, match_arp, actions, hard_timeout=0)

        return paths_with_ports[first_path][src][1]

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0, flags=0, cookie=0,
                 table_id=0, caller=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # if flags is None:
        #    flags = ofproto.OFPFF_SEND_FLOW_REM
        flow_id = cookie
        if cookie == 0:
            flow_id = self.get_next_flow_cookie(datapath.id)

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, hard_timeout=hard_timeout, flags=flags, cookie=flow_id,
                                    table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, hard_timeout=hard_timeout, flags=flags,
                                    cookie=flow_id, table_id=table_id)
        datapath.send_msg(mod)
        if not datapath.id in self.flows:
            self.flows[datapath.id] = defaultdict()
        if caller:
            self.flows[datapath.id][flow_id] = (mod, caller)
        else:
            self.flows[datapath.id][flow_id] = (mod, self)
        return flow_id

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        # logger.info("switch_features_handler is called for %s" % str(ev))
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()




        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, flags=0)

        ofp_parser = datapath.ofproto_parser

        actions = []
        match1 = ofp_parser.OFPMatch(eth_type=0x86DD)  # IPv6
        self.add_flow(datapath, 999, match1, actions, flags=0)

        mod = parser.OFPFlowMod(datapath=datapath, match=match, command=ofproto.OFPFC_DELETE)
        datapath.send_msg(mod)
        # match2 = ofp_parser.OFPMatch(eth_type=0x88CC)  # LLDP
        # self.add_flow(datapath, 999, match2, actions)

    @set_ev_cls(ofp_event.EventOFPGroupFeaturesStatsReply, MAIN_DISPATCHER)
    def group_desc_reply_handler(self, ev):
        switch = ev.msg.datapath

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        print("Port Description Stats for Switch %s" % switch.id)
        if switch.id in self.graph.nodes:

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
                        # curr value is feature of port. 2112 (dec) and 0x840 Copper and 10 Gb full-duplex rate support
                        # type 0: ethernet 1: optical 0xFFFF: experimenter
                        logger.info("Port:%s type:%d state:%s - current features=0x%x, current speed:%s kbps" % (
                            port.port_no, prop.type, port.state, prop.curr, prop.curr_speed,))
                port_bandwidths[port.port_no] = max_bw
            self.graph.nodes[switch.id]["port_desc_stats"] = sw_ports
            self.graph.nodes[switch.id]["port_bandwidths"] = port_bandwidths

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

        # avoid broadcast from LLDP
        if eth.ethertype == 0x88CC:
            # match = parser.OFPMatch(eth_type=35020)
            # actions = []
            # self.add_flow(datapath, 1, match, actions)
            return None

        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            # match = parser.OFPMatch(eth_type=eth.ethertype)
            # actions = []
            # self.add_flow(datapath, 1, match, actions)
            return None

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD

        if arp_pkt:
            # print dpid, pkt
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
                h1 = self.hosts[src]
                h2 = self.hosts[dst]
                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip)  # reverse
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]
                    out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                    self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip)  # reverse

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        try:
            datapath.send_msg(out)
        except Exception as err:
            print("out in_port: %s" %in_port)
            raise err

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser

        if switch.id not in self.graph.nodes:
            self.datapath_list[switch.id] = switch
            self.graph.add_node(switch.id, dp=switch)
            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        logger.info(ev)
        switch_id = ev.switch.dp.id
        if switch_id in self.graph.nodes:
            self.graph.remove_node(switch_id)

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        self.graph.add_edge(s1.dpid, s2.dpid, port_no=s1.port_no)
        self.graph.add_edge(s2.dpid, s1.dpid, port_no=s2.port_no)

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        if (s1.dpid, s2.dpid) in self.graph.edges:
            self.graph.remove_edge(s1.dpid, s2.dpid)
        if (s2.dpid, s1.dpid) in self.graph.edges:
            self.graph.remove_edge(s2.dpid, s1.dpid)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        manager = self.flows[dp.id][msg.cookie]
        manager[1].flow_removed(msg)
        # for manager in self.flow_managers:
        #
        # if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
        #     reason = 'IDLE TIMEOUT'
        # elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
        #     reason = 'HARD TIMEOUT'
        # elif msg.reason == ofp.OFPRR_DELETE:
        #     reason = 'DELETE'
        # elif msg.reason == ofp.OFPRR_GROUP_DELETE:
        #     reason = 'GROUP DELETE'
        # else:
        #     reason = 'unknown'
        #
        # print(
        #     'OFPFlowRemoved received: cookie=%d priority=%d reason=%s table_id=%d duration_sec=%d duration_nsec=%d idle_timeout=%d hard_timeout=%d packet_count=%d byte_count=%d match.fields=%s' % (
        #     msg.cookie, msg.priority, reason, msg.table_id, msg.duration_sec, msg.duration_nsec, msg.idle_timeout,
        #     msg.hard_timeout, msg.packet_count, msg.byte_count, msg.match))
