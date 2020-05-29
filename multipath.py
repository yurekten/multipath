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
import networkx as nx

from collections import defaultdict
from ryu.topology.event import EventSwitchEnter, EventSwitchReconnected
from operator import itemgetter

import os
import random
import time
import logging

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

    def get_paths(self, src, dst):
        """
        Get all paths from src to dst using DFS algorithm
        """
        if src == dst:
            # host target is on the same switch
            return [[src]]

        path_results = nx.all_simple_paths(self.graph, source=src, target=dst)
        paths = []
        for path in path_results:
            paths.append(path)

        return paths

    def get_link_cost(self, s1, s2):
        """
        Get the link cost between two switches
        """
        e1 = self.graph.edges.get((s1, s2))["port_no"]
        e2 = self.graph.edges.get((s2, s1))["port_no"]
        bw1 = self.graph.nodes[s1]["port_bandwidths"][e1]
        bw2 = self.graph.nodes[s2]["port_bandwidths"][e2]
        bl = min(bw1, bw2)
        ew = int(REFERENCE_BW / bl)
        return ew

    def get_path_cost(self, path):
        """
        Get the path cost
        """
        cost = 0
        for i in range(len(path) - 1):
            cost += self.get_link_cost(path[i], path[i + 1])
        return cost

    def get_optimal_paths(self, src, dst):
        """
        Get the n-most optimal paths according to MAX_PATHS
        """
        if (src, dst)  in self.optimal_paths:
            return self.optimal_paths[(src, dst) ]

        paths = self.get_paths(src, dst)
        paths_count = len(paths) if len(
            paths) < MAX_PATHS else MAX_PATHS

        sorted_paths = sorted(paths, key=lambda x: self.get_path_cost(x))[0:(paths_count)]
        self.optimal_paths[(src, dst)] = sorted_paths
         #logger.debug ("Available and selected paths from ", src, " to ", dst, " : ", sorted_paths)
        return sorted_paths

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
        if (src, first_port, dst, last_port, ip_src, ip_dst) in self.installed_paths:
            current_path = self.installed_paths [(src, first_port, dst, last_port, ip_src, ip_dst)]
            return current_path[0][src][1]

        computation_start = time.time()
        paths = self.get_optimal_paths(src, dst)
        pw = []
        for path in paths:
            pw.append(self.get_path_cost(path))

        sum_of_pw = sum(pw) * 1.0
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        self.installed_paths[(src, first_port, dst, last_port, ip_src, ip_dst)] = paths_with_ports

        #logger.debug("Paths from ", src, " to ", dst, " : ", paths_with_ports)
        switches_in_paths = set().union(*paths)

        for node in switches_in_paths:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            ports = defaultdict(list)
            i = 0

            for path in paths_with_ports:
                if node in path:
                    in_port = path[node][0]
                    out_port = path[node][1]
                    if (out_port, pw[i]) not in ports[in_port]:
                        ports[in_port].append((out_port, pw[i]))
                i += 1

            for in_port in ports:

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

                out_ports = ports[in_port]
                # print out_ports 

                optimized_ports = defaultdict()
                for port, weight in out_ports:
                    if not port in optimized_ports:
                        optimized_ports[port] = 0
                    optimized_ports[port] = optimized_ports[port] + weight

                new_group_ports = []
                for port in optimized_ports:
                    new_group_ports.append((port, optimized_ports[port]))
                out_ports = new_group_ports
                out_ports = sorted(out_ports, key=lambda tup: (tup[0], tup[1]))

                out_ports_str = ' '.join([str(elem) for elem in out_ports])

                if len(out_ports) > 1:

                    if node in self.switch_groups and out_ports_str in self.switch_groups[node]:
                        group_id = self.switch_groups[node][out_ports_str]
                    else:
                        group_new = False
                        if (node, src, first_port, dst, last_port) not in self.multipath_group_ids:
                            group_new = True
                            self.multipath_group_ids[node, src, first_port, dst, last_port] = self.generate_openflow_gid()
                        group_id = self.multipath_group_ids[node, src, first_port, dst, last_port]
                        if not node in  self.switch_groups:
                            self.switch_groups[node] = {}
                        self.switch_groups[node][out_ports_str] = group_id

                        buckets = []
                        weight_k_factor = 0
                        for _, weight in out_ports:
                            weight_k_factor = weight_k_factor + 1.0 / weight

                        weight_k = sum_of_pw / weight_k_factor
                        for port, weight in out_ports:
                            bucket_weight = int(round((1.0*weight_k/weight)*100/sum_of_pw))
                            bucket_action = [ofp_parser.OFPActionOutput(port)]
                            buckets.append(
                                ofp_parser.OFPBucket(
                                    weight=bucket_weight,
                                    watch_port=port,
                                    watch_group=ofp.OFPG_ANY,
                                    actions=bucket_action
                                )
                            )

                        if group_new:
                            req = ofp_parser.OFPGroupMod(
                                dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id,
                                buckets
                            )
                            dp.send_msg(req)
                        else:
                            req = ofp_parser.OFPGroupMod(
                                dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,
                                group_id, buckets)
                            dp.send_msg(req)

                    actions = [ofp_parser.OFPActionGroup(group_id)]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)

                elif len(out_ports) == 1:
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)
        #logger.debug("Path installation is finished for src:%s port:%s > dst:%s port:%s src_ip:%s dst_ip:%s in %s sec" %(src, first_port, dst,  last_port, ip_src, ip_dst, time.time() - computation_start))
        return paths_with_ports[0][src][1]

    @staticmethod
    def add_flow(datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        print("switch_features_handler is called")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        ofp_parser = datapath.ofproto_parser

        actions = []
        match1 = ofp_parser.OFPMatch(eth_type=0x86DD)  # IPv6
        self.add_flow(datapath, 999, match1, actions)

        match2 = ofp_parser.OFPMatch(eth_type=0x88CC)  # LLDP
        self.add_flow(datapath, 999, match2, actions)
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
                if port.state & 0x01 != 1: # select port with status different than OFPPS_LINK_DOWN

                    for prop in port.properties:
                        # select maximum speed
                        if max_bw < prop.curr_speed:
                            max_bw = prop.curr_speed
                        # curr value is feature of port. 2112 (dec) and 0x840 Copper and 10 Gb full-duplex rate support
                        # type 0: ethernet 1: optical 0xFFFF: experimenter
                        print("Port:%s type:%d state:%s - current features=0x%x, current speed:%s kbps" % (port.port_no, prop.type, port.state, prop.curr, prop.curr_speed,))
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
        if eth.ethertype == 35020:
            match = parser.OFPMatch(eth_type=35020)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None

        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
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
        datapath.send_msg(out)

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
        print(ev)
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
