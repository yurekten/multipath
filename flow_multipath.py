from collections import defaultdict
from datetime import datetime
import random
import time
from threading import RLock, Timer

import networkx as nx
import asyncio

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

REFERENCE_BW = 10000000

class FlowMultipathManager(object):
    NOT_ACTIVE = 0
    INITIATED = 1
    ACTIVE = 2

    def __init__(self, multipath_app, graph, dp_list, src, first_port, dst, last_port, ip_src, ip_dst,  max_paths=10, max_installed_path_count = 3, min_timeout_time=2, highest_priority=60000, *args, **kwargs):
        self.state = FlowMultipathManager.NOT_ACTIVE
        self.multipath_app = multipath_app
        self.graph = graph
        self.dp_list = dp_list
        self.src = src
        self.first_port = first_port
        self.dst = dst
        self.last_port = last_port
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.max_paths = max_paths
        self.max_installed_path_count = max_installed_path_count
        self.min_timeout_time = min_timeout_time
        self.highest_priority = highest_priority
        self.statistics = defaultdict()
        self.statistics["rule_set"] = defaultdict()
        self.statistics["paths"] = None
        self.statistics["path_choices"] = None

        self.flow_info = (src, first_port, dst, last_port, ip_src, ip_dst,)

        self.optimal_paths = None
        self.paths_with_ports = None

        self.path_choices = None
        self.last_installed_path_index = -1
        self.installed_path_indices = []


        self.deactivation_started = False
        self.removed_flow_id = defaultdict()

        self.all_paths = None
        self.rule_set_id = 0x10000
        self.flow_id_rule_set = defaultdict()

        self.lock = RLock()
        self.calculate_optimal_paths()


    def get_status(self):
        return self.state

    def get_paths(self):
        """
        Get all paths from src to dst using DFS algorithm
        """
        if self.src == self.dst:
            # host target is on the same switch
            return [[self.src]]

        if self.all_paths is not None:
            return self.all_paths

        path_results = nx.all_simple_paths(self.graph, source=self.src, target=self.dst)
        paths = []
        for path in path_results:
            paths.append(path)

        self.all_paths = paths
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

    def calculate_optimal_paths(self):
        """
        Get the n-most optimal paths according to MAX_PATHS
        """

        if self.optimal_paths is not None:
            return self.optimal_paths

        paths = self.get_paths()
        paths_count = len(paths) if len(paths) < self.max_paths else self.max_paths

        sorted_paths = sorted(paths, key=lambda x: self.get_path_cost(x))[0:(paths_count)]
        self.optimal_paths = sorted_paths
        pw = []
        for path in sorted_paths:
            pw.append(self.get_path_cost(path))

        path_indices = range(0, len(sorted_paths))
        self.path_choices = random.choices(path_indices, weights=pw, k=100)
        self.paths_with_ports = self.add_ports_to_paths(self.optimal_paths, self.first_port, self.last_port)
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

    def initiate_paths(self):
        with self.lock:
            updated = self.update_paths()
            if updated:
                t = Timer(self.min_timeout_time, self.update_paths)
                t.start()
            return self.get_output_port()
            #elif self.state == FlowMultipathManager.INITIATED:
        #    print("Beklenmedik durum")


    def update_paths(self):
        updated = False
        first_initialization = False
        if self.state == FlowMultipathManager.NOT_ACTIVE:
            self.state = FlowMultipathManager.INITIATED
            first_initialization = True
            #self.last_installed_path_index = -1
            #self.installed_path_indices = []
            #self.optimal_paths = None
            #self.paths_with_ports = None
            start = time.perf_counter()
            self.calculate_optimal_paths()
            end = time.perf_counter()
            logger.info(f"calculate_optimal_paths in {end - start:0.4f} seconds")
            #self.paths_with_ports = self.add_ports_to_paths(self.optimal_paths, self.first_port, self.last_port)





            #print(self.paths_with_ports)
        #elif self.state == FlowMultipathManager.ACTIVE:
        if first_initialization == True or self.state == FlowMultipathManager.ACTIVE:

            assert len(self.installed_path_indices) >= 0, "If State is active, path count must be greater than 0"
            timeout_time = len(self.installed_path_indices)*self.min_timeout_time
            if len(self.installed_path_indices) < self.max_installed_path_count:
                for i in range(len(self.installed_path_indices), self.max_installed_path_count):
                    self.last_installed_path_index = self.last_installed_path_index + 1
                    if self.last_installed_path_index >= len(self.path_choices):
                        self.last_installed_path_index = 0

                    current_path_index = self.path_choices[self.last_installed_path_index]
                    timeout_time = timeout_time + self.min_timeout_time

                    priority = self.highest_priority - self.last_installed_path_index

                    selected_path = self.paths_with_ports[current_path_index]
                    rule_set_id = self.create_flow_rules(selected_path, priority, hard_timeout=timeout_time)
                    updated = True
                    self.statistics["paths"] = self.paths_with_ports
                    self.statistics["path_choices"] = self.path_choices
                    self.statistics["rule_set"][rule_set_id]["installed_path_index"] = current_path_index
                    self.statistics["rule_set"][rule_set_id]["choise_index"] = self.last_installed_path_index
                    self.installed_path_indices.append(self.last_installed_path_index)
                    self.state = FlowMultipathManager.ACTIVE
        return updated




    def get_output_port(self):
        if len(self.installed_path_indices) > 0:
            active_path_in_choises = self.installed_path_indices[0]
            active_path =  self.paths_with_ports[self.path_choices[active_path_in_choises]]
            first_output_port = active_path[self.src][1]
            return first_output_port
        return None

    def create_flow_rules(self, current_path, priority, hard_timeout=10):

        #self.rule_set_id = 0x10000
        self.rule_set_id = self.rule_set_id + 1
        self.statistics["rule_set"][self.rule_set_id] = defaultdict()
        self.statistics["rule_set"][self.rule_set_id]["path"] = current_path
        self.statistics["rule_set"][self.rule_set_id]["datapath_list"] = defaultdict()
        self.statistics["rule_set"][self.rule_set_id]["flow_info"] = self.flow_info


        rule_set = self.statistics["rule_set"][self.rule_set_id]

        for node in current_path:

            if node not in rule_set["datapath_list"]:
                rule_set["datapath_list"][node] = defaultdict()
                rule_set["datapath_list"][node]["ip_flow"] = defaultdict()
                rule_set["datapath_list"][node]["arp_flow"] = defaultdict()




            dp = self.dp_list[node]
            ofproto = dp.ofproto
            ofp_parser = dp.ofproto_parser

            in_port = current_path[node][0]

            match_ip = ofp_parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=self.ip_src,
                ipv4_dst=self.ip_dst,
                in_port=in_port
            )
            match_arp = ofp_parser.OFPMatch(
                eth_type=0x0806,
                arp_spa=self.ip_src,
                arp_tpa=self.ip_dst,
                in_port=in_port,
            )
            actions = [ofp_parser.OFPActionOutput(current_path[node][1])]
            #flows[node] = (dp, match_ip, match_arp, actions)
            flow_id = self.multipath_app.add_flow(dp, priority, match_ip, actions, hard_timeout=hard_timeout, flags = ofproto.OFPFF_SEND_FLOW_REM, caller=self)


            stats = rule_set["datapath_list"][node]["ip_flow"]

            stats[flow_id] = defaultdict()
            stats[flow_id]["created_time"] = datetime.now()
            stats[flow_id]["flow_params"] = (node, match_ip, match_arp, actions)
            stats[flow_id]["removed_time"] = None
            stats[flow_id]["packet_count"] = None
            self.flow_id_rule_set[flow_id] = self.rule_set_id
            flow_id = self.multipath_app.add_flow(dp, priority, match_arp, actions, hard_timeout=hard_timeout, flags = ofproto.OFPFF_SEND_FLOW_REM, caller=self)
            stats = rule_set["datapath_list"][node]["arp_flow"]

            self.flow_id_rule_set[flow_id] = self.rule_set_id
            stats[flow_id] = defaultdict()
            stats[flow_id]["created_time"] = datetime.now()
            stats[flow_id]["removed_time"] = None
            stats[flow_id]["packet_count"] = None
            stats[flow_id]["flow_params"] = (node, match_ip, match_arp, actions)

        return self.rule_set_id

    def flow_removed(self, msg):
        #print (msg)

        removed_path_index = -1
        if msg.cookie in self.flow_id_rule_set:
            rule_set_id = self.flow_id_rule_set[msg.cookie]
            removed_path_index = self.statistics["rule_set"][rule_set_id]["choise_index"]
            #path = self.statistics[rule_set_id]["path"]
            # if removed_path_index not in self.statistics:
            #     self.statistics[removed_path_index] = defaultdict()
            #     self.statistics[removed_path_index]["path"] = self.paths_with_ports[path]
            #     self.statistics[removed_path_index]["datapath"] = defaultdict()
            #     self.statistics[removed_path_index]["flow"] = self.flow_info

            # if  msg.datapath.id not in self.statistics[removed_path_index]["datapath"]:
            #     self.statistics[removed_path_index]["datapath"][msg.datapath.id] = defaultdict()
            if msg.datapath.id in self.statistics["rule_set"][rule_set_id]["datapath_list"]:
                stats = self.statistics["rule_set"][rule_set_id]["datapath_list"][msg.datapath.id]["ip_flow"]
                if msg.cookie in stats:
                    stats[msg.cookie]["removed_time"] = datetime.now()
                    stats[msg.cookie]["packet_count"] = msg.packet_count

                stats = self.statistics["rule_set"][rule_set_id]["datapath_list"][msg.datapath.id]["ip_flow"]
                if msg.cookie in stats:
                    stats[msg.cookie]["removed_time"] = datetime.now()
                    stats[msg.cookie]["packet_count"] = msg.packet_count

            #logger.info("flow: %s step:%s path: %s datapath:%s flow id:0x%x removed. Packet_count:%s:" % (self.flow_info, removed_path_index, self.paths_with_ports[path], msg.datapath.id, msg.cookie, msg.packet_count))


        if removed_path_index in self.installed_path_indices:
            try:
                self.installed_path_indices.remove(removed_path_index)
            except ValueError:
                pass  # do nothing!
            if self.deactivation_started == False:
                self.initiate_paths()

            if msg.packet_count == 0:
                if msg.datapath.id not in self.removed_flow_id:
                    self.removed_flow_id[msg.datapath.id] = []

                self.removed_flow_id[msg.datapath.id].append(msg.cookie)

                if len(self.removed_flow_id[msg.datapath.id]) > 1:
                    self.deactivation_started = True
                    self.state = FlowMultipathManager.NOT_ACTIVE
                    del self.removed_flow_id[msg.datapath.id]
                #self.deactivation_time = time.time() + self.min_timeout_time  - 0.5
            else:
                self.deactivation_started = False

        # print(
        #     'OFPFlowRemoved received: cookie=%d priority=%d reason=%s table_id=%d duration_sec=%d duration_nsec=%d idle_timeout=%d hard_timeout=%d packet_count=%d byte_count=%d match.fields=%s' % (
        #     msg.cookie, msg.priority, reason, msg.table_id, msg.duration_sec, msg.duration_nsec, msg.idle_timeout,
        #     msg.hard_timeout, msg.packet_count, msg.byte_count, msg.match))

    def start(self, outputs, probabilities, timeout_sec, time_frame_sec=1):
        self.time_frame =  time_frame_sec
        self.start_time = datetime.now()
        self.end_time = datetime.now().second + timeout_sec*1000
        self.outputs = outputs
        self.probabilities = probabilities
        self.state = FlowMultipathManager.INITIATED
        self.choices = random.choices(outputs, weights=probabilities, k=int(timeout_sec/time_frame_sec))

        self.time_boxes = []
        current = None
        increment = 0
        for item in self.choices:
            increment = increment + 1
            if current != item:
                self.time_boxes.append((current, increment))
                current = item
                increment = 0

        self.time_boxes.append((current, increment+1))
        del self.time_boxes[0]

        self.rules = {}
        counter = 0
        for output, count  in self.time_boxes:
            self.rules[self.cookie_base + counter] = (output, count*time_frame_sec)

        print(self.time_boxes)
        return self.choices






if __name__ == '__main__':

    manager = FlowMultipathManager()


    choices = manager.start([1,2,3],[0.4,0.3, 0.3], 10,1)
    print(choices)

    choices = manager.start([1,2,3],[0.4,0.3, 0.3], 10,1)
    print(choices)

    choices = manager.start([1,2,3],[0.4,0.3, 0.3], 10,1)
    print(choices)