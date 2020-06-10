from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4, oxm_fields
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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Cisco Reference bandwidth = 1 Gbps
REFERENCE_BW = 10000000
DEFAULT_BW = 10000000

MAX_PATHS = 10


class TestSDNControllerApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TestSDNControllerApp, self).__init__(*args, **kwargs)

    @staticmethod
    def add_flow(datapath, priority, match, actions, buffer_id=None, hard_timeout=0, flags=0, table=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if flags == 0:
            flags = ofproto.OFPFF_SEND_FLOW_REM

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, hard_timeout=hard_timeout, flags=flags, table_id=table)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, hard_timeout=hard_timeout, flags=flags,
                                    table_id=table)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        reg = oxm_fields.NiciraExtended1('reg0', 0, type_desc.Int4),
        actions_x = [parser.NXActionMultipath(fields=nicira_ext.NX_HASH_FIELDS_SYMMETRIC_L4,
                                              basis=1024,
                                              algorithm=nicira_ext.NX_MP_ALG_HRW,
                                              max_link=1,
                                              arg=0,
                                              ofs_nbits=nicira_ext.ofs_nbits(0, 31),
                                              dst="reg0")]

        actions_x.append(parser.NXActionResubmitTable(in_port=8080, table_id=10))
        self.add_flow(datapath, 999, match, actions_x, table=0)

        actions = [parser.NXActionOutputReg(ofs_nbits=nicira_ext.ofs_nbits(0, 31), src="reg0", max_len=2048)]
        learn_action = parser.NXActionLearn(
            table_id=15,
            specs=[
                # Match
                parser.NXFlowSpecMatch(
                    src=('eth_type_nxm', 16),
                    dst=('eth_type', 0),
                    n_bits=16,
                ),
                parser.NXFlowSpecMatch(
                    src=("ip_proto_nxm", 8),
                    dst=('ip_proto', 0),
                    n_bits=8,
                ),

                # Actions
                parser.NXFlowSpecLoad(
                    src=('reg6', 0),
                    dst=('reg7', 0),
                    n_bits=32,
                ),
            ],
            fin_idle_timeout=1,
            fin_hard_timeout=1,
        )

        actions.append(learn_action)
        self.add_flow(datapath, 999, match, actions, table=10)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        pass