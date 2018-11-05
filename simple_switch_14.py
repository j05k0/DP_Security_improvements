# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import time
import Queue

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet, ipv6, ipv4, arp, in_proto, tcp, udp
from ryu.ofproto import ofproto_v1_4
from dnn_module import DNNModule

queue = Queue.Queue()

class SimpleSwitch14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    # Defined numbers of tables
    TABLE_HOST_COUNT = 0
    TABLE_SERVICE_COUNT = 1
    TABLE_SWITCHING = 10

    # Refresh rate defines how often is called DNN module (seconds)
    REFRESH_RATE = 10
    FW_REFRESH_RATE = 1  # TODO maybe this time will cause a bug if there are multiple forwarders (ask Rudo)

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch14, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stats = {}

        # Initialize and start DNN module
        self.dnn_module = DNNModule(self, queue)
        self.dnn_module.start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        queue.put(datapath)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(self.TABLE_SERVICE_COUNT,
                                               ofproto.OFPIT_GOTO_TABLE)]
        self.add_flow(datapath, 0, match, inst, self.TABLE_HOST_COUNT)

        inst = [parser.OFPInstructionGotoTable(self.TABLE_SWITCHING,
                                               ofproto.OFPIT_GOTO_TABLE)]
        self.add_flow(datapath, 0, match, inst, self.TABLE_SERVICE_COUNT)

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 0, match, inst, self.TABLE_SWITCHING)

    def add_flow(self, datapath, priority, match, inst, table_id):
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,
                                table_id=table_id,
                                priority=priority,
                                match=match,
                                instructions=inst)
        datapath.send_msg(mod)
        self.logger.info('[' + str(datapath.id) + ']: Flow successfully installed')

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv6_proto = pkt.get_protocol(ipv6.ipv6)
        ipv4_proto = pkt.get_protocol(ipv4.ipv4)
        arp_proto = pkt.get_protocol(arp.arp)
        tcp_proto = pkt.get_protocol(tcp.tcp)
        udp_proto = pkt.get_protocol(udp.udp)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        # Ignoring IPv6 traffic
        if ipv6_proto is not None:
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s\n", dpid, src, dst, in_port)
        self.logger.info(pkt)
        self.logger.info("")
        self.logger.info(ipv4_proto)
        self.logger.info("")

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # determine to which port should FW send the traffic
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if ipv4_proto is not None:
                # Add match to table 0 for counting connections to hosts
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=ipv4_proto.dst)
                priority = 10
                inst = [parser.OFPInstructionGotoTable(self.TABLE_SERVICE_COUNT,
                                                       ofproto.OFPIT_GOTO_TABLE)]
                self.add_flow(datapath, priority, match, inst, self.TABLE_HOST_COUNT)

                if ipv4_proto.proto is in_proto.IPPROTO_TCP:
                    # Add match to table 1 for counting connections to services
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=ipv4_proto.proto,
                        tcp_dst=tcp_proto.dst_port)
                    priority = 10
                    inst = [parser.OFPInstructionGotoTable(self.TABLE_SWITCHING,
                                                           ofproto.OFPIT_GOTO_TABLE)]
                    self.add_flow(datapath, priority, match, inst, self.TABLE_SERVICE_COUNT)

                    self.logger.info(tcp_proto)
                    self.logger.info("")
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=ipv4_proto.proto,
                        ipv4_src=ipv4_proto.src,
                        ipv4_dst=ipv4_proto.dst,
                        tcp_dst=tcp_proto.dst_port)
                    priority = 30
                elif ipv4_proto.proto is in_proto.IPPROTO_UDP:
                    # Add match to table 1 for counting connections to services
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=ipv4_proto.proto,
                        udp_dst=udp_proto.dst_port)
                    priority = 10
                    inst = [parser.OFPInstructionGotoTable(self.TABLE_SWITCHING,
                                                           ofproto.OFPIT_GOTO_TABLE)]
                    self.add_flow(datapath, priority, match, inst, self.TABLE_SERVICE_COUNT)

                    self.logger.info(udp_proto)
                    self.logger.info("")
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=ipv4_proto.proto,
                        ipv4_src=ipv4_proto.src,
                        ipv4_dst=ipv4_proto.dst,
                        udp_dst=udp_proto.dst_port)
                    priority = 30
                else:
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=ipv4_proto.proto,
                        ipv4_src=ipv4_proto.src,
                        ipv4_dst=ipv4_proto.dst)
                    priority = 20
            elif arp_proto is not None:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_ARP,
                    arp_op=arp_proto.opcode,
                    arp_spa=arp_proto.src_ip,
                    arp_tpa=arp_proto.dst_ip)
                priority = 10
            else:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_dst=dst)
                priority = 1

            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self.add_flow(datapath, priority, match, inst, self.TABLE_SWITCHING)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        datapath.send_msg(out)
        self.logger.info("--------------------------------------------------------------")

    def send_flow_stats_request(self, datapath):
        print '[' + str(datapath.id) + ']: Requesting flow stats...'
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch(in_port=1)
        req = ofp_parser.OFPFlowStatsRequest(datapath=datapath,
                                             flags=0,
                                             table_id=ofp.OFPTT_ALL,
                                             out_port=ofp.OFPP_ANY,
                                             out_group=ofp.OFPG_ANY,
                                             cookie=cookie,
                                             cookie_mask=cookie_mask,
                                             match=match)
        datapath.send_msg(req)
        match = ofp_parser.OFPMatch(in_port=2)
        req = ofp_parser.OFPFlowStatsRequest(datapath=datapath,
                                             flags=0,
                                             table_id=ofp.OFPTT_ALL,
                                             out_port=ofp.OFPP_ANY,
                                             out_group=ofp.OFPG_ANY,
                                             cookie=cookie,
                                             cookie_mask=cookie_mask,
                                             match=match)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        print '[' + str(dpid) + ']: Received flow stats:'
        # flows = []
        self.stats.setdefault(dpid, {})
        for stat in ev.msg.body:
            # self.logger.info(stat)
            # self.logger.info('***************************************************************')
            in_port = stat.match['in_port']
            if in_port not in self.stats[dpid]:
                self.stats[dpid][in_port] = [stat]
            else:
                self.stats[dpid][in_port].append(stat)
            # flows.append('table_id=%s '
            #              'duration_sec=%d duration_nsec=%d '
            #              'priority=%d '
            #              'idle_timeout=%d hard_timeout=%d flags=0x%04x '
            #              'importance=%d cookie=%d packet_count=%d '
            #              'byte_count=%d match=%s instructions=%s' %
            #              (stat.table_id,
            #               stat.duration_sec, stat.duration_nsec,
            #               stat.priority,
            #               stat.idle_timeout, stat.hard_timeout,
            #               stat.flags, stat.importance,
            #               stat.cookie, stat.packet_count, stat.byte_count,
            #               stat.match, stat.instructions))

        # self.logger.debug('FlowStats: %s', flows)

    def flow_stats_parser(self):
        parsed_flows = {}
        for sw_id in self.stats:
            print 'Switch ' + str(sw_id) + ':'
            for port in self.stats[sw_id]:
                print 'Input port ' + str(port) + ':'
                for idx in range(0, len(self.stats[sw_id][port])):
                    print self.stats[sw_id][port][idx]
                    print '************************************************************'
                print '************************************************************'
            print '************************************************************'
        for sw_id in self.stats:
            for port in self.stats[sw_id]:
                for idx in range(0, len(self.stats[sw_id][port])):
                    stat = self.stats[sw_id][port][idx]
        # TODO determine where I should run this function.
        # Running it inside a thread for switch is probably not a good idea
        self.stats = {}
