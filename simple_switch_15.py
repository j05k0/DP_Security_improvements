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

import thread
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet, ipv6, ipv4, arp, in_proto, tcp, udp
from ryu.ofproto import ofproto_v1_5


class SimpleSwitch15(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch15, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        thread.start_new_thread(self.send_flow_stats_request, (datapath,))
        #thread.start_new_thread(self.send_port_stats_request, (datapath,))

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("Flow successfully installed\n")

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
                if ipv4_proto.proto is in_proto.IPPROTO_TCP:
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
                    self.logger.info(udp_proto)
                    self.logger.info("")
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=ipv4_proto.proto,
                        ipv4_src=ipv4_proto.src,
                        ipv4_dst=ipv4_proto.dst,
                        udp_dst=tcp_proto.dst_port)
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

            self.add_flow(datapath, priority, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        match = parser.OFPMatch(in_port=in_port)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                 match=match, actions=actions, data=data)

        datapath.send_msg(out)
        self.logger.info("--------------------------------------------------------------")

    def send_flow_stats_request(self, datapath):
        print '[' + str(datapath.id) + ']: Thread started'
        while 1:
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
            print req
            print '-------------------------------------------------------------------------'
            datapath.send_msg(req)
            req = ofp_parser.OFPFlowStatsRequest(datapath)
            print req
            datapath.send_msg(req)
            time.sleep(10)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        print '[' + str(ev.msg.datapath.id) + ']: Received flow stats:'
        flows = []
        for stat in ev.msg.body:
            flows.append('table_id=%s '
                         'duration_sec=%d duration_nsec=%d '
                         'priority=%d '
                         'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                         'importance=%d cookie=%d packet_count=%d '
                         'byte_count=%d match=%s instructions=%s' %
                         (stat.table_id,
                          stat.duration_sec, stat.duration_nsec,
                          stat.priority,
                          stat.idle_timeout, stat.hard_timeout,
                          stat.flags, stat.importance,
                          stat.cookie, stat.packet_count, stat.byte_count,
                          stat.match, stat.instructions))

        self.logger.debug('FlowStats: %s', flows)

    def send_port_stats_request(self, datapath):
        print '[' + str(datapath.id) + ']: Thread started'
        while 1:
            time.sleep(10)
            print '[' + str(datapath.id) + ']: Requesting flow stats...'
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
            datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        ports = []
        for stat in ev.msg.body:
            print stat
            print '-----------------------------------------------------------------'
            # ports.append(stat.length, stat.port_no,
            #              stat.duration_sec, stat.duration_nsec,
            #              stat.rx_packets, stat.tx_packets,
            #              stat.rx_bytes, stat.tx_bytes,
            #              stat.rx_dropped, stat.tx_dropped,
            #              stat.rx_errors, stat.tx_errors,
            #              repr(stat.properties))
        self.logger.debug('PortStats: %s', ports)
