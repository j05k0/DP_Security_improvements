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


import Queue
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet, ipv6, ipv4, arp, in_proto, tcp, udp
from ryu.ofproto import ofproto_v1_4
from ryu import cfg
from dnn_module import DNNModule

queue = Queue.Queue()


class SimpleSwitch14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    # Defined numbers of tables
    TABLE_HOST_COUNT = 0
    TABLE_SERVICE_COUNT = 1
    TABLE_SWITCHING = 10

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch14, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stats = {}
        self.packet_ins = []

        # Get the input params from .conf file
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.IntOpt('REFRESH_RATE', default=10),
            cfg.IntOpt('FW_REFRESH_RATE', default=1),
            cfg.IntOpt('TIMEOUT', default=30),
            cfg.StrOpt('FLOWS_DUMP_FILE', default='../results/flows_default.dump'),
            cfg.StrOpt('DNN_MODEL', default='../models/DNN_model_all_binary.h5'),
            cfg.StrOpt('DNN_SCALER', default='../models/DNN_model_all_binary_scaler.sav')
        ])
        params = []
        params.append(CONF.REFRESH_RATE)
        params.append(CONF.FW_REFRESH_RATE)
        params.append(CONF.TIMEOUT)
        params.append(CONF.FLOWS_DUMP_FILE)
        params.append(CONF.DNN_MODEL)
        params.append(CONF.DNN_SCALER)

        # Initialize and start DNN module
        self.dnn_module = DNNModule(self, queue, params)
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
        # self.logger.info('[' + str(datapath.id) + ']: Flow successfully installed')
        # print '[', str(datapath.id), ']: Flow successfully installed'
        # print mod, '\n'

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

        # TODO IPv6 traffic should be switched off on hosts and switches
        # https://github.com/cchliu/SDN-Defense/blob/master/topo.py
        # Ignoring IPv6 traffic
        if ipv6_proto is not None:
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # print '*****************************************************************'
        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        # if ipv4_proto is not None:
        #     self.logger.info('%s %s\n', ipv4_proto.src, ipv4_proto.dst)
        # self.logger.info(pkt)
        # self.logger.info("")
        #self.logger.info(ipv4_proto)

        # print "packet in ", dpid, src, dst, in_port
        # print pkt
        # if ipv4_proto is not None:
            # print ipv4_proto.src, ipv4_proto.dst
            # print ipv4_proto

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # determine to which port should FW send the traffic
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            # self.logger.info('Forwarding packet to %s port on forwarder %s', self.mac_to_port[dpid][dst], dpid)
            # print 'Forwarding packet to', self.mac_to_port[dpid][dst], 'port on forwarder', dpid
        else:
            out_port = ofproto.OFPP_FLOOD
            # self.logger.info('Setting flooding flag on forwarder %s', dpid)
            # print 'Setting flooding flag on forwarder', dpid
        # self.logger.info('*****************************************************************')
        # print '*****************************************************************'

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if ipv4_proto is not None:
                # Save the first packet of the new flow
                self.packet_ins.append((dpid, pkt))

                # Add match to TABLE_HOST_COUNT for counting connections to hosts
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=ipv4_proto.dst)
                priority = 10
                inst = [parser.OFPInstructionGotoTable(self.TABLE_SERVICE_COUNT,
                                                       ofproto.OFPIT_GOTO_TABLE)]
                self.add_flow(datapath, priority, match, inst, self.TABLE_HOST_COUNT)

                if ipv4_proto.proto is in_proto.IPPROTO_TCP:
                    # Add match to TABLE_SERVICE_COUNT for counting connections to services
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=ipv4_proto.proto,
                        tcp_dst=tcp_proto.dst_port)
                    priority = 10
                    inst = [parser.OFPInstructionGotoTable(self.TABLE_SWITCHING,
                                                           ofproto.OFPIT_GOTO_TABLE)]
                    self.add_flow(datapath, priority, match, inst, self.TABLE_SERVICE_COUNT)

                    # self.logger.info(tcp_proto)
                    # self.logger.info("")
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=ipv4_proto.proto,
                        ipv4_src=ipv4_proto.src,
                        ipv4_dst=ipv4_proto.dst,
                        tcp_src=tcp_proto.src_port,
                        tcp_dst=tcp_proto.dst_port)
                    priority = 30
                elif ipv4_proto.proto is in_proto.IPPROTO_UDP:
                    # Add match to TABLE_SERVICE_COUNT for counting connections to services
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=ipv4_proto.proto,
                        udp_dst=udp_proto.dst_port)
                    priority = 10
                    inst = [parser.OFPInstructionGotoTable(self.TABLE_SWITCHING,
                                                           ofproto.OFPIT_GOTO_TABLE)]
                    self.add_flow(datapath, priority, match, inst, self.TABLE_SERVICE_COUNT)

                    # self.logger.info(udp_proto)
                    # self.logger.info("")
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=ipv4_proto.proto,
                        ipv4_src=ipv4_proto.src,
                        ipv4_dst=ipv4_proto.dst,
                        udp_src=udp_proto.src_port,
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
                # Save the first packet of the new flow
                self.packet_ins.append((dpid, pkt))
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_ARP,
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
        # self.logger.info("--------------------------------------------------------------")

    def send_port_stats_request(self, datapath):
        self.logger.info('[' + str(datapath.id) + ']: Requesting port stats...')
        # print '[' + str(datapath.id) + ']: Requesting port stats...'
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        ports = []
        dpid = ev.msg.datapath.id
        self.logger.info('[' + str(dpid) + ']: Received port stats')
        ofp = ev.msg.datapath.ofproto
        for stat in ev.msg.body:
            if stat.port_no is not ofp.OFPP_ANY:
                ports.append(stat.port_no)
        queue.put((ev.msg.datapath, ports))

    def send_flow_stats_request(self, datapath, in_port):
        self.logger.info('[' + str(datapath.id) + ']: Requesting flow stats...')
        # print '[' + str(datapath.id) + ']: Requesting flow stats...'
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch(in_port=in_port)
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
        self.logger.info('[' + str(dpid) + ']: Received flow stats')
        # print '[' + str(dpid) + ']: Received flow stats:'
        # flows = []
        self.stats.setdefault(dpid, {})
        in_port = 0
        for stat in ev.msg.body:
            # self.logger.info(stat)
            # self.logger.info('***************************************************************')
            in_port = stat.match['in_port']
            if in_port not in self.stats[dpid]:
                self.stats[dpid][in_port] = [stat]
            else:
                self.stats[dpid][in_port].append(stat)
            # print stat.stats
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
        queue.put((ev.msg.datapath, in_port))
        # self.logger.debug('FlowStats: %s', flows)

    def get_stats(self):
        return self.stats

    def clear_stats(self):
        self.stats = {}

    def clear_counters(self, datapath):
        stats = self.stats
        for dpid in stats:
            if dpid == datapath.id:
                for in_port in stats[dpid]:
                    for idx in range(0, len(stats[dpid][in_port])):
                        stat = stats[dpid][in_port][idx]
                        parser = datapath.ofproto_parser
                        ofproto = datapath.ofproto
                        mod = parser.OFPFlowMod(datapath=datapath,
                                                table_id=stat.table_id,
                                                command=ofproto.OFPFC_MODIFY_STRICT,
                                                priority=stat.priority,
                                                flags=ofproto.OFPFF_RESET_COUNTS,
                                                match=stat.match,
                                                instructions=stat.instructions)
                        datapath.send_msg(mod)
                self.logger.info('[' + str(datapath.id) + ']: Counters reset done')
