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
import datetime
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet, ipv6, ipv4, arp, in_proto, tcp, udp
from ryu.ofproto import ofproto_v1_3
from ryu import cfg
from dnn_module import DNNModule

queue = Queue.Queue()


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Defined numbers of tables
    TABLE_HOST_COUNT = 0
    TABLE_SERVICE_COUNT = 1
    TABLE_SWITCHING = 10

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stats = {}
        self.packet_ins = []

        # Get the input params from .conf file
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.BoolOpt('ENABLED', default=True),
            cfg.IntOpt('REFRESH_RATE', default=10),
            cfg.IntOpt('FW_REFRESH_RATE', default=1),
            cfg.IntOpt('TIMEOUT', default=30),
            cfg.StrOpt('FLOWS_DUMP_FILE', default='../results/flows_default.dump'),
            cfg.StrOpt('DNN_MODEL', default='../models/DNN_model_all_binary.h5'),
            cfg.StrOpt('DNN_SCALER', default='../models/DNN_model_all_binary_scaler.sav'),
            cfg.ListOpt('NORMAL', default=[0, 0.5]),
            cfg.ListOpt('WARNING', default=[0.5, 0.8]),
            cfg.ListOpt('BEST_EFFORT', default=[0.8, 0.95]),
            cfg.ListOpt('ATTACK', default=[0.95, 1]),
            cfg.ListOpt('METER_RATES', default=[1000, 100, 0]),
            cfg.ListOpt('METER_BURST_SIZES', default=[10, 10, 0]),
            cfg.ListOpt('METER_FLAGS', default=['KBPS', 'KBPS', 'KBPS']),
            cfg.BoolOpt('PREVENTION', default=True)
        ])
        params = [CONF.REFRESH_RATE, CONF.FW_REFRESH_RATE, CONF.TIMEOUT, CONF.FLOWS_DUMP_FILE, CONF.DNN_MODEL,
                  CONF.DNN_SCALER, CONF.NORMAL, CONF.WARNING, CONF.BEST_EFFORT, CONF.ATTACK, CONF.PREVENTION]

        self.DNN_MODULE_ENABLED = CONF.ENABLED
        self.METER_RATES = []
        self.METER_BURST_SIZES = []
        self.METER_FLAGS = CONF.METER_FLAGS

        # Converting meter rates and burst sizes loaded from params file into integers
        for i in range(len(CONF.METER_RATES)):
            self.METER_RATES.append(int(CONF.METER_RATES[i]))

        for i in range(len(CONF.METER_BURST_SIZES)):
            self.METER_BURST_SIZES.append(int(CONF.METER_BURST_SIZES[i]))

        if self.DNN_MODULE_ENABLED:
            # Initialize and start DNN module
            self.logger.info('DNN module is enabled')
            self.dnn_module = DNNModule(self, queue, params)
            self.dnn_module.start()
        else:
            self.logger.info('DNN module is disabled')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if self.DNN_MODULE_ENABLED:
            # Somehow the forwarders change their ID during operation this is hack to workaround this
            for fw in self.dnn_module.forwarders:
                if fw.id == datapath.id:
                    self.dnn_module.forwarders.pop(fw)
                    break
            self.dnn_module.forwarders[datapath] = []

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

        flags = []
        for i in range(len(self.METER_FLAGS)):
            if self.METER_FLAGS[i] == 'KBPS':
                flags.append(ofproto.OFPMF_KBPS)
            elif self.METER_FLAGS[i] == 'PKTPS':
                flags.append(ofproto.OFPMF_PKTPS)
            else:
                self.logger.info('Unknown meter flag used. Setting default value KBPS')
                flags.append(ofproto.OFPMF_KBPS)

        # Install meter table's entries
        # Meter rate for WARNING class
        # print self.METER_RATES

        bands = [parser.OFPMeterBandDrop(rate=self.METER_RATES[0],
                                         burst_size=self.METER_BURST_SIZES[0])]
        msg = parser.OFPMeterMod(datapath=datapath,
                                 command=ofproto.OFPMC_ADD,
                                 flags=flags[0],
                                 meter_id=1,
                                 bands=bands)
        datapath.send_msg(msg)

        # Meter for BEST_EFFORT class
        bands = [parser.OFPMeterBandDrop(rate=self.METER_RATES[1],
                                         burst_size=self.METER_BURST_SIZES[1])]
        msg = parser.OFPMeterMod(datapath=datapath,
                                 command=ofproto.OFPMC_ADD,
                                 flags=flags[1],
                                 meter_id=2,
                                 bands=bands)
        datapath.send_msg(msg)

        # Meter for ATTACK class
        bands = [parser.OFPMeterBandDrop(rate=self.METER_RATES[2],
                                         burst_size=self.METER_BURST_SIZES[2])]
        msg = parser.OFPMeterMod(datapath=datapath,
                                 command=ofproto.OFPMC_ADD,
                                 flags=flags[2],
                                 meter_id=3,
                                 bands=bands)
        datapath.send_msg(msg)

        self.send_meter_stats_request(datapath)

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

        # Save the first packet of the new flow
        # HACK Save only packet_ins from FW2 to skip unifying of packet_ins which could take long in case of big PCAP replayed
        if dpid == 2:
            self.packet_ins.append((dpid, pkt))

        if not self.DNN_MODULE_ENABLED:
            if dpid == 2:
                self.logger.info('*****************************************************************')
                self.logger.info(self.current_timestamp() + " packet in %s %s %s %s", dpid, src, dst, in_port)
                if ipv4_proto is not None:
                    self.logger.info('%s %s\n', ipv4_proto.src, ipv4_proto.dst)
                # self.logger.info(pkt)
                # self.logger.info("")
                # self.logger.info(ipv4_proto)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # determine to which port should FW send the traffic
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            # if dpid == 2:
            #     self.logger.info('Forwarding packet to %s port on forwarder %s', self.mac_to_port[dpid][dst], dpid)
        else:
            out_port = ofproto.OFPP_FLOOD
            # if dpid == 2:
            #     self.logger.info('Setting flooding flag on forwarder %s', dpid)
        # self.logger.info('*****************************************************************')

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if ipv4_proto is not None:
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

                    # Prepare match for TABLE_SWITCHING
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

                    # Prepare match for TABLE_SWITCHING
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
                    # Prepare match for TABLE_SWITCHING
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=ipv4_proto.proto,
                        ipv4_src=ipv4_proto.src,
                        ipv4_dst=ipv4_proto.dst)
                    priority = 20
            elif arp_proto is not None:
                # Prepare match for TABLE_SWITCHING
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_ARP,
                    arp_spa=arp_proto.src_ip,
                    arp_tpa=arp_proto.dst_ip)
                priority = 10
            else:
                # Prepare match for TABLE_SWITCHING
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
            if stat.port_no != ofp.OFPP_LOCAL:
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
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        self.logger.info('[' + str(dpid) + ']: Received flow stats')
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

            # Clear counters for the particular stat in the forwarder
            # TODO This could be done with delta - you must save the old flows for comparision
            self.clear_counters(datapath, stat)

        # Checking whether there are not multiple packets for one reply (e.g. too large reply is sent in multiple packets)
        if ev.msg.flags == ofproto.OFPMPF_REPLY_MORE:
            self.logger.info('More flow stats replies are expected from port ' + str(in_port))
        else:
            if in_port == 0:
                self.logger.info('No flow stats received')
            else:
                self.logger.info('Number of received stats ' + str(len(self.stats[dpid][in_port])) + ' from port ' + str(in_port))
            queue.put((ev.msg.datapath, in_port))

    def send_meter_stats_request(self, datapath):
        protocol = datapath.ofproto
        parser = datapath.ofproto_parser
        request = parser.OFPMeterStatsRequest(datapath, 0, protocol.OFPM_ALL)
        datapath.send_msg(request)

    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
    def meter_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        meters = []
        for stat in ev.msg.body:
            meters.append('meter_id=0x%08x len=%d flow_count=%d '
                          'packet_in_count=%d byte_in_count=%d '
                          'duration_sec=%d duration_nsec=%d '
                          'band_stats=%s' %
                          (stat.meter_id, stat.len, stat.flow_count,
                           stat.packet_in_count, stat.byte_in_count,
                           stat.duration_sec, stat.duration_nsec,
                           stat.band_stats))
        self.logger.info('MeterStats of %d: %s', datapath.id, meters)
        # self.send_meter_stats_request(datapath)

    def get_stats(self):
        return self.stats

    def clear_stats(self):
        self.stats = {}

    def clear_counters(self, datapath, stat):
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
        # self.logger.info('[' + str(datapath.id) + ']: Counters reset done')

    def apply_meter(self, datapath, params, meter_id):
        stats = self.stats
        for dpid in stats:
            if dpid == datapath.id:
                for in_port in stats[dpid]:
                    for idx in range(len(stats[dpid][in_port])):
                        stat = stats[dpid][in_port][idx]
                        if (stat.table_id == self.TABLE_SWITCHING
                                and stat.match['eth_type'] == params['eth_type']):
                            if stat.match['eth_type'] == ether_types.ETH_TYPE_IP:
                                if stat.match['ip_proto'] == params['proto']:
                                    if stat.match['ip_proto'] == in_proto.IPPROTO_TCP:
                                        if (stat.match['ipv4_src'] == params['ipv4_src']
                                                and stat.match['ipv4_dst'] == params['ipv4_dst']
                                                and stat.match['tcp_src'] == params['port_src']
                                                and stat.match['tcp_dst'] == params['port_dst']):
                                            parser = datapath.ofproto_parser
                                            ofproto = datapath.ofproto
                                            stat.instructions.append(parser.OFPInstructionMeter(meter_id,
                                                                                                ofproto.OFPIT_METER))
                                            # self.logger.info('[' + str(dpid) + ']: Applying meter: ' + stat.instructions)
                                            mod = parser.OFPFlowMod(datapath=datapath,
                                                                    table_id=stat.table_id,
                                                                    command=ofproto.OFPFC_MODIFY_STRICT,
                                                                    priority=stat.priority,
                                                                    match=stat.match,
                                                                    instructions=stat.instructions)
                                            datapath.send_msg(mod)
                                            return
                                    elif stat.match['ip_proto'] == in_proto.IPPROTO_UDP:
                                        if (stat.match['ipv4_src'] == params['ipv4_src']
                                                and stat.match['ipv4_dst'] == params['ipv4_dst']
                                                and stat.match['udp_src'] == params['port_src']
                                                and stat.match['udp_dst'] == params['port_dst']):
                                            parser = datapath.ofproto_parser
                                            ofproto = datapath.ofproto
                                            stat.instructions.append(parser.OFPInstructionMeter(meter_id,
                                                                                                ofproto.OFPIT_METER))
                                            mod = parser.OFPFlowMod(datapath=datapath,
                                                                    table_id=stat.table_id,
                                                                    command=ofproto.OFPFC_MODIFY_STRICT,
                                                                    priority=stat.priority,
                                                                    match=stat.match,
                                                                    instructions=stat.instructions)
                                            datapath.send_msg(mod)
                                            return
                                    else:
                                        if (stat.match['ipv4_src'] == params['ipv4_src']
                                                and stat.match['ipv4_dst'] == params['ipv4_dst']):
                                            parser = datapath.ofproto_parser
                                            ofproto = datapath.ofproto
                                            stat.instructions.append(parser.OFPInstructionMeter(meter_id,
                                                                                                ofproto.OFPIT_METER))
                                            mod = parser.OFPFlowMod(datapath=datapath,
                                                                    table_id=stat.table_id,
                                                                    command=ofproto.OFPFC_MODIFY_STRICT,
                                                                    priority=stat.priority,
                                                                    match=stat.match,
                                                                    instructions=stat.instructions)
                                            datapath.send_msg(mod)
                                            return
                            elif stat.match['eth_type'] == ether_types.ETH_TYPE_ARP:
                                if (stat.match['arp_spa'] == params['ipv4_src']
                                        and stat.match['arp_tpa'] == params['ipv4_dst']):
                                    parser = datapath.ofproto_parser
                                    ofproto = datapath.ofproto
                                    stat.instructions.append(parser.OFPInstructionMeter(meter_id,
                                                                                        ofproto.OFPIT_METER))
                                    mod = parser.OFPFlowMod(datapath=datapath,
                                                            table_id=stat.table_id,
                                                            command=ofproto.OFPFC_MODIFY_STRICT,
                                                            priority=stat.priority,
                                                            match=stat.match,
                                                            instructions=stat.instructions)
                                    datapath.send_msg(mod)
                                    return
                            else:
                                # self.logger.info('[Controller] We have matched this:')
                                # self.logger.info(stat)
                                if stat.match['eth_dst'] == params['eth_dst']:
                                    parser = datapath.ofproto_parser
                                    ofproto = datapath.ofproto
                                    stat.instructions.append(parser.OFPInstructionMeter(meter_id,
                                                                                        ofproto.OFPIT_METER))
                                    mod = parser.OFPFlowMod(datapath=datapath,
                                                            table_id=stat.table_id,
                                                            command=ofproto.OFPFC_MODIFY_STRICT,
                                                            priority=stat.priority,
                                                            match=stat.match,
                                                            instructions=stat.instructions)
                                    datapath.send_msg(mod)
                                    return

    # Deprecated
    def block_host(self, datapath, in_port, ipv4_src):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        match = parser.OFPMatch(in_port=in_port,
                                eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=ipv4_src)
        priority = 50
        mod = parser.OFPFlowMod(datapath=datapath,
                                table_id=self.TABLE_SWITCHING,
                                match=match,
                                command=ofproto.OFPFC_ADD,
                                priority=priority,
                                instructions=inst)
        datapath.send_msg(mod)

    def current_timestamp(self):
        return datetime.datetime.fromtimestamp(time.time()).strftime('%d-%m-%Y %H:%M:%S')