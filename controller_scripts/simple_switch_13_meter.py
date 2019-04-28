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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("METER: Handler = Switch Features: enter!")
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

        self.meteradd(datapath, 1)

        self.send_meter_stats_request(datapath)
        self.send_meter_config_stats_request(datapath)
        self.send_meter_features_stats_request(datapath)

        self.logger.info("METER: Handler = Switch Features: leave!")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def meteradd(self, datapath, meter_id):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        bands = [parser.OFPMeterBandDrop(type_=ofproto.OFPMBT_DROP,
                                         len_=0,
                                         rate=1000,
                                         burst_size=10)]
        modification = parser.OFPMeterMod(datapath=datapath,
                                          command=ofproto.OFPMC_ADD,
                                          flags=ofproto.OFPMF_KBPS,
                                          meter_id=meter_id,
                                          bands=bands)
        datapath.send_msg(modification)

    def send_meter_features_stats_request(self, datapath):
        parser = datapath.ofproto_parser
        request = parser.OFPMeterFeaturesStatsRequest(datapath, 0)
        datapath.send_msg(request)

    def send_meter_config_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPMeterConfigStatsRequest(datapath, 0, ofp.OFPM_ALL)
        datapath.send_msg(req)

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
        self.logger.info('MeterStats: %s', meters)
        # self.send_meter_stats_request(datapath)

    @set_ev_cls(ofp_event.EventOFPMeterConfigStatsReply, MAIN_DISPATCHER)
    def meter_config_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        configs = []
        for stat in ev.msg.body:
            configs.append('length=%d flags=0x%04x meter_id=0x%08x '
                           'bands=%s' %
                           (stat.length, stat.flags, stat.meter_id,
                            stat.bands))
        self.logger.info('MeterConfigStats: %s', configs)
        # self.send_meter_config_stats_request(datapath)

    @set_ev_cls(ofp_event.EventOFPMeterFeaturesStatsReply, MAIN_DISPATCHER)
    def meter_features_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        features = []
        for stat in ev.msg.body:
            features.append('max_meter=%d band_types=0x%08x '
                            'capabilities=0x%08x '
                            'max_color=%d' %
                            (stat.max_meter, stat.band_types,
                             stat.capabilities,
                             stat.max_color))
        self.logger.info('MeterFeaturesStats: %s', features)
        # self.send_meter_features_stats_request(datapath)