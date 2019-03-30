import threading
import time
from ryu.lib.packet import ether_types, in_proto, ipv4, arp, tcp, udp
import keras
import tensorflow as tf
from keras.models import load_model
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.externals import joblib


class DNNModule(threading.Thread):
    ARP_PROTO = -1
    FLOWS_DUMP_FILE = '../results/flows_dump.txt'

    def __init__(self, controller, queue):
        super(DNNModule, self).__init__()
        self.forwarders = {}
        self.controller = controller
        self.queue = queue
        try:
            self.model = load_model('../models/DNN_model_all_binary.h5')
            self.scaler = joblib.load('../models/DNN_model_all_binary_scaler.sav')
            self.model._make_predict_function()
            self.graph = tf.get_default_graph()
            self.controller.logger.info('[DNN module] DNN module initialized')
            # print '[DNN module] DNN module initialized'
        except Exception as e:
            self.controller.logger.info('[DNN module] DNN module failed to initialize')
            # print '[DNN module] DNN module failed to initialize'
            self.controller.logger.info(e)
            # print e

    def run(self):
        # TODO possible change to networkx and digraph
        # Open dump file and add the first line - column names
        with open(self.FLOWS_DUMP_FILE, 'w') as f:
            f.write(
                'ipv4_src,port_src,ipv4_dst,port_dst,proto,bytes_src,bytes_dst,packets_src,packets_dst,srv_dst_count,'
                'dst_count,category,probability\n')
        while 1:
            if self.get_forwarders():
                while 1:
                    # print '[DNN module] Starting new iteration...'
                    self.controller.logger.info('[DNN module] Starting new iteration...')
                    record_count = 0
                    if self.update_forwarders():
                        for fw in self.forwarders:
                            for port in self.forwarders[fw]:
                                self.controller.send_flow_stats_request(fw, port)
                                record_count += 1
                        self.wait_for_items_in_queue()
                        if self.queue.qsize() == record_count:
                            stats = self.controller.get_stats()
                            if self.print_flow_stats(stats):
                                try:
                                    parsed_flows = self.flow_stats_parser(stats)
                                    try:
                                        if len(parsed_flows) > 0:
                                            scaled_samples = self.preprocess_flows(parsed_flows)
                                            self.evaluate_samples(scaled_samples, parsed_flows)
                                        else:
                                            self.controller.logger.info('[DNN module] No flow stats available')
                                    except Exception as e:
                                        self.controller.logger.info(
                                            '[DNN module] Exception during evaluation process. Operation will continue in the next iteration.')
                                        self.controller.logger.info(e)
                                        # print '[DNN module] Exception during evaluation process. Operation will continue in the next iteration.'
                                        # print e
                                except Exception as e:
                                    self.controller.logger.info(
                                        '[DNN module] Exception during parsing flow stats. Operation will continue in the next iteration.')
                                    self.controller.logger.info(e)
                                    # print '[DNN module] Exception during parsing flow stats. Operation will continue in the next iteration.'
                                    # print e
                            else:
                                self.controller.logger.info('[DNN module] No flow stats available')
                                # print '[DNN module] No flow stats available'
                        else:
                            self.controller.logger.info('[DNN module] Wrong number of flow stats replies received')
                            self.controller.logger.info('[DNN module] Record count is %s', record_count)
                            self.controller.logger.info('[DNN module] Size of the queue is %s', self.queue.qsize())
                            # print '[DNN module] Wrong number of flow stats replies received'
                            # print '[DNN module] Record count is ', record_count
                            # print '[DNN module] Size of the queue is ', self.queue.qsize()
                    else:
                        self.controller.logger.info(
                            '[DNN module] An error occured during updating forwarders. Skipping requesting of flow stats.')
                        # print '[DNN module] An error occured during updating forwarders. Skipping requesting of flow stats.'

                    self.clear_queue()
                    if self.controller.mac_to_port != {}:
                        self.controller.logger.info('[DNN module] Actual MAC to port table:')
                        # print '[DNN module] Actual MAC to port table:'
                        for sw_id in self.controller.mac_to_port:
                            self.controller.logger.info('Switch ' + str(sw_id) + ':')
                            # print 'Switch ' + str(sw_id) + ':'
                            for dst in self.controller.mac_to_port[sw_id]:
                                self.controller.logger.info('%s %s', dst, self.controller.mac_to_port[sw_id][dst])
                                # print dst, self.controller.mac_to_port[sw_id][dst]
                    for fw in self.forwarders:
                        self.controller.clear_counters(fw)
                    self.controller.clear_stats()
                    self.controller.packet_ins = []
                    self.controller.logger.info('[DNN module] Iteration done.')
                    self.controller.logger.info('************************************************************')
                    # print '[DNN module] Iteration done.'
                    # print '************************************************************'
                    time.sleep(self.controller.REFRESH_RATE)

            else:
                self.controller.logger.info(
                    '[DNN module] An error occured during getting forwarders. Skipping requesting of flow stats.')
                # print '[DNN module] An error occured during getting forwarders. Skipping requesting of flow stats.'

            time.sleep(self.controller.REFRESH_RATE)

    def get_forwarders(self):
        self.controller.logger.info('[DNN module] Waiting for forwarders...')
        # print '[DNN module] Waiting for forwarders...'
        self.wait_for_items_in_queue()

        try:
            self.controller.logger.info('[DNN module] Getting datapaths of the forwarders...')
            # print '[DNN module] Getting datapaths of the forwarders...'
            while not self.queue.empty():
                self.forwarders[self.queue.get()] = []
            return True
        except Exception as e:
            self.controller.logger.info(e)
            return False

    def update_forwarders(self):
        self.controller.logger.info('[DNN module] Updating the status of the forwarders...')
        self.controller.logger.info('[DNN module] Getting active ports of the forwarders...')
        # print '[DNN module] Updating the status of the forwarders...'
        # print '[DNN module] Getting active ports of the forwarders...'
        record_count = 0
        for fw in self.forwarders:
            self.controller.logger.info('[DNN module] Datapath: %s', fw)
            # print '[DNN module] Datapath: ', fw
            self.controller.send_port_stats_request(fw)
            record_count += 1
        self.wait_for_items_in_queue()
        if self.queue.qsize() == record_count:
            while not self.queue.empty():
                datapath, ports = self.queue.get()
                self.forwarders[datapath] = ports
            self.controller.logger.info('[DNN module] Forwarders: %s', self.forwarders)
            # print '[DNN module] Forwarders: ', self.forwarders
            return True
        self.controller.logger.info('[DNN module] Wrong number of port stats replies received')
        self.controller.logger.info('[DNN module] Record count is %s', record_count)
        self.controller.logger.info('[DNN module] Size of the queue is %s', self.queue.qsize())
        # print '[DNN module] Wrong number of port stats replies received'
        # print '[DNN module] Record count is ', record_count
        # print '[DNN module] Size of the queue is ', self.queue.qsize()
        return False

    def wait_for_items_in_queue(self):
        while self.queue.empty():
            time.sleep(self.controller.FW_REFRESH_RATE)

    def clear_queue(self):
        while not self.queue.empty():
            self.queue.get()

    def print_flow_stats(self, stats):
        if stats == {}:
            return False
        is_stats = False
        for sw_id in stats:
            if stats[sw_id] != {}:
                is_stats = True
            self.controller.logger.info('Switch ' + str(sw_id) + ':')
            # print 'Switch ' + str(sw_id) + ':'
            for port in stats[sw_id]:
                # if len(stats[sw_id][port]) == 0:
                #     return False
                self.controller.logger.info('Input port ' + str(port) + ':')
                # print 'Input port ' + str(port) + ':'
                for idx in range(0, len(stats[sw_id][port])):
                    self.controller.logger.info(stats[sw_id][port][idx])
                    self.controller.logger.info('************************************************************')
                    # print stats[sw_id][port][idx]
                    # print '************************************************************'
                self.controller.logger.info('************************************************************')
                # print '************************************************************'
            self.controller.logger.info('************************************************************')
            # print '************************************************************'
        return is_stats

    def print_flows(self, flows):
        for idx in range(0, len(flows)):
            self.controller.logger.info(flows[idx])
            self.controller.logger.info('************************************************************')
            # print flows[idx]
            # print '************************************************************'

    def flow_stats_parser(self, stats):
        parsed_flows = self.parse_flows(stats)
        self.controller.logger.info('Parsed flows:')
        # print 'Parsed flows:'
        self.print_flows(parsed_flows)

        parsed_flows = self.unique_flows(parsed_flows)
        self.controller.logger.info('Unique flows:')
        # print 'Unique flows:'
        self.print_flows(parsed_flows)

        parsed_flows = self.merge_flows(parsed_flows)
        self.controller.logger.info('Merged flows:')
        # print 'Merged flows:'
        self.print_flows(parsed_flows)

        parsed_flows = self.process_packet_ins(parsed_flows)
        self.controller.logger.info('Added packet_ins:')
        # print 'Final flows:'
        self.print_flows(parsed_flows)

        parsed_flows = self.remove_dead_flows(parsed_flows)
        self.controller.logger.info('Removed dead connections:')
        self.print_flows(parsed_flows)

        parsed_flows = self.extended_stats(parsed_flows)
        self.controller.logger.info('Extended flows:')
        # print 'Extended flows:'
        self.print_flows(parsed_flows)

        return parsed_flows

    def parse_flows(self, stats):
        parsed_flows = []
        id = 0
        for sw_id in stats:
            for port in stats[sw_id]:
                for idx in range(0, len(stats[sw_id][port])):
                    stat = stats[sw_id][port][idx]
                    if stat.table_id == self.controller.TABLE_SWITCHING:
                        flow = {'id': id}
                        if stat.match['eth_type'] == ether_types.ETH_TYPE_IP:
                            flow['proto'] = stat.match['ip_proto']
                            flow['ipv4_src'] = stat.match['ipv4_src']
                            flow['ipv4_dst'] = stat.match['ipv4_dst']
                            if flow['proto'] == in_proto.IPPROTO_TCP:
                                flow['port_src'] = stat.match['tcp_src']
                                flow['port_dst'] = stat.match['tcp_dst']
                            elif flow['proto'] == in_proto.IPPROTO_UDP:
                                flow['port_src'] = stat.match['udp_src']
                                flow['port_dst'] = stat.match['udp_dst']
                            else:
                                flow['port_src'] = 0
                                flow['port_dst'] = 0
                        elif stat.match['eth_type'] == ether_types.ETH_TYPE_ARP:
                            # TODO Here maybe different representation for ARP protocol
                            flow['proto'] = self.ARP_PROTO
                            flow['ipv4_src'] = stat.match['arp_spa']
                            flow['ipv4_dst'] = stat.match['arp_tpa']
                            flow['port_src'] = 0
                            flow['port_dst'] = 0
                        else:
                            self.controller.logger.info('Unhandled eth_type: %s', stat.match['eth_type'])
                            # print 'Unhandled eth_type: ', stat.match['eth_type']
                        flow['packet_count'] = stat.packet_count
                        flow['byte_count'] = stat.byte_count
                        # Adding extended stats
                        flow['srv_dst_count'] = 0
                        flow['dst_count'] = 0
                        parsed_flows.append(flow)
                        id += 1
        return parsed_flows

    def unique_flows(self, flows):
        unique_flows = [flows[0]]
        for f in range(1, len(flows)):
            for u in range(0, len(unique_flows)):
                if (flows[f]['ipv4_src'] == unique_flows[u]['ipv4_src']
                        and flows[f]['ipv4_dst'] == unique_flows[u]['ipv4_dst']
                        and flows[f]['proto'] == unique_flows[u]['proto']):
                    if flows[f]['proto'] == in_proto.IPPROTO_TCP or flows[f]['proto'] == in_proto.IPPROTO_UDP:
                        if (flows[f]['port_src'] == unique_flows[u]['port_src']
                                and flows[f]['port_dst'] == unique_flows[u]['port_dst']):
                            try:
                                if flows[f]['dpid'] != unique_flows[u]['dpid']:
                                    break
                            except:
                                break
                    else:
                        try:
                            if flows[f]['dpid'] != unique_flows[u]['dpid']:
                                break
                        except:
                            break
                if u == len(unique_flows) - 1:
                    unique_flows.append(flows[f])
                    break
        return unique_flows

    def extended_stats(self, flows):
        # TODO Here maybe more stats
        for f in range(0, len(flows)):
            for ft in range(0, len(flows)):
                if flows[f]['ipv4_dst'] == flows[ft]['ipv4_dst']:
                    flows[f]['dst_count'] += 1
                if flows[f]['proto'] == flows[ft]['proto']:
                    if (flows[f]['port_dst'] == flows[ft]['port_dst']
                            and flows[f]['ipv4_dst'] == flows[ft]['ipv4_dst']):
                        flows[f]['srv_dst_count'] += 1
        return flows

    def merge_flows(self, flows):
        merged_flows = []
        for f in range(0, len(flows) - 1):
            for ft in range(f + 1, len(flows)):
                if (flows[f]['ipv4_src'] == flows[ft]['ipv4_dst']
                        and flows[f]['ipv4_dst'] == flows[ft]['ipv4_src']
                        and flows[f]['proto'] == flows[ft]['proto']
                        and flows[f]['port_src'] == flows[ft]['port_dst']
                        and flows[f]['port_dst'] == flows[ft]['port_src']):
                    # Destination port of the opposite flow is the src port of current flow
                    tmp_flow = {'ipv4_src': flows[f]['ipv4_src'], 'ipv4_dst': flows[f]['ipv4_dst'],
                                'proto': flows[f]['proto'], 'bytes_src': flows[f]['byte_count'],
                                'bytes_dst': flows[ft]['byte_count'], 'packets_src': flows[f]['packet_count'],
                                'packets_dst': flows[ft]['packet_count'], 'dst_count': flows[f]['dst_count'],
                                'srv_dst_count': flows[f]['srv_dst_count'], 'port_src': flows[ft]['port_dst'],
                                'port_dst': flows[f]['port_dst']}
                    merged_flows.append(tmp_flow)
        return merged_flows

    def process_packet_ins(self, flows):
        packet_ins_flows = []
        packet_ins = self.controller.packet_ins
        if len(packet_ins) > 0:
            self.controller.logger.info('[DNN module] Processing %s packet_ins...', len(packet_ins))
            # print '[DNN module] Processing', len(packet_ins), 'packet_ins...'
            for dpid, pkt in packet_ins:
                if pkt.get_protocol(ipv4.ipv4) is not None:
                    ipv4_proto = pkt.get_protocol(ipv4.ipv4)

                    # Serialization is for getting the size of the packet
                    pkt.serialize()
                    flow = {'dpid': dpid,
                            'ipv4_src': ipv4_proto.src,
                            'ipv4_dst': ipv4_proto.dst,
                            'proto': ipv4_proto.proto,
                            'byte_count': len(pkt.data),
                            'packet_count': 1}
                    if pkt.get_protocol(tcp.tcp) is not None:
                        tcp_proto = pkt.get_protocol(tcp.tcp)
                        flow['port_src'] = tcp_proto.src_port
                        flow['port_dst'] = tcp_proto.dst_port
                    elif pkt.get_protocol(udp.udp) is not None:
                        udp_proto = pkt.get_protocol(udp.udp)
                        flow['port_src'] = udp_proto.src_port
                        flow['port_dst'] = udp_proto.dst_port
                    else:
                        flow['port_src'] = 0
                        flow['port_dst'] = 0
                    packet_ins_flows.append(flow)

                elif pkt.get_protocol(arp.arp) is not None:
                    arp_proto = pkt.get_protocol(arp.arp)

                    # Serialization is for getting the size of the packet
                    pkt.serialize()
                    flow = {'dpid': dpid,
                            'ipv4_src': arp_proto.src_ip,
                            'ipv4_dst': arp_proto.dst_ip,
                            'proto': self.ARP_PROTO,
                            'port_src': 0,
                            'port_dst': 0,
                            'byte_count': len(pkt.data) - 18,
                            # TODO This one is temporary to match the real size of ARP packet. Investigate...
                            'packet_count': 1}
                    packet_ins_flows.append(flow)

            self.controller.logger.info('Packet_ins flows before unique:')
            # print 'Packet_ins flows before unique:'
            self.print_flows(packet_ins_flows)

            packet_ins_flows = self.unique_flows(packet_ins_flows)
            self.controller.logger.info('Unique packet_ins flows:')
            # print 'Unique packet_ins flows:'
            self.print_flows(packet_ins_flows)

            self.controller.logger.info('[DNN module] After unifying we have %s packet_ins.', len(packet_ins_flows))
            # print '[DNN module] After unifying we have', len(packet_ins_flows), 'packet_ins.'

            for flow in flows:
                for pif in packet_ins_flows:
                    if (flow['ipv4_src'] == pif['ipv4_src']
                            and flow['ipv4_dst'] == pif['ipv4_dst']
                            and flow['proto'] == pif['proto']
                            and flow['port_src'] == pif['port_src']
                            and flow['port_dst'] == pif['port_dst']):

                        # Found matching flow from statistics of forwarders
                        flow['bytes_src'] += pif['byte_count']
                        flow['packets_src'] += pif['packet_count']
                    elif (flow['ipv4_src'] == pif['ipv4_dst']
                          and flow['ipv4_dst'] == pif['ipv4_src']
                          and flow['proto'] == pif['proto']
                          and flow['port_src'] == pif['port_dst']
                          and flow['port_dst'] == pif['port_src']):

                        # Found matching opposite flow from statistics of forwarders
                        flow['bytes_dst'] += pif['byte_count']
                        flow['packets_dst'] += pif['packet_count']
        else:
            self.controller.logger.info('[DNN module] No new packet_ins.')
        return flows

    def remove_dead_flows(self, flows):
        alive_flows = []
        for flow in flows:
            if flow['packets_src'] != 0 or flow['packets_dst'] != 0:
                if flow['bytes_src'] != 0 or flow['bytes_dst'] != 0:
                    alive_flows.append(flow)
        return alive_flows

    def preprocess_flows(self, flows):
        names = ['packets_src', 'packets_dst', 'bytes_src', 'bytes_dst', 'srv_dst_count', 'dst_count']
        proto_names = ['proto_arp', 'proto_igmp', 'proto_ospf', 'proto_other', 'proto_tcp', 'proto_udp']
        samples = pd.DataFrame(columns=names)
        protos = pd.DataFrame(columns=proto_names)
        for flow in flows:
            samples.loc[len(samples)] = [flow['packets_src'],
                                         flow['packets_dst'],
                                         flow['bytes_src'],
                                         flow['bytes_dst'],
                                         flow['srv_dst_count'],
                                         flow['dst_count']]
            row = [0, 0, 0, 0, 0, 0]
            if flow['proto'] == self.ARP_PROTO:
                row[0] = 1
            elif flow['proto'] == in_proto.IPPROTO_IGMP:
                row[1] = 1
            elif flow['proto'] == in_proto.IPPROTO_OSPF:
                row[2] = 1
            elif flow['proto'] == in_proto.IPPROTO_TCP:
                row[4] = 1
            elif flow['proto'] == in_proto.IPPROTO_UDP:
                row[5] = 1
            else:
                row[3] = 1
            protos.loc[len(protos)] = row
        samples = pd.concat([samples, protos], axis=1)
        self.controller.logger.info(str(samples))
        # print samples
        return self.scaler.transform(samples)

    def evaluate_samples(self, samples, flows):
        with self.graph.as_default():
            predictions = self.model.predict_classes(samples)
            probabs = self.model.predict_proba(samples)
        self.controller.logger.info('Predictions: %s', str(predictions))
        self.controller.logger.info('Probabilities: %s', str(probabs))
        self.controller.logger.info('[DNN module] Evaluation of the flows is as follows:')
        # print 'Predictions:', predictions
        # print 'Probabilities:', probabs
        # print '[DNN module] Evaluation of the flows is as follows:'
        idx = 0
        # Save calculated predictions and classification into dump file
        with open(self.FLOWS_DUMP_FILE, 'a') as f:
            for flow in flows:
                f.write(str(flow['ipv4_src']) + ',' +
                        str(flow['port_src']) + ',' +
                        str(flow['ipv4_dst']) + ',' +
                        str(flow['port_dst']) + ',' +
                        str(flow['proto']) + ',' +
                        str(flow['bytes_src']) + ',' +
                        str(flow['bytes_dst']) + ',' +
                        str(flow['packets_src']) + ',' +
                        str(flow['packets_dst']) + ',' +
                        str(flow['srv_dst_count']) + ',' +
                        str(flow['dst_count']) + ',')
                if predictions[idx]:
                    f.write('Attack,')
                else:
                    f.write('Normal,')
                f.write('%.2f%%\n' % (probabs[idx][0] * 100))
                idx += 1
