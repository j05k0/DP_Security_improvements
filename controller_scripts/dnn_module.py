import datetime
import threading
import time
import pandas as pd
import tensorflow as tf
from keras.models import load_model
from ryu.lib.packet import ether_types, in_proto, ipv4, arp, tcp, udp
from sklearn.externals import joblib
import traceback


class DNNModule(threading.Thread):
    ARP_PROTO = -1
    METER_ID_WARNING = 1
    METER_ID_BEST_EFFORT = 2

    def __init__(self, controller, queue, params):
        super(DNNModule, self).__init__()
        self.forwarders = {}
        self.controller = controller
        self.queue = queue
        try:
            self.REFRESH_RATE = params[0]
            self.logger('REFRESH_RATE is ' + str(self.REFRESH_RATE))
            self.FW_REFRESH_RATE = params[1]
            self.logger('FW_REFRESH_RATE is ' + str(self.FW_REFRESH_RATE))
            self.TIMEOUT = params[2]
            self.logger('TIMEOUT is ' + str(self.TIMEOUT))
            self.FLOWS_DUMP_FILE = params[3]
            self.logger('FLOWS_DUMP_FILE is ' + str(self.FLOWS_DUMP_FILE))
            self.DNN_MODEL = params[4]
            self.DNN_SCALER = params[5]

            # Loading values to intervals
            self.NORMAL = [float(params[6][0]), float(params[6][1])]
            self.WARNING = [float(params[7][0]), float(params[7][1])]
            self.BEST_EFFORT = [float(params[8][0]), float(params[8][1])]
            self.ATTACK = [float(params[9][0]), float(params[9][1])]
        except Exception as e:
            self.logger(e)
            traceback.print_exc()
        try:
            self.model = load_model(self.DNN_MODEL)
            self.logger('DNN_MODEL is ' + str(self.DNN_MODEL))
            self.scaler = joblib.load(self.DNN_SCALER)
            self.logger('DNN_SCALER is ' + str(self.DNN_SCALER))
            self.logger('Intervals are:')
            self.logger('Normal is ' + str(self.NORMAL))
            self.logger('Warning is ' + str(self.WARNING))
            self.logger('Best Effort is ' + str(self.BEST_EFFORT))
            self.logger('Attack is ' + str(self.ATTACK))
            self.model._make_predict_function()
            self.graph = tf.get_default_graph()
            self.logger('[DNN module] DNN module initialized')
            self.printer('[DNN module] DNN module initialized')

        except Exception as e:
            self.logger('[DNN module] DNN module failed to initialize')
            self.printer('[DNN module] DNN module failed to initialize')
            self.logger(e)
            traceback.print_exc()
            # print e
        # Open dump file and add the first line - column names
        with open(self.FLOWS_DUMP_FILE, 'w') as f:
            f.write(
                'ipv4_src,port_src,ipv4_dst,port_dst,proto,bytes_src,bytes_dst,packets_src,packets_dst,srv_dst_count,'
                'dst_count,prediction,category,probability\n')
        # Set pandas to display all columns in prints/logs
        pd.set_option('display.max_columns', None)

    def run(self):
        # TODO possible change to networkx and digraph
        while 1:
            if self.get_forwarders():
                while 1:
                    self.printer('[DNN module] Starting new iteration...')
                    self.logger('[DNN module] Starting new iteration...')
                    record_count = 0
                    if self.update_forwarders():
                        for fw in self.forwarders:
                            for port in self.forwarders[fw]:
                                self.controller.send_flow_stats_request(fw, port)
                                record_count += 1
                        if self.wait_for_items_in_queue(record_count):
                            # Get actual stats from forwarders
                            stats = self.controller.get_stats()

                            # TODO This could be done with delta - you must save the old flows for comparision
                            # Clear counters on all forwarders
                            for fw in self.forwarders:
                                self.controller.clear_counters(fw)

                            # Save actual packet_ins and clear packet_ins list
                            packet_ins, self.controller.packet_ins = self.controller.packet_ins, []
                            if self.print_flow_stats(stats):
                                try:
                                    parsed_flows = self.flow_stats_parser(stats, packet_ins)
                                    try:
                                        if len(parsed_flows) > 0:
                                            scaled_samples = self.preprocess_flows(parsed_flows)
                                            warnings, attacks = self.evaluate_samples(scaled_samples, parsed_flows)
                                            self.logger('Warnings are ' + str(len(warnings)))
                                            self.logger('Attacks are ' + str(len(attacks)))
                                            try:
                                                self.apply_warnings(warnings)
                                            except Exception as e:
                                                self.logger('[DNN module] Exception during applying warnings')
                                                self.logger(e)
                                            try:
                                                self.apply_attacks(attacks)
                                            except Exception as e:
                                                self.logger('[DNN module] Exception during applying attacks')
                                                self.logger(e)
                                        else:
                                            self.logger('[DNN module] No flow stats available')
                                            self.printer('[DNN module] No flow stats available')
                                    except Exception as e:
                                        self.logger(
                                            '[DNN module] Exception during evaluation process. Operation will continue in the next iteration.')
                                        self.logger(e)
                                        traceback.print_exc()
                                        # print '[DNN module] Exception during evaluation process. Operation will continue in the next iteration.'
                                        # print e
                                except Exception as e:
                                    self.logger(
                                        '[DNN module] Exception during parsing flow stats. Operation will continue in the next iteration.')
                                    self.logger(e)
                                    # print '[DNN module] Exception during parsing flow stats. Operation will continue in the next iteration.'
                                    # print e
                            else:
                                self.logger('[DNN module] No flow stats available')
                                self.printer('[DNN module] No flow stats available')
                        elif self.queue.qsize() != record_count:
                            self.logger('[DNN module] Wrong number of flow stats replies received')
                            self.logger('[DNN module] Record count is ' + str(record_count))
                            self.logger('[DNN module] Size of the queue is ' + str(self.queue.qsize()))
                            # print '[DNN module] Wrong number of flow stats replies received'
                            # print '[DNN module] Record count is ', record_count
                            # print '[DNN module] Size of the queue is ', self.queue.qsize()
                        else:
                            self.logger(
                                '[DNN module] Waiting for replies from forwarders timed out')
                    else:
                        self.logger(
                            '[DNN module] An error occured during updating forwarders. Skipping requesting of flow stats.')
                        # print '[DNN module] An error occured during updating forwarders. Skipping requesting of flow stats.'

                    # Clear stats in controller
                    self.controller.clear_stats()
                    self.clear_queue()
                    if self.controller.mac_to_port != {}:
                        self.logger('[DNN module] Actual MAC to port table:')
                        # print '[DNN module] Actual MAC to port table:'
                        for sw_id in self.controller.mac_to_port:
                            self.logger('Switch ' + str(sw_id) + ':')
                            # print 'Switch ' + str(sw_id) + ':'
                            for dst in self.controller.mac_to_port[sw_id]:
                                self.logger(dst + ' ' + str(self.controller.mac_to_port[sw_id][dst]))
                                # print dst, self.controller.mac_to_port[sw_id][dst]
                    self.logger('[DNN module] Iteration done.')
                    self.logger(' ************************************************************')
                    self.printer('[DNN module] Iteration done.')
                    self.printer('************************************************************')
                    time.sleep(self.REFRESH_RATE)

            else:
                self.logger(
                    '[DNN module] An error occured during getting forwarders. Skipping requesting of flow stats.')
                # print '[DNN module] An error occured during getting forwarders. Skipping requesting of flow stats.'

            time.sleep(self.REFRESH_RATE)

    def logger(self, to_print):
        self.controller.logger.info(self.current_timestamp() + ' ' + str(to_print))

    def printer(self, to_print):
        print (self.current_timestamp() + ' ' + str(to_print))

    def current_timestamp(self):
        return datetime.datetime.fromtimestamp(time.time()).strftime('%d-%m-%Y %H:%M:%S')

    def get_forwarders(self):
        self.logger('[DNN module] Waiting for forwarders...')
        self.printer('[DNN module] Waiting for forwarders...')

        # FW_REFRESH_RATE is small number to get forwarders quickly
        while self.queue.empty():
            time.sleep(self.FW_REFRESH_RATE)
        try:
            self.logger('[DNN module] Getting datapaths of the forwarders...')
            # print '[DNN module] Getting datapaths of the forwarders...'
            while not self.queue.empty():
                self.forwarders[self.queue.get()] = []
            return True
        except Exception as e:
            self.logger(e)
            return False

    def update_forwarders(self):
        self.logger('[DNN module] Updating the status of the forwarders...')
        self.logger('[DNN module] Getting active ports of the forwarders...')
        # print '[DNN module] Updating the status of the forwarders...'
        # print '[DNN module] Getting active ports of the forwarders...'
        record_count = 0
        for fw in self.forwarders:
            self.logger('[DNN module] Datapath: ' + str(fw))
            # print '[DNN module] Datapath: ', fw
            self.controller.send_port_stats_request(fw)
            record_count += 1
        if self.wait_for_items_in_queue(record_count):
            try:
                while not self.queue.empty():
                    datapath, ports = self.queue.get()
                    self.forwarders[datapath] = ports
                self.logger('[DNN module] Forwarders: ' + str(self.forwarders))
                # print '[DNN module] Forwarders: ', self.forwarders
                return True
            except Exception as e:
                self.logger(e)
        elif self.queue.qsize() != record_count:
            self.logger('[DNN module] Wrong number of port stats replies received')
            self.logger('[DNN module] Record count is ' + str(record_count))
            self.logger('[DNN module] Size of the queue is ' + str(self.queue.qsize()))
            # print '[DNN module] Wrong number of port stats replies received'
            # print '[DNN module] Record count is ', record_count
            # print '[DNN module] Size of the queue is ', self.queue.qsize()
        else:
            self.logger('[DNN module] Waiting for replies from forwarders timed out')
        return False

    def wait_for_items_in_queue(self, record_count):
        start = time.time()
        while self.queue.qsize() != record_count:
            time.sleep(self.FW_REFRESH_RATE)
            if time.time() - start > self.TIMEOUT:
                return False
        return True

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
                break
            #self.logger('Switch ' + str(sw_id) + ':')
            # print 'Switch ' + str(sw_id) + ':'
            #for port in stats[sw_id]:
                # if len(stats[sw_id][port]) == 0:
                #     return False
                #self.logger('Input port ' + str(port) + ':')
                # print 'Input port ' + str(port) + ':'
                #for idx in range(0, len(stats[sw_id][port])):
                    #self.logger(stats[sw_id][port][idx])
                    #self.logger('************************************************************')
                    # print stats[sw_id][port][idx]
                    # print '************************************************************'
                #self.logger('************************************************************')
                # print '************************************************************'
            #self.logger('************************************************************')
            # print '************************************************************'
        return is_stats

    def print_flows(self, flows):
        for idx in range(0, len(flows)):
            self.logger(flows[idx])
            self.logger('************************************************************')
            # print flows[idx]
            # print '************************************************************'

    def flow_stats_parser(self, stats, packet_ins):
        parsed_flows = self.parse_flows(stats)
        # self.logger('Parsed flows:')
        # print 'Parsed flows:'
        #self.print_flows(parsed_flows)

        parsed_flows = self.unique_flows(parsed_flows)
        # self.logger('Unique flows:')
        # print 'Unique flows:'
        #self.print_flows(parsed_flows)

        parsed_flows = self.merge_flows(parsed_flows)
        # self.logger('Merged flows:')
        # print 'Merged flows:'
        #self.print_flows(parsed_flows)

        parsed_flows = self.process_packet_ins(parsed_flows, packet_ins)
        # self.logger('Added packet_ins:')
        # print 'Final flows:'
        #self.print_flows(parsed_flows)

        parsed_flows = self.remove_dead_flows(parsed_flows)
        # self.logger('Removed dead connections:')
        #self.print_flows(parsed_flows)

        parsed_flows = self.extended_stats(parsed_flows)
        # self.logger('Extended flows:')
        # print 'Extended flows:'
        #self.print_flows(parsed_flows)

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
                            self.logger('Unhandled eth_type: ' + str(stat.match['eth_type']))
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
                            except Exception as e:
                                # self.logger(e)
                                break
                    else:
                        try:
                            if flows[f]['dpid'] != unique_flows[u]['dpid']:
                                break
                        except Exception as e:
                            # self.logger(e)
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

    def process_packet_ins(self, flows, packet_ins):
        packet_ins_flows = []
        if len(packet_ins) > 0:
            self.logger('[DNN module] Processing ' + str(len(packet_ins)) + ' packet_ins...')
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

            # self.logger('Packet_ins flows before unique:')
            # print 'Packet_ins flows before unique:'
            #self.print_flows(packet_ins_flows)

            packet_ins_flows = self.unique_flows(packet_ins_flows)
            # self.logger('Unique packet_ins flows:')
            # print 'Unique packet_ins flows:'
            #self.print_flows(packet_ins_flows)

            self.logger('[DNN module] After unifying we have ' + str(len(packet_ins_flows)) + ' packet_ins.')
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
            self.logger('[DNN module] No new packet_ins.')
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
        proto_names = ['proto_arp', 'proto_icmp', 'proto_igmp', 'proto_ospf', 'proto_other', 'proto_tcp', 'proto_udp']
        samples = pd.DataFrame(columns=names)
        protos = pd.DataFrame(columns=proto_names)
        for flow in flows:
            samples.loc[len(samples)] = [flow['packets_src'],
                                         flow['packets_dst'],
                                         flow['bytes_src'],
                                         flow['bytes_dst'],
                                         flow['srv_dst_count'],
                                         flow['dst_count']]
            row = [0] * len(proto_names)
            if flow['proto'] == self.ARP_PROTO:
                row[0] = 1
            elif flow['proto'] == in_proto.IPPROTO_ICMP:
                row[1] = 1
            elif flow['proto'] == in_proto.IPPROTO_IGMP:
                row[2] = 1
            elif flow['proto'] == in_proto.IPPROTO_OSPF:
                row[3] = 1
            elif flow['proto'] == in_proto.IPPROTO_TCP:
                row[5] = 1
            elif flow['proto'] == in_proto.IPPROTO_UDP:
                row[6] = 1
            else:
                row[4] = 1
            protos.loc[len(protos)] = row
        samples = pd.concat([samples, protos], axis=1)
        # self.logger('\n' + str(samples))
        # self.printer(str(samples))
        return self.scaler.transform(samples)

    def evaluate_samples(self, samples, flows):
        warnings = []
        attacks = []

        # Predict classes and probabilities on scaled samples using trained DNN model
        with self.graph.as_default():
            preds = self.model.predict_classes(samples)
            probabs = self.model.predict_proba(samples)
        # self.logger('Predictions: ' + str(preds))
        # self.logger('Probabilities: ' + str(probabs))
        self.logger('[DNN module] Evaluation of the flows is going to be saved into ' + str(self.FLOWS_DUMP_FILE))
        # print 'Predictions:', preds
        # print 'Probabilities:', probabs
        # print '[DNN module] Evaluation of the flows is as follows:'
        idx = 0

        # Save calculated preds and classification into dump file
        with open(self.FLOWS_DUMP_FILE, 'a') as f:
            for flow in flows:
                # Write info about flow into file
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

                # Evaluate flows based on specified intervals of probabilities for NORMAL, WARNING, BEST_EFFORT and
                # ATTACK traffic and add prediction and category to the file
                if self.NORMAL[0] <= probabs[idx] < self.NORMAL[1]:
                    f.write(str(preds[idx][0]) + ',Normal,')
                elif self.WARNING[0] <= probabs[idx] < self.WARNING[1]:
                    f.write(str(preds[idx][0]) + ',Warning,')
                    warnings.append((flow, self.METER_ID_WARNING))
                elif self.BEST_EFFORT[0] <= probabs[idx] < self.BEST_EFFORT[1]:
                    f.write(str(preds[idx][0]) + ',Best_effort,')
                    warnings.append((flow, self.METER_ID_BEST_EFFORT))
                elif self.ATTACK[0] <= probabs[idx] <= self.ATTACK[1]:
                    f.write(str(preds[idx][0]) + ',Attack,')
                    attacks.append(flow)

                # Save computed probabilities to the file
                f.write('%.2f%%\n' % (probabs[idx][0] * 100))
                idx += 1

            self.logger('[DNN module] Evaluation of the flows is successfully saved')
            self.logger('[DNN module] Number of saved flows is ' + str(idx))
        return warnings, attacks

    def apply_warnings(self, warnings):
        self.logger('Applying warnings')

        # Iterate over all warnings and build params structure
        for warning, meter_id in warnings:
            self.logger('Warning: ' + str(warning))
            self.logger('Meter ID: ' + str(meter_id))
            params = {'ipv4_src': warning['ipv4_src'],
                      'port_src': warning['port_src'],
                      'ipv4_dst': warning['ipv4_dst'],
                      'port_dst': warning['port_dst']}
            if warning['proto'] == self.ARP_PROTO:
                params['eth_type'] = ether_types.ETH_TYPE_ARP
            else:
                params['eth_type'] = ether_types.ETH_TYPE_IP
                params['proto'] = warning['proto']
            self.logger('Params: ' + str(params))

            # Apply meter on every forwarder
            for fw in self.forwarders:
                self.controller.apply_meter(fw, params, meter_id)

    def apply_attacks(self, attacks):
        pass
