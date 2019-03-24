import threading
import time
from ryu.lib.packet import ether_types, in_proto, ipv4, arp, tcp, udp


class DNNModule(threading.Thread):
    ARP_PROTO = -1

    def __init__(self, controller, queue):
        super(DNNModule, self).__init__()
        self.forwarders = {}
        self.controller = controller
        self.queue = queue
        print '[DNN module] DNN module initialized'

    def run(self):
        # TODO possible change to networkx and digraph
        while 1:
            if self.get_forwarders():
                while 1:
                    print '[DNN module] Starting new iteration...'
                    record_count = 0
                    if self.update_forwarders():
                        for fw in self.forwarders:
                            for port in self.forwarders[fw]:
                                self.controller.send_flow_stats_request(fw, port)
                                record_count += 1

                        self.wait_for_items_in_queue()
                        if self.queue.qsize() == record_count:
                            stats = self.controller.getStats()
                            self.controller.clearStats()
                            if self.print_flow_stats(stats):
                                try:
                                    self.flow_stats_parser(stats)
                                except:
                                    # TODO Here maybe different print string
                                    print '[DNN module] Exception during parsing flow stats. Operation will continue in the next iteration'

                            else:
                                print '[DNN module] No flow stats available'

                        else:
                            print '[DNN module] Wrong number of flow stats replies received'
                            print '[DNN module] Record count is ', record_count
                            print '[DNN module] Size of the queue is ', self.queue.qsize()

                        self.clear_queue()
                        if self.controller.mac_to_port != {}:
                            print '[DNN module] Actual MAC to port table:'
                            for sw_id in self.controller.mac_to_port:
                                print 'Switch ' + str(sw_id) + ':'
                                for dst in self.controller.mac_to_port[sw_id]:
                                    print dst, self.controller.mac_to_port[sw_id][dst]

                    else:
                        print '[DNN module] An error occured during updating forwarders. Skipping requesting of flow stats'

                    print '[DNN module] Iteration done.'
                    print '************************************************************'
                    time.sleep(self.controller.REFRESH_RATE)

            else:
                print '[DNN module] An error occured during getting forwarders. Skipping requesting of flow stats'

            time.sleep(self.controller.REFRESH_RATE)

    def get_forwarders(self):
        print '[DNN module] Waiting for forwarders...'
        self.wait_for_items_in_queue()

        try:
            print '[DNN module] Getting datapaths of the forwarders...'
            while not self.queue.empty():
                self.forwarders[self.queue.get()] = []
            return True
        except:
            return False

    def update_forwarders(self):
        print '[DNN module] Updating the status of the forwarders...'
        print '[DNN module] Getting active ports of the forwarders...'
        record_count = 0
        for fw in self.forwarders:
            print '[DNN module] Datapath: ', fw
            self.controller.send_port_stats_request(fw)
            record_count += 1
        self.wait_for_items_in_queue()
        if self.queue.qsize() == record_count:
            while not self.queue.empty():
                datapath, ports = self.queue.get()
                self.forwarders[datapath] = ports
            print '[DNN module] Forwarders: ', self.forwarders
            return True
        print '[DNN module] Wrong number of port stats replies received'
        print '[DNN module] Record count is ', record_count
        print '[DNN module] Size of the queue is ', self.queue.qsize()
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
        for sw_id in stats:
            # if stats[sw_id] == {}:
            #     return False
            print 'Switch ' + str(sw_id) + ':'
            for port in stats[sw_id]:
                # if len(stats[sw_id][port]) == 0:
                #     return False
                print 'Input port ' + str(port) + ':'
                for idx in range(0, len(stats[sw_id][port])):
                    print stats[sw_id][port][idx]
                    print '************************************************************'
                print '************************************************************'
            print '************************************************************'
        return True

    def print_flows(self, flows):
        for idx in range(0, len(flows)):
            print flows[idx]
            print '************************************************************'

    def flow_stats_parser(self, stats):
        parsed_flows = self.parse_flows(stats)
        print 'Parsed flows:'
        self.print_flows(parsed_flows)

        parsed_flows = self.unique_flows(parsed_flows)
        print 'Unique flows:'
        self.print_flows(parsed_flows)

        parsed_flows = self.extended_stats(parsed_flows)
        print 'Extended flows:'
        self.print_flows(parsed_flows)

        parsed_flows = self.merge_flows(parsed_flows)
        print 'Merged flows:'
        self.print_flows(parsed_flows)

        parsed_flows = self.process_packet_ins(parsed_flows)
        print 'Final flows:'
        self.print_flows(parsed_flows)

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
                        elif stat.match['eth_type'] == ether_types.ETH_TYPE_ARP:
                            # TODO Here maybe different representation for ARP protocol
                            flow['proto'] = self.ARP_PROTO
                            flow['ipv4_src'] = stat.match['arp_spa']
                            flow['ipv4_dst'] = stat.match['arp_tpa']
                        else:
                            print 'Unhandled eth_type: ', stat.match['eth_type']
                        flow['packet_count'] = stat.packet_count
                        flow['byte_count'] = stat.byte_count
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
                            break
                    else:
                        break
                if u == len(unique_flows) - 1:
                    unique_flows.append(flows[f])
                    break
        return unique_flows

    def extended_stats(self, flows):
        for f in range(0, len(flows)):
            flows[f]['host_count'] = 0
            flows[f]['service_count'] = 0
            for ft in range(0, len(flows)):
                if flows[f]['ipv4_dst'] == flows[ft]['ipv4_dst']:
                    flows[f]['host_count'] += 1
                if flows[f]['proto'] == flows[ft]['proto']:
                    try:
                        if flows[f]['port_dst'] == flows[ft]['port_dst']:
                            flows[f]['service_count'] += 1
                    except:
                        flows[f]['service_count'] += 1
        return flows

    def merge_flows(self, flows):
        merged_flows = []
        for f in range(0, len(flows) - 1):
            for ft in range(f + 1, len(flows)):
                if (flows[f]['ipv4_src'] == flows[ft]['ipv4_dst']
                        and flows[f]['ipv4_dst'] == flows[ft]['ipv4_src']
                        and flows[f]['proto'] == flows[ft]['proto']):
                    # Destination port of the opposite flow is the src port of current flow
                    print flows[f]
                    print flows[ft]
                    tmp_flow = {'ipv4_src': flows[f]['ipv4_src'],
                                'ipv4_dst': flows[f]['ipv4_dst'],
                                'proto': flows[f]['proto'],
                                'bytes_src': flows[f]['byte_count'],
                                'bytes_dst': flows[ft]['byte_count'],
                                'packets_src': flows[f]['packet_count'],
                                'packets_dst': flows[ft]['packet_count'],
                                'host_count': flows[f]['host_count'],
                                'service_count': flows[f]['service_count']}
                    if tmp_flow['proto'] == in_proto.IPPROTO_TCP or tmp_flow['proto'] == in_proto.IPPROTO_UDP:
                        tmp_flow['port_src'] = flows[ft]['port_dst']
                        tmp_flow['port_dst'] = flows[f]['port_dst']
                    else:
                        tmp_flow['port_src'] = 0
                        tmp_flow['port_dst'] = 0
                    merged_flows.append(tmp_flow)
        return merged_flows

    def process_packet_ins(self, flows):
        packet_ins_flows = []
        packet_ins = self.controller.packet_ins
        print '[DNN module] Processing', len(packet_ins), 'packet_ins...'
        for pkt in packet_ins:
            if pkt.get_protocol(ipv4.ipv4) is not None:
                ipv4_proto = pkt.get_protocol(ipv4.ipv4)
                pkt.serialize()
                flow = {'ipv4_src': ipv4_proto.src,
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
                pkt.serialize()
                flow = {'ipv4_src': arp_proto.src_ip,
                        'ipv4_dst': arp_proto.dst_ip,
                        'proto': self.ARP_PROTO,
                        'port_src': 0,
                        'port_dst': 0,
                        'byte_count': len(pkt.data) - 18,
                        # TODO This one is temporary to mathc the real size of ARP packet. Investigate...
                        'packet_count': 1}
                packet_ins_flows.append(flow)

        packet_ins_flows = self.unique_flows(packet_ins_flows)
        print 'Packet_ins flows:'
        self.print_flows(packet_ins_flows)

        for flow in flows:
            for pif in packet_ins_flows:
                if (flow['ipv4_src'] == pif['ipv4_src']
                        and flow['ipv4_dst'] == pif['ipv4_dst']
                        and flow['proto'] == pif['proto']
                        and flow['port_src'] == pif['port_src']
                        and flow['port_dst'] == pif['port_dst']):
                    flow['bytes_src'] += pif['byte_count']
                    flow['packets_src'] += pif['packet_count']
                elif (flow['ipv4_src'] == pif['ipv4_dst']
                        and flow['ipv4_dst'] == pif['ipv4_src']
                        and flow['proto'] == pif['proto']
                        and flow['port_src'] == pif['port_dst']
                        and flow['port_dst'] == pif['port_src']):
                    flow['bytes_dst'] += pif['byte_count']
                    flow['packets_dst'] += pif['packet_count']
        return flows