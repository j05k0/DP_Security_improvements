import threading
import time
from ryu.lib.packet import ether_types, in_proto


class DNNModule(threading.Thread):

    def __init__(self, controller, queue):
        super(DNNModule, self).__init__()
        self.forwarders = {}
        self.controller = controller
        self.queue = queue
        print 'DNN module initialized'

    def run(self):
        self.get_forwarders()
        record_count = 0
        while 1:
            print 'DNN module is running'
            for fw in self.forwarders:
                for port in self.forwarders[fw]:
                    self.controller.send_flow_stats_request(fw, port)
                    record_count += 1

            self.wait_for_items_in_queue()
            if self.queue.qsize() == record_count:
                record_count = 0
                stats = self.controller.getStats()
                self.controller.clearStats()
                self.print_flow_stats(stats)
                try:
                    self.flow_stats_parser(stats)
                except:
                    # TODO Here maybe different print string
                    #testing comment
                    print 'No stats available'
                while not self.queue.empty():
                    self.queue.get()
            else:
                print 'Wrong number of replies received!!!'
                print 'Record count is ', record_count
                print 'Size of the queue is ', self.queue.qsize()
                record_count = 0

            time.sleep(self.controller.REFRESH_RATE)

    def get_forwarders(self):
        print 'Waiting for forwarders...'
        self.wait_for_items_in_queue()

        print 'Getting datapaths of the forwarders...'
        while not self.queue.empty():
            self.forwarders[self.queue.get()] = []

        print 'Getting ports of the forwarders...'
        for fw in self.forwarders:
            print 'Datapath: ', fw
            self.controller.send_port_stats_request(fw)
        self.wait_for_items_in_queue()
        while not self.queue.empty():
            datapath, ports = self.queue.get()
            self.forwarders[datapath] = ports

        print 'Forwarders: ', self.forwarders

    def wait_for_items_in_queue(self):
        while self.queue.empty():
            time.sleep(self.controller.FW_REFRESH_RATE)

    def print_flow_stats(self, stats):
        for sw_id in stats:
            print 'Switch ' + str(sw_id) + ':'
            for port in stats[sw_id]:
                print 'Input port ' + str(port) + ':'
                for idx in range(0, len(stats[sw_id][port])):
                    print stats[sw_id][port][idx]
                    print '************************************************************'
                print '************************************************************'
            print '************************************************************'

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
                                flow['port_dst'] = stat.match['tcp_dst']
                            elif flow['proto'] == in_proto.IPPROTO_UDP:
                                flow['port_dst'] = stat.match['udp_dst']
                        elif stat.match['eth_type'] == ether_types.ETH_TYPE_ARP:
                            flow['proto'] = 'arp'
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
                        and flows[f]['proto'] == unique_flows[u]['proto']
                        and flows[f]['packet_count'] == unique_flows[u]['packet_count']
                        and flows[f]['byte_count'] == unique_flows[u]['byte_count']):
                    if flows[f]['proto'] == in_proto.IPPROTO_TCP or flows[f][
                        'proto'] == in_proto.IPPROTO_UDP:
                        if flows[f]['port_dst'] == unique_flows[u]['port_dst']:
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
