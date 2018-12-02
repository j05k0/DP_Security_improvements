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
                self.flow_stats_parser(stats)
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

    def flow_stats_parser(self, stats):
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
        for f in range(0, len(parsed_flows)):
            parsed_flows[f]['host_count'] = 0
            parsed_flows[f]['service_count'] = 0
            for ft in range(0, len(parsed_flows)):
                if parsed_flows[f]['ipv4_dst'] == parsed_flows[ft]['ipv4_dst']:
                    parsed_flows[f]['host_count'] += 1
                if parsed_flows[f]['proto'] == parsed_flows[ft]['proto']:
                    try:
                        if parsed_flows[f]['port_dst'] == parsed_flows[ft]['port_dst']:
                            parsed_flows[f]['service_count'] += 1
                    except:
                        parsed_flows[f]['service_count'] += 1
        print 'Parsed flows:'
        for idx in range(0, len(parsed_flows)):
            print parsed_flows[idx]
            print '************************************************************'
        unique_flows = []
        unique_flows.append(parsed_flows[0])
        for f in range(1, len(parsed_flows)):
            for u in range(0, len(unique_flows)):
                if (parsed_flows[f]['ipv4_src'] == unique_flows[u]['ipv4_src']
                        and parsed_flows[f]['ipv4_dst'] == unique_flows[u]['ipv4_dst']
                        and parsed_flows[f]['proto'] == unique_flows[u]['proto']
                        and parsed_flows[f]['packet_count'] == unique_flows[u]['packet_count']
                        and parsed_flows[f]['byte_count'] == unique_flows[u]['byte_count']
                        and parsed_flows[f]['host_count'] == unique_flows[u]['host_count']
                        and parsed_flows[f]['service_count'] == unique_flows[u]['service_count']):
                    if parsed_flows[f]['proto'] == in_proto.IPPROTO_TCP or parsed_flows[f]['proto'] == in_proto.IPPROTO_UDP:
                        if parsed_flows[f]['port_dst'] == unique_flows[u]['port_dst']:
                            break
                    else:
                        break
                if u == len(unique_flows) - 1:
                    unique_flows.append(parsed_flows[f])
                    break
        parsed_flows = []

        print 'Unique flows:'
        for idx in range(0, len(unique_flows)):
            print unique_flows[idx]
            print '************************************************************'

        merged_flows = []
        merged_flows.append(unique_flows[0])
        for f in range (1, len(unique_flows)):
            for u in range(0, len(merged_flows)):
                if (unique_flows[f]['ipv4_src'] == merged_flows[u]['ipv4_dst']
                        and unique_flows[f]['ipv4_dst'] == merged_flows[u]['ipv4_src']
                        and unique_flows[f]['proto'] == merged_flows[u]['proto']):
                    break
                if u == len(merged_flows) - 1:
                    merged_flows.append(unique_flows[f])
                    #TODO Add anothoer flow stats to merged flows
                    break

        print 'Merged flows:'
        for idx in range(0, len(merged_flows)):
            print merged_flows[idx]
            print '************************************************************'
        unique_flows = []


