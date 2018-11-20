import threading
import time
from ryu.lib.packet import ether_types

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
                self.print_flow_stats(stats)
                self.flow_stats_parser(stats)
                while not self.queue.empty:
                    self.queue.get()
            else:
                print 'Wrong number of replies received!!!'

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
                        elif stat.match['eth_type'] == ether_types.ETH_TYPE_ARP:
                            flow['proto'] = 'arp'
                            flow['ipv4_src'] = stat.match['arp_spa']
                            flow['ipv4_dst'] = stat.match['arp_tpa']
                        else:
                            print 'Unhandled eth_type: ', stat.match['eth_type']
                        flow['packet_count'] = stat.packet_count
                        parsed_flows.append(flow)
                        id += 1
        for idx in range(0, len(parsed_flows)):
            print parsed_flows[idx]
            print '************************************************************'
