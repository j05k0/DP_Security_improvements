import threading
import time


class DNNModule(threading.Thread):

    def __init__(self, controller, queue):
        super(DNNModule, self).__init__()
        self.forwarders = {}
        self.controller = controller
        self.queue = queue
        print 'DNN module initialized'

    def run(self):
        self.get_forwarders()
        while 1:
            print 'DNN module is running'
            for fw in self.forwarders:
                self.controller.send_flow_stats_request(fw)
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
