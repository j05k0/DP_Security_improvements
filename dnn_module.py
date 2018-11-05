import threading
import time


class DNNModule(threading.Thread):

    def __init__(self, controller, queue):
        super(DNNModule, self).__init__()
        self.forwarders = []
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
        while self.queue.empty():
            time.sleep(self.controller.FW_REFRESH_RATE)
        print 'Getting forwarders datapaths...'
        while not self.queue.empty():
            if not self.forwarders:
                self.forwarders = [self.queue.get()]
            else:
                self.forwarders.append(self.queue.get())
        print 'Forwarders: ', self.forwarders
