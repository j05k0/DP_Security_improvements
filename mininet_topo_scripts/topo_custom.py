#!/usr/bin/python
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI


def topo():
    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)

    print 'Creating nodes...'
    # h1 = net.addHost('h1', mac='3c:8c:f8:f6:0b:f0', ip='192.168.56.225/24')
    # h2 = net.addHost('h2', mac='00:0c:29:76:e7:12', ip='192.168.56.31/24')
    h1 = net.addHost('h1', mac='00:00:00:00:00:01', ip='175.45.176.0/2')
    h2 = net.addHost('h2', mac='00:00:00:00:00:02', ip='149.171.126.16/2')

    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')

    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    print 'Creating links...'
    net.addLink(h1, s1)
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s3, h2)

    print 'Starting network...'
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])

    print 'Verifying connectivity...'
    loss = net.pingAll()

    # if loss == 0:
        # h1, h2 = net.getNodeByName('h1', 'h2')
        # print 'Replaying malicious traffic using tcpreplay...'
        # h1.cmd('sudo tcpreplay -i h1-eth0 -K pcaps/22-01-2015_filtered_record_24_client.pcap &> h1_console.txt &')
        # h2.cmd('sudo tcpreplay -i h2-eth0 -K pcaps/22-01-2015_filtered_record_24_server.pcap &> h2_console.txt &')

    print 'Running CLI...'
    CLI(net)

    print 'Stopping network...'
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topo()
