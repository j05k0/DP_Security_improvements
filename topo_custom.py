#!/usr/bin/python
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI


def topo():
    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)

    print 'Creating nodes...'
    h1 = net.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1/24')
    h2 = net.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2/24')

    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')

    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    print 'Creating links...'
    net.addLink(h1, s1, bw=100)
    net.addLink(s1, s2, bw=100)
    net.addLink(s2, h2, bw=100)

    print 'Starting network...'
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])

    print 'Verifying connectivity...'
    loss = net.pingAll()

    if loss == 0:
        h1, h2 = net.getNodeByName('h1', 'h2')


    print 'Running CLI...'
    CLI(net)

    print 'Stopping network...'
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topo()
