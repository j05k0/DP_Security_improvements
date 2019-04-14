#!/usr/bin/python
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController, UserSwitch, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI


def topo():
    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)

    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')

    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    print 'Creating links...'
    net.addLink(s1, s2)
    net.addLink(s2, s3)

    print 'Starting network...'
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])

    print 'Running CLI...'
    CLI(net)

    print 'Stopping network...'
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topo()
