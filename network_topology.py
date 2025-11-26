#!/usr/bin/env python3
"""
Mininet Topology: 3 Hosts + 1 Switch + Remote Controller
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def create_topology():
    """Create network topology with 3 hosts and 1 switch"""
    
    info('*** Creating network\n')
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        autoSetMacs=True
    )

    info('*** Adding controller\n')
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )

    info('*** Adding switch\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')

    info('*** Creating links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    info('*** Starting network\n')
    net.start()

    info('\n*** Network ready!\n')
    info('Topology: h1 --- s1 --- h2\n')
    info('                 |\n')
    info('                h3\n\n')
    
    info('*** Testing connectivity\n')
    net.pingAll()

    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()