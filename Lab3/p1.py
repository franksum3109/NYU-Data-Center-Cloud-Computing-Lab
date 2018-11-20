#!/usr/bin/python

"""
This setup the topology in lab3-part1
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.util import dumpNodeConnections
from mininet.link import Link, Intf, TCLink
import os 
from time import sleep
import sys

class Topology(Topo):
    
    
    def __init__(self):
        "Create Topology."
        
        # Initialize topology
        Topo.__init__(self)
        
      
        # Add hosts
        host1 = self.addHost('h1', ip='10.0.0.1/24')
        host2 = self.addHost('h2', ip='10.0.0.2/24')
        
        
        # Add switches
        swA = self.addSwitch('s1')
        swB = self.addSwitch('s2')
        swC = self.addSwitch('s3')
        swD = self.addSwitch('s4')
        swE = self.addSwitch('s5')
        
        self.addLink(host1, swA)
        self.addLink(swA, swB)
        self.addLink(swA, swC)
        self.addLink(swB, swD)
        self.addLink(swB, swE)
        self.addLink(swC, swD)
        self.addLink(swC, swE)
        self.addLink(swD, swE)
        self.addLink(swD, host2)

        
def AutoSetFlows():
    # Other flow (low priority) h1 -> h2
    cmd = "ovs-ofctl add-flow s1 priority=1,in_port=1,actions=output:2"
    os.system(cmd)
    cmd = "ovs-ofctl add-flow s2 priority=1,in_port=1,actions=output:3"
    os.system(cmd)
    cmd = "ovs-ofctl add-flow s5 priority=1,in_port=1,actions=output:3"
    os.system(cmd)
    cmd = "ovs-ofctl add-flow s4 priority=1,in_port=3,actions=output:4"
    os.system(cmd)
    
    # Other flow (low priority) h2 -> h1
    cmd = "ovs-ofctl add-flow s4 priority=1,in_port=4,actions=output:2"
    os.system(cmd)
    cmd = "ovs-ofctl add-flow s3 priority=1,in_port=2,actions=output:3"
    os.system(cmd)
    cmd = "ovs-ofctl add-flow s5 priority=1,in_port=2,actions=output:1"
    os.system(cmd)
    cmd = "ovs-ofctl add-flow s2 priority=1,in_port=3,actions=output:1"
    os.system(cmd)
    cmd = "ovs-ofctl add-flow s1 priority=1,in_port=2,actions=output:1"
    os.system(cmd)
    
    # Port = 80, h1 -> h2
    cmd = "ovs-ofctl add-flow s1 priority=2,in_port=1,tcp,tcp_dst=80,actions=output:3"
    os.system(cmd)
    cmd = "ovs-ofctl add-flow s3 priority=2,in_port=1,tcp,tcp_dst=80,actions=output:2"
    os.system(cmd)
    cmd = "ovs-ofctl add-flow s4 priority=2,in_port=2,tcp,tcp_dst=80,actions=output:4"
    os.system(cmd)
    
    # Port = 80, h2 -> h1
    cmd = "ovs-ofctl add-flow s4 priority=2,in_port=4,tcp,tcp_src=80,actions=output:1"
    os.system(cmd)
    cmd = "ovs-ofctl add-flow s2 priority=2,in_port=2,tcp,tcp_src=80,actions=output:1"
    os.system(cmd)
    cmd = "ovs-ofctl add-flow s1 priority=2,in_port=2,tcp,tcp_src=80,actions=output:1"
    os.system(cmd)
        

# This is for "mn --custom"
topos = { 'mytopo': ( lambda: Topology() ) }


# This is for "python *.py"
if __name__ == '__main__':
    setLogLevel( 'info' )
            
    topo = Topology()
    net = Mininet(topo=topo, link=TCLink)
    
    # 1. Start mininet
    net.start()
    
    # Wait for links setup
    print "\nWaiting for links to setup . . . .",
    sys.stdout.flush()
    for time_idx in range(3):
        print ".",
        sys.stdout.flush()
        sleep(1)
        
    AutoSetFlows()
    
        
    info( '\n*** Running CLI\n' )
    CLI( net )
    
    net.stop()

