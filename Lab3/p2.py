#!/usr/bin/python



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

class FatTreeTopo(Topo):
    "N Fat Tree Topology"
    
    
    def __init__(self, N):
        "Create Fat Tree Topology."
        
        # Initialize topology
        Topo.__init__(self)
        
        
        # Add hosts
        hosts = [[0 for h_idx in range(N/2)] for sL_idx in range(N)]
        for sL_idx in range(N):
            for h_idx in range(N/2):
                host_name = 'h' + str(sL_idx) + '_' + str(h_idx)
                host_ip_idx = h_idx+sL_idx*N/2+1
                hosts[sL_idx][h_idx] = self.addHost(host_name, ip='10.0.0.'+ str(host_ip_idx) +'/24')
        
        # Add Leaves switch
        l_switch = [0 for sL_idx in range(N)]
        for sL_idx in range(N):
            l_switch_name = 'sL' + str(sL_idx)
            l_switch[sL_idx] = self.addSwitch(l_switch_name)
                
        # Add Spine switch
        s_switch = [0 for sS_idx in range(N/2)]
        for sS_idx in range(N/2):
            s_switch_name = 'sS' + str(sS_idx)
            s_switch[sS_idx] = self.addSwitch(s_switch_name)
                
                
        # Add links in pod
        # Add host + leaves switch links
        for sL_idx in range(N):
            for h_idx in range(N/2):
                self.addLink(hosts[sL_idx][h_idx], l_switch[sL_idx])
                
        # Add leaves switch + spine switch links
        for sS_idx in range(N/2):
            for sL_idx in range(N):
                self.addLink(l_switch[sL_idx], s_switch[sS_idx])



                
# This is for "mn --custom"
topos = { 'mytopo': ( lambda: FatTreeTopo() ) }


# This is for "python *.py"
if __name__ == '__main__':
    setLogLevel( 'info' )
    
    # 0. get the N
    if len(sys.argv) != 2:
        print "Usage: python p2.py <N>"
        exit()
    N = int(sys.argv[1])

    if N % 2 != 0:
        print "Please enter even number: N"
        exit()
    
    topo = FatTreeTopo(N)
    net = Mininet(topo=topo, link=TCLink, controller=None)
    
    # 1. Start mininet
    net.start()
    
    # Wait for links setup
    print "\nWaiting for links to setup . . . .",
    sys.stdout.flush()
    for time_idx in range(3):
        print ".",
        sys.stdout.flush()
        sleep(1)
    
    info( '\n*** Running CLI\n' )
    CLI( net )
    
    net.stop()
