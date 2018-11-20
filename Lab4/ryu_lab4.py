from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib


from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib import mac
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

import networkx as nx
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

import enum

priority_list={'miss':0, 'STP': 1, 'ARP': 2, 'TCP': 2, 'UDP': 2, 'Block': 3}


class Lab4(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #_CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(Lab4, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        #self.stp = kwargs['stplib']
        
        self.net=nx.DiGraph()
        self.topology_api_app = self
        self.id2dp = dict()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority_list['miss'], match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        
    def add_mst_drop_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]

        mod = parser.OFPFlowMod(datapath=datapath, cookie=1, cookie_mask=0xFF, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        
    def add_drop_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)
            
    def delete_drop_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        mod = parser.OFPFlowMod(
            datapath, cookie=1, cookie_mask=0xFF, command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
            priority=priority_list['STP'], match=match)
        datapath.send_msg(mod)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
        
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
    #@set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    #def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        
        pk_arp = pkt.get_protocol(arp.arp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        

        if pk_arp:
            if (src not in self.net.nodes):
                self.AddHosts(src, datapath.id, in_port)
            
            print("[ARP] arrive at ", datapath.id, dst)
            if dst in self.net.nodes:
                
                try:
                    path = nx.shortest_path(self.net,src,dst)
                except:
                    for edge in self.net.edges:
                        print (edge)
                    print ("Not found ",datapath.id,dst)
                    return;
               
                # Install rules on shortest path if path is found
                for idx in range(1, len(path)-1):
                    preID = path[idx-1]
                    targetID = path[idx]
                    targetDp = self.id2dp[targetID]
                    nextID = path[idx+1]
                    data = msg.data
                    
                    in_port=self.net[targetID][nextID]['port'] 
                    out_port = self.net[targetID][preID]['port']
                    actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(eth_type=0x0806, eth_dst=src)
                    self.add_flow(targetDp, priority_list['ARP'], match, actions)
                    
                    actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
                    match = parser.OFPMatch(eth_type=0x0806, eth_dst=dst)
                    self.add_flow(targetDp, priority_list['ARP'], match, actions)
                    print("[ARP] Add arp flows: ", targetID, nextID)
                # Packet out
                nextID = path[path.index(datapath.id)+1]
                out_port = self.net[datapath.id][nextID]['port']
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions)
                datapath.send_msg(out)
            else:
                out_port = ofproto.OFPP_FLOOD

                actions = [parser.OFPActionOutput(out_port)]

                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                print("[ARP] Flood")
                
                
        elif pkt_icmp:
            print("[ICMP] arrive at ", datapath.id)
            src_host_list = [n for n in self.net.neighbors(src)]
            src_sw_id = src_host_list[0]
            
            dst_host_list = [n for n in self.net.neighbors(dst)]
            dst_sw_id = dst_host_list[0]
            path = self.DumpShortestPathIcmpTCP(src_sw_id, dst_sw_id)
            path.append(dst)
            
            for idx in range(1, len(path)):
                fromID = path[idx-1]
                fromDp = self.id2dp[fromID]
                nextID = path[idx]
                data = msg.data
                
                out_port = self.net[fromID][nextID]['port']
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_type=0x0800, ip_proto = pkt_ipv4.proto, eth_dst=dst)
                self.add_flow(fromDp, priority_list['ARP'], match, actions)
                print("[ICMP] Add icmp flows: ", fromID, nextID)
                
                
            nextID = path[path.index(datapath.id)+1]
            out_port = self.net[datapath.id][nextID]['port']
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
        
        elif pkt_tcp:
            print("[TCP] arrive at ", datapath.id, dst)
            src_host_list = [n for n in self.net.neighbors(src)]
            src_sw_id = src_host_list[0]

            
            if (src_sw_id == 2 or src_sw_id == 4) and (pkt_tcp.dst_port == 80):
                
                mypkt = packet.Packet()

                mypkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,src=dst,dst=src))
                mypkt.add_protocol(ipv4.ipv4(src=pkt_ipv4.dst,dst=pkt_ipv4.src,proto=6))
                mypkt.add_protocol(tcp.tcp(src_port=pkt_tcp.dst_port,
                                         dst_port=pkt_tcp.src_port,
                                         ack=pkt_tcp.seq+1,
                                         bits=0b010100))

                self._send_packet(datapath, in_port, mypkt)
                print("TCP: Reject connection")
            
            else:
                dst_host_list = [n for n in self.net.neighbors(dst)]
                dst_sw_id = dst_host_list[0]
                path = self.DumpShortestPathIcmpTCP(src_sw_id, dst_sw_id)
                path.append(dst)
                
                for idx in range(1, len(path)):
                    fromID = path[idx-1]
                    fromDp = self.id2dp[fromID]
                    nextID = path[idx]
                    data = msg.data
                    
                    out_port = self.net[fromID][nextID]['port']
                    actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(eth_type=0x0800, ip_proto = pkt_ipv4.proto, eth_dst=dst)
                    self.add_flow(fromDp, priority_list['TCP'], match, actions)
                    print("[TCP] Add tcp flows: ", fromID, nextID)
                
                nextID = path[path.index(datapath.id)+1]
                out_port = self.net[datapath.id][nextID]['port']
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
            
        elif pkt_udp:
            print("[UDP] arrive at ", datapath.id)
            src_host_list = [n for n in self.net.neighbors(src)]
            src_sw_id = src_host_list[0]
            
            dst_host_list = [n for n in self.net.neighbors(dst)]
            dst_sw_id = dst_host_list[0]
            path = self.DumpShortestPathIcmpTCP(src_sw_id, dst_sw_id)
            path.append(dst)
            
            for idx in range(1, len(path)):
                fromID = path[idx-1]
                fromDp = self.id2dp[fromID]
                nextID = path[idx]
                data = msg.data
                
                out_port = self.net[fromID][nextID]['port']
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_type=0x0800, ip_proto = pkt_ipv4.proto, eth_dst=dst)
                self.add_flow(fromDp, priority_list['UDP'], match, actions)
                print("[UDP] Add udp flows: ", fromID, nextID)
                
                
            nextID = path[path.index(datapath.id)+1]
            out_port = self.net[datapath.id][nextID]['port']
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
    
    def DumpShortestPathIcmpTCP(self, src_dpid, dst_dpid):
        path = []
        if abs(src_dpid-dst_dpid)==1:
            path = [src_dpid, dst_dpid]
            
        else:
            next_hop = 0
            
            if src_dpid == 1:
                next_hop = 4
            elif src_dpid == 2:
                next_hop = 1
            elif src_dpid == 3:
                next_hop = 4
            elif src_dpid == 4:
                next_hop = 1

            path = [src_dpid, next_hop, dst_dpid]
            
        return path
        
    def DumpShortestPathUDP(self, src_dpid, dst_dpid):
        path = []
        if abs(src_dpid-dst_dpid)==1:
            path = [src_dpid, dst_dpid]
            
        else:
            next_hop = 0
            
            if src_dpid == 1:
                next_hop = 2
            elif src_dpid == 2:
                next_hop = 3
            elif src_dpid == 3:
                next_hop = 2
            elif src_dpid == 4:
                next_hop = 3

            path = [src_dpid, next_hop, dst_dpid]
            
        return path

###############################################
    #'''
    @set_ev_cls([event.EventSwitchEnter,event.EventPortAdd,event.EventPortModify])
    def GetTopologyData(self, ev):

        switchesList = get_switch(self.topology_api_app, None)
        linksList = get_link(self.topology_api_app, None)
        self.PopulateNet(switchesList, linksList)
        
     
    def PopulateNet(self, switchesList, linksList):
        for switch in switchesList:
            self.id2dp[switch.dp.id] = switch.dp
        self.net.add_nodes_from([switch.dp.id for switch in switchesList])

        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in linksList]
        self.net.add_edges_from(links)
        links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in linksList]
        self.net.add_edges_from(links)
        
        
        net_graph=nx.Graph()
        net_graph.add_nodes_from([switch.dp.id for switch in switchesList])
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in linksList]
        net_graph.add_edges_from(links)
        
        
        span_tree=nx.minimum_spanning_tree(net_graph)
        remove_edges = [edge for edge in net_graph.edges if edge not in span_tree.edges]
        
        #'''
        # Redo the spanning tree
        for switch in switchesList:
            self.delete_drop_flow(switch.dp)
        
        for edge in remove_edges:
            in_port = self.net[edge[0]][edge[1]]['port']
            parser = self.id2dp[edge[0]].ofproto_parser
            match = parser.OFPMatch(in_port=in_port)
            self.add_mst_drop_flow(self.id2dp[edge[0]], priority_list['STP'], match)
            
            in_port = self.net[edge[1]][edge[0]]['port']
            parser = self.id2dp[edge[1]].ofproto_parser
            match = parser.OFPMatch(in_port=in_port)
            self.add_mst_drop_flow(self.id2dp[edge[1]], priority_list['STP'], match)
            
            print("[MST] Add dropping flows: ", edge[0], edge[1])
        
        #'''
        
        # Reject TCP
        for switch in switchesList:
            if switch.dp.id==2 or switch.dp.id==4:
                idx = switch.dp.id
                
                '''
                actions = [self.id2dp[idx].ofproto_parser.OFPActionOutput(self.id2dp[idx].ofproto.OFPP_CONTROLLER)]
                match = self.id2dp[idx].ofproto_parser.OFPMatch(in_port=1,eth_type=0x0800, ip_proto = 0x06, tcp_src=80)
                self.add_flow(self.id2dp[idx], priority_list['Block'], match, actions)
                '''
                
                actions = [self.id2dp[idx].ofproto_parser.OFPActionOutput(self.id2dp[idx].ofproto.OFPP_CONTROLLER)]
                match = self.id2dp[idx].ofproto_parser.OFPMatch(in_port=1,eth_type=0x0800, ip_proto = 0x06, tcp_dst=80)
                self.add_flow(self.id2dp[idx], priority_list['Block'], match, actions)
                print("[TCP] Add drop flows: ", idx)
                
        # Reject UDP
        for switch in switchesList:
            if switch.dp.id==1 or switch.dp.id==4:
                idx = switch.dp.id
                match = self.id2dp[idx].ofproto_parser.OFPMatch(in_port=1,eth_type=0x0800, ip_proto = 17)
                self.add_drop_flow(self.id2dp[idx], priority_list['Block'], match)
                print("[UDP] Add drop flows: ", idx)
        
    ################################################

    def AddHosts(self, srcMAC, datapathID, port):
        self.net.add_node(srcMAC)
        
        self.net.add_edge(datapathID,srcMAC,port=port)

        self.net.add_edge(srcMAC,datapathID)