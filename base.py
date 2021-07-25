import logging

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import arp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv6
from ryu.lib.packet import icmpv6
from ryu.lib.packet import packet_base
from ryu.lib.packet import packet_utils
from netaddr import *



class NAT(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """ OpenFlow 1.3 NAT implementation with IPv6 """
        super(NAT, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        """
        Hardcoding adresses here which will be received through NBI app
            ip_one
            ip_two
            out_port1
            in_port2
            nat_src
            nat_dst
            dp1
            dp2
            dp3
        """

    def remove_flows(self, datapath, table_id=0):
        """ Removing all flow entries """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid = datapath.id
        flow_mod = parser.OFPFlowMod(datapath=datapath,
                                     dpid=dpid,
                                     cookie=0,
                                     table_id=table_id,
                                     ofproto.OFPFC_DELETE,
                                     0, 0,
                                     priority=1,
                                     ofproto.OFPCML_NO_BUFFER,
                                     ofproto.OFPP_ANY,
                                     ofproto.OFPG_ANY, 0,
                                     match, instructions)
        datapath.send_msg(flow_mod)


    def add_flow(self, datapath, match, actions, priority, hard_timeout=0):
        """ Adding flow entries """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                            actions)]
        flow_mod = parser.OFPFlowMod(datapath=datapath,
                                     priority=priority,
                                     match=match,
                                     instructions=inst,
                                     hard_timeout=hard_timeout,
                                     cookie=0,
                                     cookie_mask=2,
                                     command=ofproto.OFPFC_ADD)
        datapath.send_msg(flow_mod)
        self.logger.debug("add_flow:"+str(flow_mod))


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        ETH_TYPE_ARP = 0x0806
        ETH_TYPE_IPV4 = 0x0800
        ETH_TYPE_IPV6 = 0x86dd
        dp = ev.msg.datapath
        dpid = dp.id
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        self.logger.info("switch connected %s", dp)

        # On inital connect - delete all flows as a precaution
        self.remove_flows(dp)

        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]

        # Add common rules to all DPNs so packets don't get dropped
        # ARP
        match = parser.OFPMatch(eth_type=ETH_TYPE_ARP)
        self.add_flow(dp, match, actions, priority=0)

        # ICMPv6
        match = parser.OFPMatch(eth_type=ETH_TYPE_IPV6, ip_proto=58)
        self.add_flow(dp, match, actions, priority=0)

        # ICMP
        match = parser.OFPMatch(eth_type=ETH_TYPE_IPV4, ip_proto=1)
        self.add_flow(dp, match, actions, priority=0)

        #TCP
        match = parser.OFPMatch(eth_type=ETH_TYPE_IPV4, ip_proto=6)
        self.add_flow(dp, match, actions, priority=0)

        #UDP
        match = parser.OFPMatch(eth_type=ETH_TYPE_IPV4, ip_proto=17)
        self.add_flow(dp, match, actions, priority=0)

        #TCPv6
        match = parser.OFPMatch(eth_type=ETH_TYPE_IPV6, ip_proto=6)
        self.add_flow(dp, match, actions, priority=0)

        #UDPv6
        match = parser.OFPMatch(eth_type=ETH_TYPE_IPV6, ip_proto=17)
        self.add_flow(dp, match, actions, priority=0)


        if typeofrule == 'Forward':
            if dpid1 == 1:  # Root PEP (Add real DPID from the switch)

                match = parser.OFPMatch(eth_type=ETH_TYPE_IPV6,
                                        ip_proto=58,
                                        ipv6_dst=ip_one)
                actions = [parser.OFPActionOutput(out_por1)]
                self.add_flow(dp1, match, actions, priority=1)

                match = parser.OFPMatch(eth_type=ETH_TYPE_IPV6,
                                        ip_proto=58,
                                        ipv6_src=ip_two)
                actions = [parser.OFPActionOutput(in_port2)]
                self.add_flow(dp1, match, actions, priority=1)


            if dpid2 == 2:    # Edge PEP1 (Add real DPID from the switch)

                match = parser.OFPMatch(eth_type=ETH_TYPE_IPV6,
                                        ip_proto=58,
                                        ipv6_dst=ip_one)
                actions = [parser.OFPActionOutput(out_port1)]
                self.add_flow(dp2, match, actions, priority=1)

                match = parser.OFPMatch(eth_type=ETH_TYPE_IPV6,
                                        ip_proto=58,
                                        ipv6_src=ip_two)
                actions = [parser.OFPActionOutput(in_port2)]
                self.add_flow(dp2, match, actions, priority=1)


        elif typeofrule == 'NAT6':
            if dpid1 == 1:

                match = parser.OFPMatch(eth_type=ETH_TYPE_IPV6,
                                        ip_proto=58,
                                        ipv6_src=ip_two)
                actions = [parser.OFPActionSetField(ipv6_src=nat_src),
                            parser.OFPActionOutput(in_port2)]
                self.add_flow(dp1, match, actions, priority=1)

                match = parser.OFPMatch(eth_type=ETH_TYPE_IPV6,
                                        ip_proto=58,
                                        ipv6_dst=ip_one)
                actions = [parser.OFPActionSetField(ipv6_dst=nat_dst),
                            parser.OFPActionOutput(out_port1)]
                self.add_flow(dp1, match, actions, priority=1)

            if dpid3 == 3:    # Edge PEP2 (Add real DPID from the switch)
                match = parser.OFPMatch(eth_type=ETH_TYPE_IPV6,
                                        ip_proto=58,
                                        ipv6_dst=ip_one)
                actions = [parser.OFPActionSetField(ipv6_dst=nat_dst),
                            parser.OFPActionOutput(out_port1)]
                self.add_flow(dp3, match, actions, priority=1)

                match = parser.OFPMatch(eth_type=ETH_TYPE_IPV6,
                                        ip_proto=58,
                                        pv6_src=ip_two)
                actions = [parser.OFPActionSetField(ipv6_src=nat_src),
                            parser.OFPActionOutput(in_port2)]
                self.add_flow(dp3, match, actions, priority=1)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.logger.info("msg in")
        message = ev.msg
        self.logger.info("message %s", message)
        datapath = message.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(message.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        in_port = message.match['in_port']
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
