import json

from objects.packet import Packet

class Flow(object):

    def __init__(self):
        """
        Initialise an empty packet
        """
        # intiialise src and dest IPs
        self.sip = None
        self.dip = None
        # initialise src and dest ports
        self.sport = None
        self.dport = None
        # initialise protocol and ethType
        self.proto = None
        
        self.time_start = None
    
        self.dns_queries = list()
        self.entropy = list()
        self.packets = list()
        self.tcp_flags = list()

    def print(self):
        """
        """
        data = {
            'sip' : self.sip,
            'dip' : self.dip,
            'sport' : self.sport,
            'dport' : self.dport,
            'ip_proto' : self.proto,
            'time_start': self.time_start
        }
        print(json.dumps(data, indent=4))

    def add(self, pkt):
        """
        Add a packet to the flow using IPs and Port numbers
        """

        if self.sip is not None:
            if {self.sip, self.dip} != {pkt.sip, pkt.dip} and\
                  {self.sport, self.dport} != {pkt.sport, pkt.dport}:
                return
        # Set endpoints for the flow            
        elif pkt.sport > pkt.dport:
            self.sip = pkt.sip
            self.dip = pkt.dip

            self.sport = pkt.sport
            self.dport = pkt.dport
        
        else:
            self.sip = pkt.dip
            self.dip = pkt.sip

            self.sport = pkt.dport
            self.dport = pkt.sport

        self.proto = pkt.proto

        # Add packet to the flow
        self.packets.append((pkt.time, pkt))
        
        if len(self.dns_queries) != 0:
            self.dns_queries.extend(pkt.dns_queries)
        else:
            self.dns_queries.append(None)

        if len(pkt.entropy) != 0:
            self.entropy.extend(pkt.entropy)
        else:
            self.entropy.append(0)

        self.tcp_flags.append(pkt.tcp_flags)

        return self