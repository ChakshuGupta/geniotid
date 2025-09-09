import tldextract

from scapy.all import *
from util import calculate_entropy


class Packet(object):

    def __init__(self, pkt):
        """
        Initialise an empty packet and extract the fields from the pkt
        if its not None.
        """
        # intiialise src and dest IPs
        self.sip = None
        self.dip = None
        # initialise src and dest ports
        self.sport = None
        self.dport = None
        self.tcp_flags = None
        # initialise protocol
        self.proto = None
        self.eth_type = None
        # initialise packet length
        self.length = None
        # initialise packet time
        self.time = None

        self.dns_queries = list()
        self.entropy = list()

        if pkt is not None:
            # Extract the fields and set the values for the class variables
            self.extract_fields(pkt)
    
    def extract_fields(self, pkt):
        """
        Extract the relevant fields from the packet

        [Arg]
        pkt: scapy packet
        """
        self.eth_type = self.get_eth_type(pkt)

        self.sip = pkt['IP'].src if pkt.haslayer('IP') else None
        self.dip = pkt['IP'].dst if pkt.haslayer('IP') else None
        self.proto = pkt['IP'].proto if pkt.haslayer('IP') else None

        if self.proto == 6:
            self.sport = pkt['TCP'].sport
            self.dport = pkt['TCP'].dport
            self.tcp_flags  = int(pkt['TCP'].flags)
        elif self.proto == 17:
            self.sport = pkt['UDP'].sport
            self.dport = pkt['UDP'].dport
        
        self.time = pkt.time

        if 'DNS' in pkt and pkt["DNS"].qd is not None:
            self.get_dns_queries(pkt["DNS"].qd)
        

    def get_eth_type(self, pkt):
        """
        If Ethernet layer exists, get ethernet type

        [Arg]
        pkt: scapy packet

        [Returns]
        eth_type: Ethernet type in the hex
        """
        if pkt.haslayer('Ethernet'):
            eth_type = hex(pkt['Ethernet'].type)[:2] + '0' + hex(pkt['Ethernet'].type)[2:]
        else:
            eth_type = "*"
        return eth_type
    

    def is_none(self):
        """
        Check if any of the main comparable fields of the packet is None.

        [Returns]
        True: if one of the fields is None
        False: if none of the fiels id None
        """

        if self.sip is None or self.dip is None or self.sport is None or self.dport is None or self.proto is None or self.eth_type is None:
            return True
        else:
            return False
        
    def get_dns_queries(self, queries):
        """
        Get the DNS queries, if the packet is of type DNS
        """
        for query in queries:
            domain_info = tldextract.extract(query.qname.decode("utf-8"))
            second_level = domain_info.domain
            self.dns_queries.append(query.qname.decode("utf-8"))
            if second_level.strip() != "":
                entropy = calculate_entropy(second_level)
                self.entropy.append(entropy)