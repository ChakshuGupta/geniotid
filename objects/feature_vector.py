class FeatureVector:

    def __init__(self):
        """
        Initialise the 5 features extracted from each packet.
        """
        self.sport = None
        self.dport = None
        self.tcp_flags = []
        self.dns_queries = []
        self.entropy = []
        self.max_inter_arrival_time = 0
        self.sleep_time = 0
        self.avg_entropy = 0