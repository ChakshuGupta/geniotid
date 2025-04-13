import numpy as np
import pandas as pd


from operator import attrgetter
from scapy.all import *
from sklearn.feature_extraction.text import TfidfVectorizer

from objects.feature_vector import FeatureVector
from objects.flow import Flow
from objects.packet import Packet


TIME_WINDOW = 3600

def process_pcap(list_pcaps):
    """
    Parse the pcap file and extracts the features from the traffic.
    """
    packets = []
    
    for pcap_file in list_pcaps:
        print("Reading file: ", pcap_file)
        capture = rdpcap(pcap_file)

        if not capture:
                raise ValueError("No packets found in the pcap file: ", pcap_file)
        
        for packet in capture:
             
             if 'IP' not in packet:
                  continue
             
             if 'TCP' not in packet and 'UDP' not in packet:
                  continue

             packet_obj = Packet(packet)
             packets.append(packet_obj)
    
    sorted_packets = sorted(packets, key=attrgetter('time'))
    return sorted_packets


def get_flows(packets, device):
    tfidf = TfidfVectorizer()
    dataset = []

    flows = dict()

    for packet in packets:                 
            flow_key = (packet.sip, packet.dip, packet.sport, packet.dport, packet.proto)
            reverse_key = (packet.dip, packet.sip, packet.dport, packet.sport, packet.proto)
            key = flow_key
            
            # Check if the flow exists in the flows dictionary
            if flow_key not in flows and reverse_key not in flows:
                flows[flow_key] = Flow()
                flows[flow_key].time_start = packet.time
            elif flow_key in flows:
                key = flow_key                   
            else:
                key = reverse_key
            
            # If the packets are within the time window, add to the flow
            if packet.time - flows[key].time_start <= TIME_WINDOW:
                    flows[key].add(packet)
            else:
                # Else, extract the features and delete it from the flows list.
                dataset.append(extract_features(flows[key], tfidf))
                del flows[key]
    
    print(len(dataset))
    if len(dataset) > 0:
        dataset_df = pd.DataFrame(dataset, columns=list(dataset[0].keys()))
        dataset_df["label"] = device
        return dataset_df
    else:
        if len(flows) > 0:
            for key in flows.keys():
                dataset.append(extract_features(flows[key], tfidf))
            dataset_df = pd.DataFrame(dataset, columns=list(dataset[0].keys()))
            dataset_df["label"] = device
            return dataset_df
        else:
            return


def extract_features(flow, tfidf):
    """
    Extract features from the traffic flows.
    """
    feature_set = FeatureVector()
    feature_set.sport = flow.sport
    feature_set.dport = flow.dport
    feature_set.tcp_flags = list(set(flow.tcp_flags))
    if len(flow.dns_queries) != 0:
        dns_queries = tfidf.fit_transform(list(set(flow.dns_queries)))
        feature_set.dns_queries = dns_queries.toarray()[0]
    else:
        feature_set.dns_queries = []

    timestamps = sorted([float(t[0]) for t in flow.packets])
    inter_arrival = np.diff(timestamps) if len(timestamps) > 1 else [0]
    feature_set.max_inter_arrival_time = max(inter_arrival) if len(inter_arrival) > 0 else 0
    feature_set.sleep_time = float(np.median(inter_arrival)) if len(inter_arrival) > 0 else 0
    feature_set.avg_entropy = float(np.mean(flow.entropy)) if flow.entropy else 0

    return feature_set.__dict__
