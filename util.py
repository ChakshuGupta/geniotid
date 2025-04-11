import math
import os

def get_pcap_list(dataset_dir):
    """
    Get the list of pcap files in the directory
    """
    pcap_files = []

    for root, dirs, files in os.walk(dataset_dir):
        for file in files:
            if file.endswith(".pcap") or file.endswith(".pcapng"):
                pcap_files.append(os.path.join(root, file))
    pcap_files.sort()
    return pcap_files


def calculate_entropy(domain):
    """
    Calculate the entropy
    """
    if not domain:
        return 0
    prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum(p * math.log2(p) for p in prob)
