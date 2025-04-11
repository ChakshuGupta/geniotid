import os
import sys

from process_data import process_pcap, get_flows
from util import get_pcap_list

if __name__ == "__main__":
    if len(sys.argv) < 1:
        print("ERROR! THe script requires the path to the dataset.")
        exit(1)

    dataset_path = sys.argv[1]
    device_name = sys.argv[2]
    if not os.path.isdir(dataset_path):
        print("ERROR! The given path is not a directory.")
        exit(1)
    
    pcap_list = get_pcap_list(dataset_path)

    packets = process_pcap(pcap_list)

    get_flows(packets)

    # for flow, data in features.items():
    #     print(f"Flow: {flow}")
    #     # print(data)
