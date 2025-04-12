import json
import numpy as np
import os
import pandas as pd
import pickle
import sys

from sklearn.metrics import classification_report
from sklearn.model_selection import StratifiedKFold

from process_data import process_pcap, get_flows
from train_test_model import train_model, save_model, test_model
from util import get_pcap_list

if __name__ == "__main__":
    if len(sys.argv) < 1:
        print("ERROR! THe script requires the path to the dataset.")
        exit(1)

    dataset_path = sys.argv[1]
    
    if not os.path.isdir(dataset_path):
        print("ERROR! The given path is not a directory.")
        exit(1)
    
    feature_pickle = "features.pickle"
    label_pickle = "labels.pickle"

    list_devices = os.listdir(dataset_path)

    if os.path.isfile(feature_pickle) and os.path.isfile(label_pickle):
        dataset_x = pickle.load(open(feature_pickle, 'rb')) 
        dataset_y = pickle.load(open(label_pickle, 'rb')) 

    else:
        dataset_all = pd.DataFrame()

        for device in list_devices:
            path = os.path.join(dataset_path, device)
            if os.path.isdir(path):
                pcap_list = get_pcap_list(path)
                packets = process_pcap(pcap_list)
                device_features = get_flows(packets, device)
                if dataset_all.empty:
                    dataset_all = device_features
                else:
                    dataset_all = pd.concat([dataset_all, device_features], ignore_index=True)
                print(dataset_all)

        dataset_y = dataset_all["label"]
        del dataset_all["label"]

        tcp_flags = pd.DataFrame(dataset_all["tcp_flags"].to_list())
        dns_queries = pd.DataFrame(dataset_all["dns_queries"].to_list())

        del dataset_all["tcp_flags"]
        del dataset_all["dns_queries"]

        dataset_x = pd.concat([dataset_all, tcp_flags.add_prefix("tcp_flag_"), dns_queries.add_prefix("dns_query_")], axis=1)
        print(dataset_x)

        print("Saving the extracted features into pickle files.")
        # Save the dataframes to pickle files    
        pickle.dump(dataset_x, open(feature_pickle, "wb"))
        pickle.dump(dataset_y, open(label_pickle, "wb"))

    dataset_x = np.array(dataset_x, dtype=object)
    dataset_y = np.array(dataset_y, dtype=object)

    # Declare the lists
    y_true_all = []
    y_pred_all = []
    y_prob_all = []

    # Declare the stratified k fold object
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=1111)
    idx = 0
    # Loop through the different folds
    for train_index, test_index in skf.split(dataset_x, dataset_y):
        x_train = dataset_x[train_index]
        y_train = dataset_y[train_index]
        x_test = dataset_x[test_index]
        y_test = dataset_y[test_index]
        model = train_model(x_train, y_train)
        save_model(model, idx)

        y_pred, y_prob = test_model(model, x_test)

        y_true_all.extend(y_test)
        y_pred_all.extend(y_pred)
        y_prob_all.extend(y_prob)
        idx += 1

    # Print the classification report
    report = classification_report(
                        y_true = y_true_all,
                        y_pred = y_pred_all,
                        digits = 4,
                        zero_division = 0,
                        output_dict=True
                    )
    
    report_file_path = "report.json"
    report_file = open(report_file_path, "w")
    report_file.write(json.dumps(report, indent=2))
    report_file.close()