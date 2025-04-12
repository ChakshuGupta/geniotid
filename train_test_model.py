import numpy as np
import os
import pandas as pd
import pickle

from sklearn.ensemble import RandomForestClassifier

def train_model(x_train, y_train):

    clf = RandomForestClassifier(n_estimators=121, max_depth=13)
    clf.fit(x_train, y_train)

    return clf

def save_model(model, idx, outputdir = "."):
    """ Function to save the model in files"""
    if not os.path.exists(outputdir):
        os.makedirs(outputdir)
    
    model_file = os.path.join(outputdir, "model-" +str(idx)+".sav")
    pickle.dump(model, open(model_file, 'wb'))


def test_model(model, x_test, y_test):
    y_pred = model.predict(x_test)
    y_prob = model.predict_proba(x_test)

    return y_pred, y_prob