from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import recall_score
#from sklearn import *
import pandas as pd
import pickle
import numpy as np
from dataclasses import make_dataclass
import json
import zmq
from pymongo import MongoClient
import os
import subprocess
import sweetviz as sv


# import matplotlib.pyplot as plt


def run_daemon():
    context = zmq.Context()
    receiver = context.socket(zmq.PULL)
    receiver.connect(ZMQ_ML_ADDR)
    while True:
        try:
            command = pickle.loads(receiver.recv())
            if command == 'fit':
                X, y, d, columns = get_data_from_db()
                print("Refitting model...")
                fit_model(X, y)
            elif command == 'predict':
                print('Predict requested...')
                X, y, d, columns = get_data_from_db(part_of_data='Not predicted')
                result = clf.predict(X)
                # result3 = clf.predict([[0, 9, 0, True, 297911, False, True, True, True, True]])
                result2 = clf.predict_log_proba(X)
                for i, domain in enumerate(d):
                    document = {
                        "ml-verdict": result[i]
                    }
                    analyzed_domains.update_one({'url': domain}, {'$set': document}, upsert=True)
                print(result, result2)
        except Exception as e:
            print(e)


def get_data_from_db(part_of_data='All'):
    if part_of_data == 'All':
        analyzed_domains_list = list(analyzed_domains.find({}))
        inputed_json = {}
        for domain in analyzed_domains_list:
            if domain.get('user_verdict') == 'Good':
                domain['data'].update({'verdict': 'Good'})
            elif domain.get('user_verdict') == 'Bad':
                domain['data'].update({'verdict': 'Bad'})
            else:
                continue
            inputed_json.update({domain['url']: domain['data']})

        X = []
        y = []
        domains = []
        _, columns = list(inputed_json.items())[0]
        columns = list(columns.keys())
        for line in inputed_json:
            y.append(inputed_json[line]['verdict'])
            inputed_json[line].pop('verdict')
            X.append(list(inputed_json[line].values()))
            domains.append(line)

        return X, y, domains, columns
    if part_of_data == 'Not predicted':
        domains_list = list(analyzed_domains.find({'user_verdict': None}))
        inputed_json = {}
        for domain in domains_list:
            inputed_json.update({domain['url']: domain['data']})
        X = []
        y = []
        d = []
        _, columns = list(inputed_json.items())[0]
        columns = list(columns.keys())
        for line in inputed_json:
            X.append(list(inputed_json[line].values()))
            d.append(line)
        return X, y, d, columns


def fit_model(X, y):
    clf.fit(X, y)
    pickle.dump(clf, open('ml_model.pkl', 'wb'))
    # print(clf.coef_)
    return "OK"


if __name__ == '__main__':
    print("Connecting to the DB...")
    if os.getenv('PRODUCTION') == '1':
        MONGO_HOST = 'mongo'
        ZMQ_ML_ADDR = 'tcp://domain_processor:43000'
        DB_NAME = 'phishing-alert'
    else:
        MONGO_HOST = 'localhost'
        ZMQ_ML_ADDR = 'tcp://localhost:43000'
        DB_NAME = 'phishing-alert-test'
    mongo = MongoClient(MONGO_HOST, 27017)
    db = mongo[DB_NAME]
    modules_collection = db['modules']
    analyzed_domains = db['analyzed-domains']
    modules_list_collection = db['modules_list']
    print('Initializating data...')
    subprocess.call(['python', 'db_inserting_tool.py'])
    clf = RandomForestClassifier(n_estimators=10)
    X, y, d, columns = get_data_from_db()
    DomainData = make_dataclass("DomainData", [("Number_of_digits_in_the_domain_name", int), ("Total_URL_length", int),
                                               ("Number_of_subdomains", int),
                                               ("First_level_subdomain_is_allowed", bool),
                                               ("Alexa_Top_1M_position", int), ("Phishing_Database", bool),
                                               ("Typosquatting", bool), ("MX_record_is_present", bool),
                                               ("NS_record_is_present", bool), ("TLS_Certificate_valid", bool),
                                               ("Google_Safe_Browsing", bool), ("Google_Search_index", bool),
                                               ("Favicon", bool)])
    t = []
    for line in X:
        t.append(DomainData(*line))
    data_x = pd.DataFrame(t)
    data_y = pd.DataFrame(y)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.50, random_state = 2020, stratify=y)
    ss = StandardScaler()
    X_train_scaled = ss.fit_transform(X_train)
    X_test_scaled = ss.transform(X_test)
    rfc = RandomForestClassifier()
    rfc.fit(X_train_scaled, y_train)
    print(rfc.score(X_test_scaled, y_test))
    #datamodel_report = sv.analyze(data_x)
    #datamodel_report.show_html()
    print("Fitting...")
    fit_model(X, y)
    print("Running daemon on " + ZMQ_ML_ADDR)
    run_daemon()
