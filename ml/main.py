from sklearn.datasets import make_classification
from sklearn.linear_model import SGDClassifier
from sklearn.neighbors import (NeighborhoodComponentsAnalysis, KNeighborsClassifier)
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn import *
import pickle
import json
import zmq
from pymongo import MongoClient
import os


# import matplotlib.pyplot as plt


def run_daemon():
    context = zmq.Context()
    receiver = context.socket(zmq.PULL)
    receiver.connect(ZMQ_ML_ADDR)
    while True:
        try:
            command = pickle.loads(receiver.recv())
            if command == 'fit':
                X, y = get_data_from_db()
                print("Refitting model...")
                fit_model(X, y)
            elif command == 'predict':
                print('Predict requested...')
                X, y, d = get_data_from_db(part_of_data='Not predicted')
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
        d = []
        for line in inputed_json:
            y.append(inputed_json[line]['verdict'])
            inputed_json[line].pop('verdict')
            X.append(list(inputed_json[line].values()))
            d.append(line)

        return X, y, d
    if part_of_data == 'Not predicted':
        domains_list = list(analyzed_domains.find({'user_verdict': None}))
        inputed_json = {}
        for domain in domains_list:
            inputed_json.update({domain['url']: domain['data']})
        X = []
        y = []
        d = []
        for line in inputed_json:
            X.append(list(inputed_json[line].values()))
            d.append(line)
        return X, y, d


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
    else:
        MONGO_HOST = 'localhost'
        ZMQ_ML_ADDR = 'tcp://localhost:43000'
    mongo = MongoClient(MONGO_HOST, 27017)
    db = mongo['phishing-alert']
    modules_collection = db['modules']
    analyzed_domains = db['analyzed-domains']
    modules_list_collection = db['modules_list']
    # clf = SGDClassifier(loss="hinge", penalty="l2", max_iter=100000)
    # clf = svm.SVC(probability=True)
    # clf = make_pipeline(StandardScaler(), LinearSVC(random_state=0, tol=1e-5))
    clf = RandomForestClassifier(n_estimators=10)
    print('Initializating data...')
    X, y, d = get_data_from_db()
    # clf = RandomForestClassifier(max_depth=2, random_state=0)
    print("Fitting...")
    fit_model(X, y)
    print("Running daemon on " + ZMQ_ML_ADDR)
    run_daemon()
