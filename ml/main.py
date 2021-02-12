from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
import pickle
import json
import zmq


def run_daemon():
    memory = {}

    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.bind('tcp://*:43000')

    while True:
        try:
            command, key, data = pickle.loads(socket.recv())
            if command == 'set':
                memory[key] = str(clf.predict(data))
                socket.send(b'ok')
            elif command == 'get':
                result = memory[key]
                socket.send(pickle.dumps(result))
        except Exception as e:
            print(e)


def sample_generator(json):
    X = []
    y = []
    for line in json:
        X.append(list(json[line].values())[:-1])
        y.append(json[line]['Verdict'])
    return X, y


if __name__ == '__main__':
    inputed_json = {
        "mil-ru.ru": {
            'Number of digits in the domain name': 0,
            'Total URL length': 9,
            'Number of subdomains': 0,
            'First-level subdomain is allowed': True,
            'Domain lifetime': 1521,
            'Verdict': 1
        },
        "mil.ru": {
            'Number of digits in the domain name': 0,
            'Total URL length': 6,
            'Number of subdomains': 0,
            'First-level subdomain is allowed': True,
            'Domain lifetime': 9342,
            'Verdict': 0
        }
    }
    X, y = sample_generator(inputed_json)
    clf = RandomForestClassifier(max_depth=2, random_state=0)
    clf.fit(X, y)
    pickle.dump(clf, open('ml_model.pkl', 'wb'))
    print(clf.predict([[0, 6, 0, True, 9342]]))
    run_daemon()
