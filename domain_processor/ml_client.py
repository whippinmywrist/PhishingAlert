import zmq
import pickle

class MLCommandSender:
    def __init__(self):
        context = zmq.Context()
        self.sender = context.socket(zmq.PUSH)
        self.sender.bind('tcp://127.0.0.1:43000')

    def fit(self):
        self.sender.send(pickle.dumps(('fit')))
        return "OK: fit sended"

    def predict(self):
        self.sender.send(pickle.dumps(('predict')))
        return "OK: predict sended"