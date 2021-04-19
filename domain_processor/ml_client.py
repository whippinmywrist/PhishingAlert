import zmq
import pickle

class MLCommandSender:
    def __init__(self, ZMQ_ML_ADDR):
        print(ZMQ_ML_ADDR)
        context = zmq.Context()
        self.sender = context.socket(zmq.PUSH)
        self.sender.bind(ZMQ_ML_ADDR)

    def fit(self):
        self.sender.send(pickle.dumps(('fit')))
        return "OK: fit sended"

    def predict(self):
        self.sender.send(pickle.dumps(('predict')))
        return "OK: predict sended"