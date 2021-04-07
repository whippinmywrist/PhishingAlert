import zmq
import pickle

class ZMQ(object):
    def __init__(self, app=None):
        self.zmq = None
        self.app = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.extensions = getattr(app, 'extensions', {})
        self._connect(app)
        app.extensions['zmq'] = self.zmq
        self.app = app

    def _connect(self, app):
        context = zmq.Context()
        self.zmq = context.socket(app.config['ZMQ_SOCKET_TYPE'])
        self.zmq.connect(app.config['ZMQ_BIND_ADDR'])

    def __getattr__(self, attr):
        return getattr(self.zmq, attr)

    def send(self, data):
        self.zmq.send(pickle.dumps(data))
        return 'Ok'