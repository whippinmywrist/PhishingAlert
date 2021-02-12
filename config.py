import os
import zmq


class Config(object):
    DEBUG = False
    TESTING = False
    basedir = os.path.abspath(os.path.dirname(__file__))
    MONGODB_SETTINGS = {
        'DB': 'phishing-alert',
        'host': 'localhost',
        'port': 27017,
    }
    SECRET_KEY = os.urandom(32)
    ZMQ_BIND_ADDR = 'tcp://127.0.0.1:43001'
    ZMQ_SOCKET_TYPE = zmq.PUSH


class ProductionConfig(Config):
    pass


class DebugConfig(Config):
    DEBUG = True


class TestConfig(Config):
    TESTING = True


config_dict = {
    'Production': ProductionConfig,
    'Debug': DebugConfig,
    'Testing': TestConfig
}
