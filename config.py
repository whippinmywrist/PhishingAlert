import os


class Config(object):
    DEBUG = False
    TESTING = False
    basedir = os.path.abspath(os.path.dirname(__file__))
    MONGODB_SETTINGS = {
        'DB': 'PhishingAlert',
        'host': 'localhost',
        'port': 27017,
    }
    ALLOWED_FIRST_LEVEL_DOMAINS = ['ru', 'рф']
    SECRET_KEY = os.urandom(32)


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
