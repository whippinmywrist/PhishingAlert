import os


class Config(object):
    basedir = os.path.abspath(os.path.dirname(__file__))


class ProductionConfig(Config):
    DEBUG = False


class DebugConfig(Config):
    DEBUG = True


class TestConfig(Config):
    TESTING = True

config_dict = {
    'Production': ProductionConfig,
    'Debug': DebugConfig,
    'Testing': TestConfig
}
