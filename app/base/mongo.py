from pymongo import MongoClient


class PyMongo(object):
    def __init__(self, app=None):
        self.mongo = None
        self.app = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.extensions = getattr(app, 'extensions', {})
        self.uri = 'mongodb://%s:%s/%s' % (
            app.config['MONGODB_SETTINGS']['host'], app.config['MONGODB_SETTINGS']['port'],
            app.config['MONGODB_SETTINGS']['DB'])
        self.db = MongoClient(self.uri)
        app.extensions['mongo'] = self.db
        self.app = app
