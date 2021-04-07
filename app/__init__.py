from flask import Flask
from importlib import import_module
from flask_login import LoginManager
from pymongo import MongoClient
from app.base.zmq import ZMQ

login_manager = LoginManager()
zmq = ZMQ()
mongo = MongoClient(host='localhost', port=27017)
db = mongo['phishing-alert']
modules_collection = db['modules']
analyzed_domains = db['analyzed-domains']


def user_verdict_to_domain_processor(domain, user_verdict):
    if isinstance(domain, str):
        data = {
            'action': 'user_approve',
            'domain': domain,
            'user_verdict': user_verdict
        }
        s = zmq.send(data)
        print(s)
    else:
        raise ValueError


def register_blueprints(app):
    for module_name in ('base', 'home'):
        module = import_module('app.{}.routes'.format(module_name))
        app.register_blueprint(module.blueprint)


def create_app(config):
    app = Flask(__name__, static_folder='home/static')
    app.config.from_object(config)
    zmq.init_app(app)
    return app
