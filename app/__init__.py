from flask import Flask
from importlib import import_module
from app.base.zmq import ZMQ
from app.base.mongo import PyMongo

zmq = ZMQ()
mongo = PyMongo()


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
    mongo.init_app(app)
    return app
