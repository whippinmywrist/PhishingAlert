from flask import Flask
from importlib import import_module
from flask_login import LoginManager
from flask_mongoengine import MongoEngine

login_manager = LoginManager()


def register_blueprints(app):
    for module_name in ('base', 'home'):
        module = import_module('app.{}.routes'.format(module_name))
        app.register_blueprint(module.blueprint)


def create_app(config):
    app = Flask(__name__, static_folder='home/static')
    app.config.from_object(config)
    db = MongoEngine()
    db.init_app(app)

    return app
