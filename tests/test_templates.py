from flask import Flask
from app import register_blueprints


def test_about():
    app = Flask(__name__)
    register_blueprints(app)
    assert '200 OK' == app.test_client().get('/about').status


def test_settings():
    app = Flask(__name__)
    register_blueprints(app)
    assert '200 OK' == app.test_client().get('/settings').status


def test_modules():
    app = Flask(__name__)
    register_blueprints(app)
    assert '200 OK' == app.test_client().get('/modules').status


def test_404():
    app = Flask(__name__)
    register_blueprints(app)
    assert '404 NOT FOUND' == app.test_client().get('/asdasdasdasfdaf').status
