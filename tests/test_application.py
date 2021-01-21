from flask import Flask
import sys
from app import register_blueprints
from app import create_app
from config import config_dict


def test_python_version():
    """Application runs under Python 3.9."""
    assert 3 == sys.version_info.major
    assert 9 == sys.version_info.minor


def test_create_app():
    get_config_mode = 'TESTING'
    app_config = config_dict[get_config_mode.capitalize()]
    app = create_app(app_config)


def test_index_200():
    """Makes sure the front page returns HTTP 200.
    A very basic test, if the front page is broken, something has obviously failed.
    """
    app = Flask(__name__)
    register_blueprints(app)
    assert '200 OK' == app.test_client().get('/').status