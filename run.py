import os

from app import create_app
from config import config_dict
from decouple import config
from app import register_blueprints
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.log import enable_pretty_logging

if os.getenv('PRODUCTION') is None:
    DEBUG = config('DEBUG', default=True, cast=bool)
else:
    DEBUG = False
get_config_mode = 'Debug' if DEBUG else 'Production'
app_config = config_dict[get_config_mode.capitalize()]

app = create_app(app_config)
register_blueprints(app)

if __name__ == '__main__':
    http_server = HTTPServer(WSGIContainer(app))
    http_server.listen(port=5000, address='0.0.0.0')
    enable_pretty_logging()
    IOLoop.current().start()

