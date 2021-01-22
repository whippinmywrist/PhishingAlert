from app import create_app
from config import config_dict
from decouple import config
from app import register_blueprints

DEBUG = config('DEBUG', default=True, cast=bool)
get_config_mode = 'Debug' if DEBUG else 'Production'
app_config = config_dict[get_config_mode.capitalize()]

app = create_app(app_config)
register_blueprints(app)

if __name__ == '__main__':
    app.run()
