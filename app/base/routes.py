from flask import render_template
from app.base import blueprint


@blueprint.route('/')
def index():
    return render_template('index.html', segment='index')
