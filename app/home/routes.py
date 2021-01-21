from app.home import blueprint
from flask import render_template, redirect, url_for, request
from flask_login import login_required, current_user
from app import login_manager
from jinja2 import TemplateNotFound


@blueprint.route('/<template>')
def route_template(template):
    try:
        if not template.endswith('.html'):
            template += '.html'
        # Serve the file (if exists) from app/templates/FILE.html
        return render_template(template)
    except TemplateNotFound:
        return render_template('404.html'), 404
    except:
        return render_template('500.html'), 500
