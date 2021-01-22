from app.home import blueprint
from flask import render_template, redirect, url_for, request, jsonify
from flask_login import login_required, current_user
from app import login_manager
from jinja2 import TemplateNotFound
import urllib.request
from app.home.modules_engine import test_url, modules_list
from wtforms import StringField, Form
from wtforms.validators import DataRequired


@blueprint.route('/modules/test')
def modules_test():
    url = request.args.get('url', type=str)
    try:
        urllib.request.urlopen(url)
        result = test_url(url)
    except Exception as e:
        print(e)
        return render_template('modules.html', result=dict((k, None) for k in modules_list), test=False, url=url)
    return render_template('modules.html', result=result, test=True, url=url)


@blueprint.route('/modules')
def modules():
    return render_template('modules.html', result=dict((k, None) for k in modules_list), test=False)


@blueprint.route('/module/<name>')
def module(name):
    if name in modules_list:
        return render_template('modules/base.html', fields="fields", module_name=name, modules_list=modules_list)
    else:
        return render_template('404.html'), 404


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
