from app.home import blueprint
from flask import render_template, redirect, url_for, request, jsonify
from flask_login import login_required, current_user
from app import login_manager
from jinja2 import TemplateNotFound
import urllib.request
from app.home.modules_engine import modules_list
from app import zmq


@blueprint.route('/manual/add')
def modules_test():
    url = request.args.get('url', type=str)
    try:
        urllib.request.urlopen(url)
        data = {
            'action': 'test_url',
            'url': url
        }
        zmq.send(data)

    except Exception as e:
        print(e)
        return render_template('manual.html', test=False, url=url, error=e)
    return render_template('manual.html', url=url, add=True)


@blueprint.route('/settings')
def settings():
    return render_template('settings.html', result=dict((k, None) for k in modules_list))


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
