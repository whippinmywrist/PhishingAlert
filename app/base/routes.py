from flask import render_template
from app.base import blueprint
from app import analyzed_domains
from bson.json_util import dumps

@blueprint.route('/')
def index():
    domains = list(analyzed_domains.find().sort('datetime', -1))
    for dom in domains:
        print(dom)
    return render_template('index.html', domains=list(domains))
