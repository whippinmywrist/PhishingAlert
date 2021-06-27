from flask import render_template, make_response, request, jsonify
from app.base import blueprint
from app import mongo, user_verdict_to_domain_processor
import re

regx = re.compile(r"generated.*", re.IGNORECASE)

@blueprint.route('/')
def index():
    domains = list(mongo.db['phishing-alert']['analyzed-domains'].find(
        {'$or': [{'user_verdict': 'Bad', 'url': {'$not': regx}},
                 {'ml-verdict': 'Bad', 'url': {'$not': regx}}]}).sort('datetime', -1))
    return render_template('index.html', domains=list(domains))


@blueprint.route('/good_domains')
def good_domains():
    domains = list(mongo.db['phishing-alert']['analyzed-domains'].find(
        {'$or': [{'user_verdict': 'Good', 'url': {'$not': regx}},
                 {'ml-verdict': 'Good', 'url': {'$not': regx}}]}).sort('datetime', -1))
    return render_template('good_domains.html', domains=list(domains))


@blueprint.route('/approve', methods=['POST'])
def good_domain_user_approve():
    user_verdict_to_domain_processor(request.json['domain'], request.json['verdict'])
    return jsonify('Ok')
