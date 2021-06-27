import asyncio
import datetime
import pickle
import os
import sys
import zmq
from pymongo import MongoClient, UpdateOne, DESCENDING
from tornado import ioloop

from modules import test_url_c
from ml_client import MLCommandSender


def test_url(url, database, step, step_max, test_id=1):
    dp = test_url_c(url, database)
    modules_results = {}
    # Insert current testing status into the "process" collection
    oplog.insert_one(
        {'msg': 'Test for ' + url + ' has started', 'step': step, 'step_max': step_max, "id": test_id,
         "status": "In process"})
    for i, module in enumerate(modules_list):
        # Getting result from modules
        result, e = dp.dispatch(defs[i])
        step += 1
        if result is not None:
            modules_results.update({module: result})
            # Insert current testing status into the "process" collection
            oplog.insert_one(
                {'msg': url + ' - ' + module + ': ' + str(result), 'step': step, 'step_max': step_max, "id": test_id,
                 "status": "In process"})
        else:
            oplog.insert_one(
                {'msg': url + ' - ' + module + ': ' + str(e), 'step': step, 'step_max': step_max, "id": test_id,
                 "status": "In process"})
    return modules_results


def add(url):
    print('testing ' + url + "...")
    step = 0
    document = {'url': url,
                'data': test_url(url, db, step, len(modules_list), 1),
                'datetime': datetime.datetime.now(),
                'ml-verdict': 'Not tested'
                }
    analyzed_domains.replace_one({'url': url}, document, upsert=True)
    return True


def add_bulk(urls, user_domain=False):
    # TODO: Завязать каждый анализ на ID
    # TODO: Допилить фронт (результаты, сраная очередь)
    bulk = []
    step = 0
    step_max = len(urls) * len(modules_list)
    last_log = oplog.find().sort('$natural', DESCENDING).limit(1).next()
    test_id = last_log['id'] + 1
    print('TESTID: ', test_id)
    for url in urls:
        if url == '':
            continue
        if '://' not in url:
            url = 'http://' + url
        if user_domain:
            user_verdict = "Good"
            document = {'url': url,
                        'data': test_url(url, db, step, step_max, test_id),
                        'datetime': datetime.datetime.now(),
                        'user_verdict': user_verdict,
                        'user_domain': user_domain
                        }
        else:
            document = {'url': url,
                        'data': test_url(url, db, step, step_max, test_id),
                        'datetime': datetime.datetime.now()
                        }
        step += len(modules_list)
        bulk.append(document)
    oplog.insert_one({'msg': 'Testing completed', 'step': step, 'step_max': step_max, 'id': test_id, "status": "Ready"})
    upserts = [UpdateOne({'url': x['url']}, {'$set': x}, upsert=True) for x in bulk]
    if len(upserts) != 0:
        analyzed_domains.bulk_write(upserts)
    ml.fit()
    return True


def user_approve(domain, user_verdict):
    document = {
        'user_verdict': user_verdict
    }
    analyzed_domains.update_one({'url': domain}, {'$set': document}, upsert=True)
    print(ml.fit())


def db_init(db_for_init):
    modules_list = [{'module': 'Number of digits in the domain name', 'settings': None, 'def': 'digits_counter'},
                    {'module': 'Total URL length', 'settings': None, 'def': 'url_length'},
                    {'module': 'Number of subdomains', 'settings': None, 'def': 'subdomains_counter'},
                    {'module': 'First-level subdomain is allowed',
                     'settings': {'ALLOWED_FIRST_LEVEL_DOMAINS': ['ru', 'рф']},
                     'def': 'first_level_subdomain_is_allowed'},
                    {'module': 'Domain lifetime', 'settings': None, 'def': 'domain_lifetime'},
                    {'module': 'Alexa Top 1M position', 'settings': None, 'def': 'alexa_top1m'},
                    {'module': 'Phishing Database',
                     'settings': {
                         'database_file': 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/'
                                          'ALL-phishing-domains.tar.gz'}, 'def': 'phishing_database'
                     },
                    {'module': 'MX record is present', 'settings': None, 'def': 'dig_mx'},
                    {'module': 'NS record is present', 'settings': None, 'def': 'dig_ns'},
                    {'module': 'TLS Certificate valid', 'settings': None, 'def': 'tls_cert_valid'},
                    {'module': 'Google Safe Browsing', 'settings': {'GOOGLE_SAFE_BROWSING_API_KEY': ''},
                     'def': 'google_sb'},
                    {'module': 'Google Search index', 'settings': None, 'def': 'google_search_index'},
                    {'module': 'Favicon', 'settings': None, 'def': 'favicon'}]
    db_for_init['modules_list'].insert_many(modules_list)


def echo(sock, events):
    # We don't know how many recv's we can do?
    if not sock.EVENTS & zmq.POLLIN:
        # not a read event
        return
    msg = sock.recv_multipart()
    msg = pickle.loads(msg[0])
    print(msg['action'])
    if msg['action'] == 'add':
        add(msg['url'])
        print('action add')
    if msg['action'] == 'add_bulk':
        print('action add_bulk')
        add_bulk(msg['urls'], msg['user_domain'])
    if msg['action'] == 'user_approve':
        print('action: user_approve')
        user_approve(msg['domain'], msg['user_verdict'])
    # avoid starving due to edge-triggered event FD
    # if there is more than one read event waiting
    if sock.EVENTS & zmq.POLLIN:
        ioloop.IOLoop.current().add_callback(echo, sock, events)


async def dot():
    """callback for showing that IOLoop is still responsive while we wait"""
    while True:
        sys.stdout.write('.')
        sys.stdout.flush()
        await asyncio.sleep(3)


if os.getenv('PRODUCTION') == '1':
    ZMQ_ML_ADDR = 'tcp://0.0.0.0:43000'
    MONGO_ADDR = 'mongo'
    DB_NAME = 'phishing-alert'
else:
    ZMQ_ML_ADDR = 'tcp://127.0.0.1:43000'
    MONGO_ADDR = 'localhost'
    DB_NAME = 'phishing-alert-test'
mongo = MongoClient(MONGO_ADDR, 27017)
db = mongo[DB_NAME]
modules_collection = db['modules']
analyzed_domains = db['analyzed-domains']
modules_list_collection = db['modules_list']
if "modules_list" not in db.list_collection_names():
    db_init(db)
oplog = db['process']
if "process" not in db.list_collection_names():
    db.create_collection("process", capped=True, size=100000)
    oplog.insert_one({'msg': 'DB is ready', 'step': 0, 'step_max': 100, "id": 1, "status": "Ready"})
cursor = modules_list_collection.find({})
modules_a = list(cursor).copy()
modules_c = list(modules_a).copy()
modules_list = [x['module'] for x in modules_a]
defs = [y['def'] for y in modules_c]
if __name__ == "main":
    ml = MLCommandSender(ZMQ_ML_ADDR)
