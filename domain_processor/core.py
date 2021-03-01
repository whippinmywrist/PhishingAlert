import zmq, sys
from tornado import ioloop
import asyncio
import datetime
import pickle
from pymongo import MongoClient, UpdateOne
import modules


def test_url(url):
    dp = modules.test_url_c(url, db)
    modules_results = {}
    for i, module in enumerate(modules_list):
        modules_results.update({module: dp.dispatch(defs[i])})
    return modules_results


def add(url):
    print('testing ' + url + "...")
    document = {'url': url,
                'data': test_url(url),
                'datetime': datetime.datetime.now(),
                'ml-verdict': 'Not tested'
                }
    analyzed_domains.replace_one({'url': url}, document, upsert=True)
    return True


def add_bulk(urls, user_domain=False):
    bulk = []
    for url in urls:
        print(url)
        if url == '':
            continue
        if '://' not in url:
            url = 'http://' + url
        document = {'url': url,
                    'data': test_url(url),
                    'datetime': datetime.datetime.now(),
                    'ml-verdict': 'Not tested',
                    'user_verdict': None,
                    'user_domain': user_domain
                    }
        print(document['data'])
        bulk.append(document)
    upserts = [UpdateOne({'url': x['url']}, {'$set': x}, upsert=True) for x in bulk]
    analyzed_domains.bulk_write(upserts)

    return True


def db_init():
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
                     }]
    db['modules_list'].insert_many(modules_list)


def echo(sock, events):
    # We don't know how many recv's we can do?
    if not sock.EVENTS & zmq.POLLIN:
        # not a read event
        return
    msg = sock.recv_multipart()
    msg = pickle.loads(msg[0])
    if msg['action'] == 'add':
        add(msg['url'])
        print('action add')
    if msg['action'] == 'add_bulk':
        add_bulk(msg['urls'], msg['user_domain'])
        print('action add_bulk')
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


mongo = MongoClient('localhost', 27017)
db = mongo['phishing-alert']
modules_collection = db['modules']
analyzed_domains = db['analyzed-domains']
modules_list_collection = db['modules_list']
if "modules_list" not in db.list_collection_names():
    db_init()
cursor = modules_list_collection.find({})
modules_a = list(cursor).copy()
modules_c = list(modules_a).copy()
modules_list = [x['module'] for x in modules_a]
defs = [y['def'] for y in modules_c]
