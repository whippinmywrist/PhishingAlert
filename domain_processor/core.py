import zmq, sys
from tornado import ioloop
import asyncio
import datetime
import pickle
from pymongo import MongoClient
from modules import modules_list
from modules import digits_counter, url_length, subdomains_counter, first_level_subdomain_is_allowed, \
    domain_lifetime


def test_url(url):
    modules_results = {
        modules_list[0]: digits_counter(url),
        modules_list[1]: url_length(url),
        modules_list[2]: subdomains_counter(url),
        modules_list[3]: first_level_subdomain_is_allowed(url),
        modules_list[4]: domain_lifetime(url)
    }
    return modules_results


def echo(sock, events):
    # We don't know how many recv's we can do?
    if not sock.EVENTS & zmq.POLLIN:
        # not a read event
        return
    msg = sock.recv_multipart()
    msg = pickle.loads(msg[0])
    if msg['action'] == 'test_url':
        print('testing ' + msg['url'] + "...")
        document = {'url': msg['url'],
                    'data': test_url(msg['url']),
                    'datetime': datetime.datetime.now(),
                    'ml-verdict': 'Not tested'
                    }
        analyzed_domains.replace_one({'url': msg['url']}, document, upsert=True)

    # avoid starving due to edge-triggered event FD
    # if there is more than one read event waiting
    if sock.EVENTS & zmq.POLLIN:
        ioloop.IOLoop.current().add_callback(echo, sock, events)


async def dot():
    """callback for showing that IOLoop is still responsive while we wait"""
    while True:
        sys.stdout.write('core')
        sys.stdout.flush()
        await asyncio.sleep(3)


mongo = MongoClient('localhost', 27017)
db = mongo['phishing-alert']
modules_collection = db['modules']
analyzed_domains = db['analyzed-domains']


