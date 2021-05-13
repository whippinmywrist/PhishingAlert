import datetime
import os
import sys
from multiprocessing import Process
from time import sleep

from app import create_app, zmq
from app.base.mongo import PyMongo
from pymongo import DESCENDING, CursorType
from config import config_dict
from domain_processor import modules

sys.path.insert(0, 'domain_processor/')
import core
from main import server

get_config_mode = 'TESTING'
app_config = config_dict[get_config_mode.capitalize()]
app = create_app(app_config)
mongo = PyMongo()
mongo.init_app(app)
db = mongo.db['phishing-alert']

# Prepare testing collection
db_testing = mongo.db['phishing-alert-test']
if "modules_list" not in db_testing.list_collection_names():
    core.db_init(db_testing)

GOOGLE_SAFE_BROWSING_API_KEY = db_testing['modules_list'].find({'module': 'Google Safe Browsing'})[0]['settings'][
    'GOOGLE_SAFE_BROWSING_API_KEY']
if GOOGLE_SAFE_BROWSING_API_KEY == '':
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    if GOOGLE_SAFE_BROWSING_API_KEY is not None:
        print('Google Safe Browsing API key received from environment variable')
    else:
        print('\033[33m' + 'WARNING! Google Safe Browsing API key is empty. Some tests may fail. ' + '\033[0m')
        GOOGLE_SAFE_BROWSING_API_KEY = input('Please enter API key: ')

test_obj = modules.test_url_c('https://google.com', db_testing)
test_obj_err = modules.test_url_c('https://kldsngkldfklafkls.com', db_testing)
test_obj.user_urls = ['google.com']


def test_module_preprocessor():
    assert test_obj.domain == 'google'
    assert test_obj.subdomain == ''
    assert test_obj.tld == 'com'
    assert test_obj.mx is not None
    assert test_obj.soup is not None
    assert test_obj.user_urls is not None


def test_module_preprocessor_error():
    assert test_obj_err.soup is None


def test_digits_counter():
    assert test_obj.digits_counter() == 0


def test_url_length():
    assert test_obj.url_length() == 10


def test_url_length_error():
    test_obj.url = 1
    assert test_obj.url_length() is None
    test_obj.url = 'https://google.com'


def test_subdomains_counter():
    assert test_obj.subdomains_counter() == 0
    test_obj.url = 'https://a.b.c.google.com'
    assert test_obj.subdomains_counter() == 3
    test_obj.url = 'https://google.com'


def test_subdomains_counter_error():
    test_obj.url = 1
    assert test_obj.subdomains_counter() is None
    test_obj.url = 'https://google.com'


def test_domain_lifetime():
    assert test_obj.domain_lifetime() is not None
    assert isinstance(test_obj.domain_lifetime(), int) is True


def test_first_level_subdomain_is_allowed():
    assert isinstance(test_obj.first_level_subdomain_is_allowed(), bool) is True


def test_alexa_top1m():
    assert test_obj.alexa_top1m() is not None
    assert test_obj.alexa_top1m() != 100000000000


def test_phishing_database():
    assert test_obj.phishing_database() is False
    assert "module_phishing_database" in test_obj.db.list_collection_names()
    assert test_obj.phishing_database() is False


def test_typosquatting_addition():
    # TODO: расширить список для тестов
    test_domains = ['googlea.com']
    for domain in test_obj.typosquatting_result:
        assert domain['domain-name'] in test_domains


def test_typosquatting_bitsquatting():
    # TODO: Написать тесты для тайпосквоттинга
    pass


def test_mx():
    assert test_obj.dig_mx() is not None
    assert test_obj.dig_mx() is True


def test_ns():
    assert test_obj.dig_ns() is not None
    assert test_obj.dig_ns() is True


def test_tls_cert_valid():
    assert test_obj.tls_cert_valid() is True


def test_google_sb():
    assert test_obj.GOOGLE_SAFE_BROWSING_API_KEY != ''
    assert test_obj.google_sb() is not None
    assert test_obj.google_sb() is False


def test_google_sb_err():
    assert test_obj_err.GOOGLE_SAFE_BROWSING_API_KEY != ''
    assert test_obj_err.google_sb() is not None
    assert test_obj_err.google_sb() is False


def test_google_search_index():
    assert test_obj.google_search_index() is True
    assert test_obj.google_search_index() is not None


def test_google_search_index_err():
    assert test_obj_err.google_search_index() is False
    assert test_obj_err.google_search_index() is not None


def test_favicon():
    assert test_obj.favicon() is True


def test_dispatch():
    assert test_obj.dispatch('digits_counter') == 0
    assert test_obj.dispatch('digits_counter') is not None


def test_DP_ZMQ():
    domain_processor = Process(target=server, args=('tcp://127.0.0.1:43001',))
    domain_processor.start()
    print('process spawned')
    sleep(1)

    def send_to_zmq(test_urls):
        data = {
            'action': 'add_bulk',
            'urls': test_urls,
            'user_domain': False
        }
        zmq.send(data)

    db_testing['analyzed-domains'].drop()
    send_to_zmq(['https://facebook.com', 'https://google.com'])
    oplog = db_testing['process']

    def wait_dp():
        first = oplog.find().sort('$natural', DESCENDING).limit(1).next()
        temp_id = first['_id']
        while True:
            cursor = oplog.find({'_id': {'$gt': temp_id}},
                                cursor_type=CursorType.TAILABLE_AWAIT,
                                oplog_replay=True)
            while cursor.alive:
                for doc in cursor:
                    temp_id = doc['_id']
                    print(doc)
                    if doc['msg'] == 'Testing completed':
                        return 0
                # We end up here if the find() returned no documents or if the
                # tailable cursor timed out (no new documents were added to the
                # collection for more than 1 second).
                sleep(1)

    wait_dp()
    send_to_zmq(['https://amazon.com', 'https://wikipedia.org'])
    wait_dp()
    sleep(3)
    domain_processor.kill()
    urls = [x['url'] for x in list(db_testing['analyzed-domains'].find()).copy()]
    assert {'https://amazon.com', 'https://wikipedia.org', 'https://facebook.com', 'https://google.com'} == set(
        urls)
