from domain_processor import modules
from app import db
import os
import sys

sys.path.insert(0, 'domain_processor/')

test_obj = modules.test_url_c('https://google.com', db)
test_obj_err = modules.test_url_c('https://kldsngkldfklafkls.com', db)


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
    assert "module_phishing_database" in test_obj.db.list_collection_names()


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
    assert test_obj.favicon() is not None

def test_dispatch():
    assert test_obj.dispatch('digits_counter') == 0
    assert test_obj.dispatch('digits_counter') is not None
