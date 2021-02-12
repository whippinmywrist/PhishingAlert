from urllib.parse import urlparse
import whois
import datetime


modules_list = ['Number of digits in the domain name', 'Total URL length', 'Number of subdomains',
                'First-level subdomain is allowed', 'Domain lifetime']


def digits_counter(url):
    return sum([1 for s in url if s.isdigit()])


def url_length(url):
    try:
        parse_result = urlparse(url)
        return len(parse_result.netloc)
    except Exception as e:
        print(e)
        return None


def subdomains_counter(url):
    try:
        parse_result = urlparse(url)
        return len(parse_result.netloc.split(".")) - 2
    except Exception as e:
        print(e)
        return None


def first_level_subdomain_is_allowed(url):
    try:
        from core import modules_collection
        allowed_zones = modules_collection.find_one({'ALLOWED_FIRST_LEVEL_DOMAINS': {'$exists': True}})[
            'ALLOWED_FIRST_LEVEL_DOMAINS']
        parse_result = urlparse(url)
        return True if parse_result.netloc.split(".")[-1] in allowed_zones else False
    except Exception as e:
        print(e)
        return None


def domain_lifetime(url):
    try:
        domain = whois.query(urlparse(url).netloc)
        lifetime = datetime.datetime.now() - domain.creation_date
        return lifetime.days
    except Exception as e:
        print(e)
        return None