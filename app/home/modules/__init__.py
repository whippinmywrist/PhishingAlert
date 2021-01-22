from urllib.parse import urlparse
from run import app

modules_list = ['Number of digits in the domain name', 'Total URL length', 'Number of subdomains',
                'First-level subdomain is allowed']

def digits_counter(url):
    return sum([1 for s in url if s.isdigit()])


def url_length(url):
    try:
        parse_result = urlparse(url)
        return len(parse_result.netloc)
    except:
        return None


def subdomains_counter(url):
    try:
        parse_result = urlparse(url)
        return len(parse_result.netloc.split(".")) - 2
    except:
        return None


def first_level_subdomain_is_allowed(url):
    try:
        allowed_zones = app.config['ALLOWED_FIRST_LEVEL_DOMAINS']
        parse_result = urlparse(url)
        return True if parse_result.netloc.split(".")[-1] in allowed_zones else False
    except:
        return None
