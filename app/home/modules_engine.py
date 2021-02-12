from app.home.modules import digits_counter, url_length, subdomains_counter, first_level_subdomain_is_allowed, \
    domain_lifetime
from .modules import modules_list


def test_url(url):
    modules_results = {
        modules_list[0]: digits_counter(url),
        modules_list[1]: url_length(url),
        modules_list[2]: subdomains_counter(url),
        modules_list[3]: first_level_subdomain_is_allowed(url),
        modules_list[4]: domain_lifetime(url)
    }
    return modules_results
