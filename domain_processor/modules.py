from urllib.parse import urlparse, urljoin
import whois
import datetime
import alexa_siterank
import tarfile
import os
import re
from io import BytesIO
import requests
import tldextract
import itertools
import pydig
import socket
from pysafebrowsing import SafeBrowsing
from bs4 import BeautifulSoup
from googlesearch import search
from ssl import PROTOCOL_TLSv1
from OpenSSL import SSL


class test_url_c:
    def __init__(self, url, db):
        self.url = url
        url_extract = tldextract.extract(url)
        self.subdomain = url_extract.subdomain
        self.domain = url_extract.domain
        self.tld = url_extract.suffix
        self.db = db

        self.typosquatting_result = []

        self.mx = pydig.query(urlparse(self.url).netloc, 'MX')
        try:
            self.HEADERS = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) '
                              'AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/33.0.1750.152 Safari/537.36'
            }

            self.response = requests.get(self.url, headers=self.HEADERS)
            self.response.raise_for_status()
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except Exception as e:
            self.response = ""
            self.soup = None
            print('ERROR: HTTP-GET request for ' + self.url + ' failed: ', e)

        self.user_urls = [x['url'] for x in list(self.db['analyzed-domains'].find({'user_domain': True})).copy()]

        self.qwerty = {
            '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7',
            '9': '0oi8', '0': 'po9',
            'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7',
            'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
            'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu',
            'k': 'olmji', 'l': 'kop',
            'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
        self.qwertz = {
            '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7zt5', '7': '8uz6', '8': '9iu7',
            '9': '0oi8', '0': 'po9',
            'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6zgfr5', 'z': '7uhgt6', 'u': '8ijhz7',
            'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
            'a': 'qwsy', 's': 'edxyaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'zhbvft', 'h': 'ujnbgz', 'j': 'ikmnhu',
            'k': 'olmji', 'l': 'kop',
            'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
        self.azerty = {
            '1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7',
            '9': '0oi8', '0': 'po9',
            'a': '2zq1', 'z': '3esqa2', 'e': '4rdsz3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7',
            'i': '9okju8', 'o': '0plki9', 'p': 'lo0m',
            'q': 'zswa', 's': 'edxwqz', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'iknhu',
            'k': 'olji', 'l': 'kopm', 'm': 'lp',
            'w': 'sxq', 'x': 'wsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhj'
        }
        self.glyphs = {
            '2': ['ƻ'],
            '5': ['ƽ'],
            'a': ['à'],
            'b': ['d', 'lb', 'ʙ'],
            'c': ['e'],
            'd': ['b', 'cl', 'dl'],
            'e': ['c'],
            'f': ['ƒ'],
            'g': ['q', 'ɡ'],
            'h': ['lh', 'b'],
            'i': ['1', 'l'],
            'j': ['ʝ'],
            'k': ['lk', 'ik', 'lc'],
            'l': ['1', 'i'],
            'm': ['n', 'nn', 'rn', 'rr'],
            'n': ['m', 'r'],
            'o': ['0'],
            'p': ['ƿ'],
            'q': ['g'],
            'r': ['ʀ', 'ɼ'],
            's': ['ꜱ'],
            't': ['ţ'],
            'u': ['ᴜ'],
            'v': ['ᴠ'],
            'w': ['vv', 'ᴡ'],
            'x': ['ẋ', 'ẍ'],
            'y': ['ʏ'],
            'z': ['ʐ']
        }
        self.keyboards = [self.qwerty, self.qwertz, self.azerty]
        script_dir = os.path.dirname(__file__)
        with open(os.path.join(script_dir, 'dictionaries/dictionary')) as f:
            dictionary = set(f.read().splitlines())
            self.dictionary = [x for x in dictionary if x.isalnum()]
        with open(os.path.join(script_dir, 'dictionaries/tld')) as f:
            tld_dictionary = set(f.read().splitlines())
            self.tld_dictionary = [x for x in tld_dictionary if x.isalnum()]

        from core import modules_list_collection
        self.allowed_zones = \
            modules_list_collection.find_one({'module': 'First-level subdomain is allowed'})['settings'][
                'ALLOWED_FIRST_LEVEL_DOMAINS']
        self.GOOGLE_SAFE_BROWSING_API_KEY = \
            modules_list_collection.find_one({'module': 'Google Safe Browsing'})['settings'][
                'GOOGLE_SAFE_BROWSING_API_KEY']

    # Modules
    def digits_counter(self):
        return sum([1 for s in self.url if s.isdigit()]), None

    def url_length(self):
        try:
            parse_result = urlparse(self.url)
            return len(parse_result.netloc), None
        except Exception as e:
            print(e)
            return None, e

    def subdomains_counter(self):
        try:
            parse_result = urlparse(self.url)
            return len(parse_result.netloc.split(".")) - 2, None
        except Exception as e:
            print(e)
            return None, e

    def first_level_subdomain_is_allowed(self):
        try:
            parse_result = urlparse(self.url)
            return True if parse_result.netloc.split(".")[-1] in self.allowed_zones else False, None
        except Exception as e:
            print(e)
            return None, e

    def domain_lifetime(self):
        try:
            domain = whois.query(urlparse(self.url).netloc)
            lifetime = datetime.datetime.now() - domain.creation_date
            return lifetime.days, None
        except Exception as e:
            print(e)
            return None, e

    def alexa_top1m(self):
        try:
            rank = alexa_siterank.getRank(self.url)['rank']['global']
            if not rank:
                rank = 100000000000
            return rank, None
        except Exception as e:
            print(e)
            return None, e

    def phishing_database(self):
        try:
            def update_phishing_database():
                def write_to_mongo():
                    with tarfile.open(fileobj=BytesIO(response.raw.read()), mode="r:gz") as tar_file:
                        for member in tar_file.getmembers():
                            f = tar_file.extractfile(member).read()
                            docs = []
                            for x in f.split():
                                docs.append({
                                    'domain': x.decode('utf-8')
                                })
                            module_phishing_database.insert_many(docs)

                phishing_database_url = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/ALL' \
                                        '-phishing-domains.tar.gz'

                response = requests.get(phishing_database_url, stream=True)
                if "module_phishing_database" in self.db.list_collection_names():
                    last_update = module_phishing_database.find({}).sort("_id", -1).limit(1)[0]['_id'].generation_time
                    if datetime.datetime.now(datetime.timezone.utc) - last_update > datetime.timedelta(hours=2):
                        write_to_mongo()
                else:
                    write_to_mongo()

            module_phishing_database = self.db['module_phishing_database']

            update_phishing_database()

            url_result = urlparse(self.url)
            domain = url_result.netloc
            domain = {'domain': domain}
            f = list(module_phishing_database.find(domain))
            if f:
                return True, None
            else:
                return False, None
        except Exception as e:
            print(e)
            return None, e

    def typosquatting(self):
        def __addition():
            result = []
            for user_domain in self.user_urls:
                for i in range(97, 123):
                    result.append(user_domain[1] + chr(i))
            return result

        def __bitsquatting():
            result = []
            masks = [1, 2, 4, 8, 16, 32, 64, 128]
            for user_domain in self.user_urls:
                for i in range(0, len(user_domain[1])):
                    c = user_domain[1][i]
                    for j in range(0, len(masks)):
                        b = chr(ord(c) ^ masks[j])
                        o = ord(b)
                        if (o >= 48 and o <= 57) or (o >= 97 and o <= 122) or o == 45:
                            result.append(user_domain[1][:i] + b + user_domain[1][i + 1:])
            return result

        def __homoglyph():
            result = []
            x = []
            for user_domain in self.user_urls:
                for a in user_domain[1]:
                    temp = self.glyphs.get(a)
                    if not temp:
                        break
                    temp.append(a)
                    temp2 = temp.copy()
                    x.append(temp2)
                if x:
                    res = itertools.product(*x)
                    result.extend(["".join(x) for x in res if "".join(x) != user_domain[1]])
                    x.clear()
            return result

        def __hyphenation():
            result = []
            for user_domain in self.user_urls:
                for i in range(1, len(user_domain[1])):
                    result.append(user_domain[1][:i] + '-' + user_domain[1][i:])
            return result

        def __insertion():
            result = []
            for user_domain in self.user_urls:
                for i in range(1, len(user_domain[1]) - 1):
                    for keys in self.keyboards:
                        if user_domain[1][i] in keys:
                            for c in keys[user_domain[1][i]]:
                                result.append(user_domain[1][:i] + c + user_domain[1][i] + user_domain[1][i + 1:])
                                result.append(user_domain[1][:i] + user_domain[1][i] + c + user_domain[1][i + 1:])
            return list(set(result))

        def __omission():
            result = []
            for user_domain in self.user_urls:
                for i in range(0, len(user_domain[1])):
                    result.append(user_domain[1][:i] + user_domain[1][i + 1:])
            return list(set(result))

        def __repetition():
            result = []
            for user_domain in self.user_urls:
                for i in range(0, len(user_domain[1])):
                    if user_domain[1][i].isalnum():
                        result.append(
                            user_domain[1][:i] + user_domain[1][i] + user_domain[1][i] + user_domain[1][i + 1:])
            return list(set(result))

        def __replacement():
            result = []
            for user_domain in self.user_urls:
                for i in range(0, len(user_domain[1])):
                    for keys in self.keyboards:
                        if user_domain[1][i] in keys:
                            for c in keys[user_domain[1][i]]:
                                result.append(user_domain[1][:i] + c + user_domain[1][i + 1:])
            return list(set(result))

        def __subdomain():
            result = []
            for user_domain in self.user_urls:
                # Вот тут тоже ошибочка была братан
                for i in range(1, len(user_domain[1])):
                    if user_domain[1][i] not in ['-', '.'] and user_domain[1][i - 1] not in ['-', '.']:
                        result.append(user_domain[1][:i] + '.' + user_domain[1][i:])
            return result

        def __transposition():
            result = []
            for user_domain in self.user_urls:
                for i in range(0, len(user_domain[1]) - 1):
                    if user_domain[1][i + 1] != user_domain[1][i]:
                        result.append(
                            user_domain[1][:i] + user_domain[1][i + 1] + user_domain[1][i] + user_domain[1][i + 2:])
            return result

        def __vowel_swap():
            vowels = 'aeiou'
            result = []
            for user_domain in self.user_urls:
                for i in range(0, len(user_domain[1])):
                    for vowel in vowels:
                        if user_domain[1][i] in vowels:
                            result.append(user_domain[1][:i] + vowel + user_domain[1][i + 1:])
            return list(set(result))

        def __dictionary():
            result = []
            for user_domain in self.user_urls:
                for word in self.dictionary:
                    if not (user_domain[1].startswith(word) and user_domain[1].endswith(word)):
                        result.append(user_domain[1] + '-' + word)
                        result.append(user_domain[1] + word)
                        result.append(word + '-' + user_domain[1])
                        result.append(word + user_domain[1])
            return list(set(result))

        def __tld():
            if self.tld in self.tld_dictionary:
                self.tld_dictionary.remove(self.tld)
            return list(set(self.tld_dictionary))

        def __tld_duplicate():
            result = []
            for user_domain in self.user_urls:
                result.append(user_domain[1] + '-' + self.tld)
            return result

        if not self.user_urls:
            return False

        for i, url in enumerate(self.user_urls):
            t = tldextract.extract(url)
            self.user_urls[i] = [t.subdomain, t.domain, t.suffix]

        for domain in __addition():
            self.typosquatting_result.append(
                {'fuzzer': 'addition', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
        for domain in __bitsquatting():
            self.typosquatting_result.append(
                {'fuzzer': 'bitsquatting', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
        for domain in __homoglyph():
            self.typosquatting_result.append(
                {'fuzzer': 'homoglyph', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
        for domain in __hyphenation():
            self.typosquatting_result.append(
                {'fuzzer': 'hyphenation', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
        for domain in __insertion():
            self.typosquatting_result.append(
                {'fuzzer': 'insertion', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
        for domain in __omission():
            self.typosquatting_result.append(
                {'fuzzer': 'omission', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
        for domain in __repetition():
            self.typosquatting_result.append(
                {'fuzzer': 'repetition', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
        for domain in __replacement():
            self.typosquatting_result.append(
                {'fuzzer': 'replacement', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
        for domain in __subdomain():
            # Вот тут тоже ошибочка была братан
            self.typosquatting_result.append(
                {'fuzzer': 'subdomain', 'domain-name': '.'.join(filter(None, [domain, self.tld]))})
        for domain in __transposition():
            self.typosquatting_result.append(
                {'fuzzer': 'transposition', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
        for domain in __vowel_swap():
            self.typosquatting_result.append(
                {'fuzzer': 'vowel-swap', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
        for domain in __dictionary():
            self.typosquatting_result.append(
                {'fuzzer': 'dictionary', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})

        for domain in __tld_duplicate():
            self.typosquatting_result.append(
                {'fuzzer': 'tld_duplicate', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})

        for tld in __tld():
            self.typosquatting_result.append(
                {'fuzzer': 'tld-swap', 'domain-name': '.'.join(filter(None, [self.subdomain, self.domain, tld]))})
        if '.' in self.tld:
            self.typosquatting_result.append(
                {'fuzzer': 'various', 'domain-name': self.domain + '.' + self.tld.split('.')[-1]})
            self.typosquatting_result.append({'fuzzer': 'various', 'domain-name': self.domain + self.tld})
        if '.' not in self.tld:
            self.typosquatting_result.append(
                {'fuzzer': 'various', 'domain-name': self.domain + self.tld + '.' + self.tld})
        # еще ошибка
        self.typosquatting_result.append(
            {'fuzzer': 'various', 'domain-name': self.domain + '-' + self.tld + '.' + self.tld})
        # Find in generated domains:
        # print([x for x in self.typosquatting_result if x['fuzzer'] == 'subdomain'])
        for domain in self.typosquatting_result:
            if domain['domain-name'] == '.'.join(filter(None, [self.subdomain, self.domain, self.tld])):
                return True, None
        return False, None

    def dig_mx(self):
        try:
            return True if self.mx else False, None
        except Exception as e:
            print(e)
            return None, e

    def dig_ns(self):
        try:
            ns = pydig.query(urlparse(self.url).netloc, 'NS')
            return True if ns else False, None
        except Exception as e:
            print(e)
            return None, e

    def tls_cert_valid(self):
        host = self.url
        host = host.replace('http://', '').replace('https://', '').replace('/', '')
        port = 443
        if ':' in host:
            host, port = host.split(':')
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            osobj = SSL.Context(PROTOCOL_TLSv1)
            sock.connect((host, int(port)))
            oscon = SSL.Connection(osobj, sock)
            oscon.set_tlsext_host_name(host.encode())
            oscon.set_connect_state()
            oscon.do_handshake()
            cert = oscon.get_peer_certificate()
            sock.close()
            if cert.has_expired():
                return False, None
            else:
                return True, None
        except SSL.SysCallError:
            print('Failed: Misconfigured SSL/TLS for host: ', host)
            return False, None
        except Exception as e:
            print(e)
            return False, None

    def google_sb(self):
        try:
            if self.GOOGLE_SAFE_BROWSING_API_KEY == '':
                return False, None
            s = SafeBrowsing(self.GOOGLE_SAFE_BROWSING_API_KEY)
            r = s.lookup_urls([self.url])
            return r[self.url]['malicious'], None
        except Exception as e:
            ex = 'ERROR: Google Safe Browsing ,' + str(e)
            print(ex)
            return None, ex

    def google_search_index(self):
        try:
            response = search("site:" + self.url)
            if response:
                return True, None
            else:
                return False, None
        except Exception as e:
            ex = 'ERROR: Google Search: ,' + str(e)
            print(ex)
            return None, ex

    def favicon(self):
        try:
            # Get /favicon.ico
            favicon_url = urljoin(self.url, 'favicon.ico')
            response = requests.head(favicon_url, headers=self.HEADERS, allow_redirects=True)
            if response.status_code == 200:
                return True, None
            # Get favicon from html tags
            if self.soup is None:
                return False, None
            LINK_RELS = [
                'icon',
                'shortcut icon',
                'apple-touch-icon',
                'apple-touch-icon-precomposed',
            ]
            META_NAMES = ['msapplication-TileImage', 'og:image']
            link_tags = set()
            for rel in LINK_RELS:
                for link_tag in self.soup.find_all(
                        'link', attrs={'rel': lambda r: r and r.lower() == rel, 'href': True}
                ):
                    link_tags.add(link_tag)
            meta_tags = set()
            for meta_tag in self.soup.find_all('meta', attrs={'content': True}):
                meta_type = meta_tag.get('name') or meta_tag.get('property') or ''
                meta_type = meta_type.lower()
                for name in META_NAMES:
                    if meta_type == name.lower():
                        meta_tags.add(meta_tag)

            for tag in link_tags | meta_tags:
                href = tag.get('href', '') or tag.get('content', '')
                href = href.strip()

                if not href or href.startswith('data:image/'):
                    continue
                return True, None
        except Exception as e:
            print('ERROR: Favicon module error - ', e)
            return False, e


    def dispatch(self, value):
        method_name = str(value)
        method = getattr(self, method_name)
        return method()
