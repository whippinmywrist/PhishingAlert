from pymongo import MongoClient
import random
import os

if os.getenv('PRODUCTION') == '1':
        MONGO_HOST = 'mongo'
        ZMQ_ML_ADDR = 'tcp://domain_processor:43000'
        DB_NAME = 'phishing-alert'
else:
    MONGO_HOST = 'localhost'
    ZMQ_ML_ADDR = 'tcp://localhost:43000'
    DB_NAME = 'phishing-alert-test'
mongo = MongoClient(MONGO_HOST, 27017)
db = mongo[DB_NAME]
modules_collection = db['modules']
analyzed_domains = db['analyzed-domains']
if analyzed_domains.count_documents({}) < 2000:
    for i in range(0, 2000):
        weight = 0.0
        verdict = False
        Number_of_digits_in_the_domain_name = random.randrange(7)
        Total_URL_length = random.randrange(35)
        Number_of_subdomains = random.randrange(5)
        if Number_of_digits_in_the_domain_name > 4:
            weight += 1
        if Total_URL_length > 25:
            weight += 0.5
        if Number_of_subdomains > 3:
            weight += 1
        First_level_subdomain_is_allowed = bool(random.getrandbits(1))
        if First_level_subdomain_is_allowed is False:
            weight += 2
        Phishing_Database = bool(random.getrandbits(1))
        if Phishing_Database:
            verdict = True
        Typosquatting = bool(random.getrandbits(1))
        if Typosquatting:
            verdict = True
        MX_record_is_present = bool(random.getrandbits(1))
        if not MX_record_is_present:
            weight += 0.5
        NS_record_is_present = bool(random.getrandbits(1))
        if not NS_record_is_present:
            weight += 0.5
        TLS_Certificate_valid = bool(random.getrandbits(1))
        if not TLS_Certificate_valid:
            weight += 1
        Google_Safe_Browsing = bool(random.getrandbits(1))
        if Google_Safe_Browsing:
            verdict = True
        Google_Search_index = bool(random.getrandbits(1))
        if not Google_Search_index:
            weight += 3
        Favicon = bool(random.getrandbits(1))
        if not Favicon:
            weight += 0.5
        if random.randrange(100) < int(weight*10):
            verdict = True
        if verdict:
            t = bool(random.getrandbits(1))
            if t:
                Alexa_Top_1M_position = 1000000000
            else:
                Alexa_Top_1M_position = random.randint(100000, 1000000)
        data = {
            "url": "generated" + str(i),
            "data": {
                "Number of digits in the domain name": Number_of_subdomains,
                "Total URL length": Total_URL_length,
                "Number of subdomains": Number_of_subdomains,
                "First-level subdomain is allowed": First_level_subdomain_is_allowed,
                "Alexa Top 1M position": Alexa_Top_1M_position,
                "Phishing Database": Phishing_Database,
                "Typosquatting": Typosquatting,
                "MX record is present": MX_record_is_present,
                "NS record is present": NS_record_is_present,
                "TLS Certificate valid": TLS_Certificate_valid,
                "Google Safe Browsing": Google_Safe_Browsing,
                "Google Search index": Google_Search_index,
                "Favicon": Favicon
            },
            "user_verdict": "Bad" if verdict else "Good",
            "user_domain": False
        }
        analyzed_domains.insert_one(data)

