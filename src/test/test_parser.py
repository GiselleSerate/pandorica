# Copyright (c) 2019, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Author: Giselle Serate <gserate@paloaltonetworks.com>

'''
Palo Alto Networks test_parser.py

Tests the parse code by verifying selected domains get written to the index
and the version is swapped to be parsed.

Run this file from the pandorica root.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

import logging
from logging.config import dictConfig
import os
from time import sleep

from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from elasticsearch_dsl import connections, Search
import requests

from domain_processor import process_domains
from notes_parser import wait_for_elastic, try_parse
from scraper import DocStatus, VersionDocument
from testcases import ParseTest


def setup_mappings(mappings_path, ip):
    '''
    Maps domain and tag caches. ELK must be up first.
    '''
    headers = {'Content-Type':'application/json'}
    logging.info("Installing domain details mapping.")
    contents = open(os.path.join(mappings_path, 'sfn-domain-details.json')).read()
    r = requests.put(f'http://{ip}:9200/sfn-domain-details/', data=contents, headers=headers)
    # Unless accepted or already mapped
    if r.status_code != 200 and r.status_code != 400:
        logging.warning("Unsuccessful write of domain details mapping.")
        logging.warning(r.text)

    logging.info("Installing tag details mapping.")
    contents = open(os.path.join(mappings_path, 'sfn-tag-details.json')).read()
    r = requests.put(f'http://{ip}:9200/sfn-tag-details/', data=contents, headers=headers)
    # Unless accepted or already mapped
    if r.status_code != 200 and r.status_code != 400:
        logging.warning("Unsuccessful write of tag details mapping.")
        logging.warning(r.text)


def autofocus(parse_test):
    # Assume that we have already parsed and have a good database.
    fields = ['tag_group', 'public_tag_name', 'tag_class', 'description', 'tag']
    # Try processing 10 times. That's probably enough.
    # for _ in range(10):
    process_domains()

    processed_search = Search(index=f"content_{parse_test.version}").query('match', processed=2)
    processed_search.execute()
    num_processed = 0
    for hit in processed_search.scan():
        # Check that each of these specific cases have some information in the database.
        for field in fields:
            assert hit[field] is not None, f"Domain {hit['domain']} missing field {field}."
    num_processed += processed_search.count()['value']
    partly_processed_search = Search(index=f"content_{parse_test.version}").query('match', processed=1)
    num_processed += partly_processed_search.count()

    # Count non-generic domains (the domains which should have been processed).
    non_generic_search = Search(index=f"content_{parse_test.version}").exclude('term', header__keyword='generic')
    num_non_generic = non_generic_search.count()

    # Check to see what percentage of the domains have processed.
    logging.info(f"Processed {num_processed} out of {num_non_generic}.")
    percent_processed = float(num_processed) / float(num_non_generic)
    logging.info(f"Processed {percent_processed*100}% of domains.")
    assert percent_processed >= parse_test.percent_processed, (f"Processed only {percent_processed*100}% "
                                                               f"of domains, not {parse_test.percent_processed*100}%.")


def test_all():
    home = os.getenv('HOME')
    dot = os.getcwd()
    env_path = os.path.join(dot, 'src', 'lib', '.defaultrc')
    load_dotenv(dotenv_path=env_path, verbose=True)
    env_path = os.path.join(home, '.panrc')
    try:
        load_dotenv(dotenv_path=env_path, verbose=True, override=True)
    except Exception:
        pass
    env_path = os.path.join(dot, 'src', 'test', '.testrc')
    load_dotenv(dotenv_path=env_path, verbose=True, override=True)

    dictConfig({
        'version': 1,
        'formatters': {'default': {
            'format': '[%(asctime)s] %(levelname)s in %(module)s(%(lineno)s): %(message)s',
        }},
        'handlers': {'wsgi': {
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',
            'formatter': 'default'
        }},
        'root': {
            'level': os.getenv('LOGGING_LEVEL'),
            'handlers': ['wsgi']
        }
    })

    # Initialize test settings.
    parse_test = ParseTest()

    # Set up connection.
    connections.create_connection(host=os.getenv('ELASTIC_IP'))
    wait_for_elastic(os.getenv('ELASTIC_IP'))

    mappings_path = os.path.join(dot, 'install', 'mappings')
    setup_mappings(mappings_path, os.getenv('ELASTIC_IP'))

    # Set up update details so try_parse can verify it.
    version_doc = VersionDocument(meta={'id':parse_test.version})
    version_doc.shortversion = parse_test.version.split('-')[0]
    version_doc.version = parse_test.version
    version_doc.date = parse_test.version_date
    version_doc.status = DocStatus.DOWNLOADED.value
    version_doc.save()

    # Fill in cases from raw domain.
    for case in parse_test.cases:
        split_raw = case['raw'].split(':')
        domain = split_raw[1]
        split_header = split_raw[0].split('.')
        case['domain'] = domain
        case['date'] = parse_test.version_date
        case['version'] = parse_test.version
        case['header'] = split_raw[0]
        case['threat_type'] = split_header[0]
        case['threat_name'] = split_header[1] if len(split_header) > 1 else None
        case['domain'] = split_raw[1]
        case['processed'] = 0


    # Find the preloaded version notes.
    static_dir = os.path.join(dot, 'src', 'test')
    print(static_dir)

    # Actually run parse.
    logging.info(f"Parsing version {parse_test.version} from {parse_test.version_date}")
    try_parse(path=f"{static_dir}/Updates_{parse_test.version}.html",
                     version=parse_test.version, date=parse_test.version_date)

    # Now check to see if some representative domains are in the database, with fields as expected.
    for case in parse_test.cases:
        present = False

        # Permit retry, in case there's a problem.
        for _ in range(100):
            dom_search = (Search(index=f"content_{parse_test.version}")
                          .query('match', domain__keyword=case['domain']))
            dom_search.execute()

            for hit in dom_search:
                logging.info(hit)
                present = True
                for key, value in case.items():
                    # Generic domains have no threat name; will give key error.
                    if case['header'] == 'generic' and key == 'threat_name':
                        continue
                    assert hit[key] == value, f"Mismatch on {key}, {value}: is {hit[key]} instead."
            if present:
                break
            sleep(5)

        assert present, f"Domain {case['domain']} is missing."

    # Verify that the version in update-details has had its status updated, since we just parsed.
    update_search = Search(index='update-details').query('match', id=parse_test.version)
    update_search.execute()
    for hit in update_search:
        assert hit['status'] == DocStatus.PARSED.value

    # Test autofocus query code
    autofocus(parse_test)


if __name__ == '__main__':
    test_all()
