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
import os

from dotenv import load_dotenv
from elasticsearch_dsl import connections, Search

import parser
from scraper import DocStatus, VersionDocument
from testcases import ParseTest


if __name__ == '__main__':
    # Initialize test settings.
    parse_test = ParseTest()

    # Connect to a different port so you don't accidentally nuke your data.
    connections.create_connection(host=f"localhost")

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
    home = os.getenv('HOME')
    static_dir = os.path.join(home, parse_test.static_dir)

    # Actually run parse.
    logging.info(f"Parsing version {parse_test.version} from {parse_test.version_date}")
    parser.try_parse(path=f"{static_dir}/Updates_{parse_test.version}.html",
                     version=parse_test.version, date=parse_test.version_date)

    # Now check to see if some representative domains are in the database, with fields as expected.
    for case in parse_test.cases:
        domSearch = (Search(index=f"content_{parse_test.version}")
                     .query('match', domain=case['domain']))
        domSearch.execute()

        for hit in domSearch:
            for key, value in case.items():
                # Generic domains have no threat name; will give key error.
                if case['header'] == 'generic' and key == 'threat_name':
                    continue
                assert hit[key] == value, f"Mismatch on {key}, {value}: is {hit[key]} instead."

    # Verify that the version in update-details has had its status updated, since we just parsed.
    updateSearch = Search(index='update-details').query('match', id=parse_test.version)
    updateSearch.execute()
    for hit in updateSearch:
        assert hit['status'] == DocStatus.PARSED.value
