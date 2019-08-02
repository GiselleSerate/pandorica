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
Palo Alto Networks parser.py

Downloads and parses new version notes, then writes domains to Elasticsearch. Does not tag or aggregate.

You may run this file directly. Don't forget to configure the .panrc.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

import logging
import os
import re
from threading import Thread

from bs4 import BeautifulSoup
from elasticsearch.exceptions import ConflictError, ConnectionTimeout, NotFoundError, RequestError, TransportError
from elasticsearch_dsl import Index, Search, UpdateByQuery

from domain_docs import DocStatus, DomainDocument, MaintenanceException, RetryException, VersionDocument
from lib.setuputils import config_all
from scraper import ElasticEngToolsDownloader



def parse_and_write(soup, string_name, pattern, array, date, version, thread_status):
    '''
    Pulls all domains of one type from the soup and then writes them to the database.

    Keyword arguments:
    soup -- the soup to parse
    string_name -- the string representation of the type of docs
    pattern -- the section header pattern to find in the soup
    array -- the array to put items in after they have been parsed
    version -- the update version (also the index to write to)
    thread_status -- a list to write to on proper return
    '''
    # Pull out a list of tds from parse tree
    try:
        header = soup.find('h3', text=pattern)
        tds = header.find_next_sibling('table').find_all('td')

        # Get domains from table entries
        for td in tds:
            raw_scrape = td.string
            # Extract domains from "Suspicious DNS Query" parentheses
            result = re.search(r'\((.*)\)', raw_scrape)
            if result is None:
                array.append(raw_scrape)
            else:
                array.append(result.group(1))

        logging.debug(f"{len(array)} domains {string_name}, like {array[:3]}")
    except Exception as e:
        logging.error(f"Parse of {string_name} failed. "
                      "Are you sure this HTML file is the right format?")
        logging.error(e)
        # If we can't parse out domains, don't write to the db; suggests a fundamental document
        # format change requiring more maintenance than a simple retry. Get a human to look at this.
        raise MaintenanceException

    # Write domains of all relevant documents back to index
    logging.info(f'Writing {string_name} domains to database . . .')
    for raw in array:
        split_raw = raw.split(':')
        domain = split_raw[1]
        if split_raw[0].startswith('Exploit-CVE'):
            # It's an exploit, parse differently by splitting on the hyphen
            split_char = '-'
        else:
            split_char = '.'
        split_header = split_raw[0].split(split_char)
        # Create new DomainDocument in db
        domain_doc = DomainDocument(meta={'id':domain, 'index':f'content_{version}'})
        domain_doc.date = date
        domain_doc.version = version
        domain_doc.raw = raw
        domain_doc.header = split_raw[0]
        domain_doc.threat_type = split_header[0]
        domain_doc.threat_name = split_header[1] if len(split_header) > 1 else None
        domain_doc.domain = split_raw[1]
        domain_doc.action = string_name
        domain_doc.processed = 0

        while True:
            try:
                domain_doc.save()
                break
            except ConnectionError:
                # Retry.
                pass

    logging.info(f'Finished writing {string_name} domains.')
    thread_status.append(string_name)


def run_parser(path, version, date):
    '''
    Get file with the path passed, parse, and write to database.

    Non-keyword arguments:
    path -- the local path to the release notes (may be relative)
    version -- the full version number
    date -- the release date

    '''

    # Domains get stored here
    added = []
    removed = []

    try:
        data = open(path)
    except Exception as e:
        logging.error(f'Issue opening provided file at {path}.')
        raise e # Reraise so the script stops

    # Parse file
    soup = BeautifulSoup(data, 'html5lib')


    logging.info(f'Writing updates for version {version} (released {date}).')

    # Establish index to write to
    index = Index(f'content_{version}')

    # Stop if we've written this fully before; delete if it was a partial write
    while True:
        try:
            if index.exists():
                # Search for metadoc to see if it was fully written
                meta_search = (Search(index='update-details')
                               .query('match', version__keyword=version))
                meta_search.execute()
                # By default, assume incomplete.
                complete = 0
                for hit in meta_search:
                    complete = hit.status >= DocStatus.PARSED.value
                if complete:
                    logging.info("This version has already been written to the database. "
                                 "Not rewriting the base index.")
                    return # Everything's fine, no need to retry
                # Last write was incomplete; delete the index and start over
                logging.info('Clearing index.')
                index.delete()
            break
        except ConnectionError:
            # Retry.
            logging.warning("Connection error, retrying.")

    # Create new index
    index.create()


    # Status gets stored here
    thread_status = []

    # Start threads for adds and removes
    added_thread = Thread(target=parse_and_write,
                          args=(soup, 'added', re.compile(os.getenv('ADD_REGEX')),
                                added, date, version, thread_status))
    added_thread.start()
    removed_thread = Thread(target=parse_and_write,
                            args=(soup, 'removed', re.compile(os.getenv('REM_REGEX')),
                                  removed, date, version, thread_status))
    removed_thread.start()
    added_thread.join()
    removed_thread.join()

    # Make sure both threads are okay before committing
    if len(thread_status) < 2:
        logging.error(f"Incomplete run. Please retry. Only wrote {thread_status} to the database.")
    else:
        logging.info(f"Finished writing to database.")


def try_parse(path, version, date):
    '''
    Retry parse repeatedly.

    Non-keyword arguments:
    path -- the local path to the release notes (may be relative)
    version -- the full version number
    date -- the release date

    '''
    try:
        tries_left = int(os.getenv('NUM_TRIES'))
    except ValueError:
        # Can't convert to an int; use a default.
        tries_left = 5

    retry = True
    while retry:
        retry = False
        if tries_left < 1:
            logging.error("Ran out of retries. Stopping without marking as written.")
            return
        try:
            run_parser(path=path, version=version, date=date)
        except RetryException:
            logging.error(f"Script failed, retrying. "
                          f"(Will try again {tries_left} times before giving up.)")
            retry = True
        except MaintenanceException:
            logging.error("Script may need maintenance. Find the programmer. "
                          "Stopping without marking as written.")
            return
        tries_left -= 1

    # Tell update details that downloaded version has been consumed.
    while True:
        try:
            version_doc = VersionDocument.get(id=version)
            break
        except (ConnectionError, ConnectionTimeout, NotFoundError, RequestError, TransportError):
            # Retry.
            pass
    version_doc.status = DocStatus.PARSED.value
    while True:
        try:
            version_doc.save()
            return
        except (ConflictError, ConnectionError, ConnectionTimeout,
                NotFoundError, RequestError, TransportError):
            # Retry.
            pass


def get_unanalyzed_version_details():
    '''Get all versions which have been downloaded only.'''
    ret_list = []
    unanalyzed_search = Search(index='update-details').query('match', status=1)
    unanalyzed_search.execute()
    for hit in unanalyzed_search:
        obj = {}
        obj['version'] = hit.version
        obj['date'] = hit.date
        ret_list.append(obj)
    return ret_list


def download_then_parse_all():
    '''Download the latest release notes, then parse any unparsed notes.'''
    # Download latest notes.
    scraper = ElasticEngToolsDownloader(ip=os.getenv('FW_IP'), username=os.getenv('FW_USERNAME'),
                                        password=os.getenv('FW_PASSWORD'),
                                        download_dir=os.getenv('DOWNLOAD_DIR'))
    new_ver_exists = scraper.download_release()
    exit()

    # Parse domains and write them to the database.
    versions = get_unanalyzed_version_details()
    # Sometimes the db write for freshly downloaded versions doesn't go through immediately.
    # Wait for at least those details to be in the database.
    while new_ver_exists and not versions:
        versions = get_unanalyzed_version_details()
    logging.info(f"Parsing the following {len(versions)} versions:")
    logging.info(versions)
    for ver in versions:
        try_parse(path=f"{os.getenv('DOWNLOAD_DIR')}/Updates_{ver['version']}.html",
                  version=ver['version'], date=ver['date'])


if __name__ == '__main__':
    config_all()
    download_then_parse_all()
