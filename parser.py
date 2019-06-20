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

Downloads and parses new version notes, then writes domains to Elasticsearch with autofocus details.

Run this file with the config.py set as in the README.md.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

from logging.config import dictConfig
import re
from threading import Thread

from bs4 import BeautifulSoup
from elasticsearch_dsl import connections, Index, Search, UpdateByQuery
from flask import Flask

from domain_processor import process_index
from domain_docs import RetryException, MaintenanceException, DomainDocument
from scraper import DocStatus, FirewallScraper



dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

# Configuration
app = Flask(__name__)
app.config.from_object('config.DebugConfig')


def parse_and_write(soup, string_name, pattern, array, version, thread_status): # TODO update docstrings lollll
    '''
    Pulls all domains of one type from the soup and then writes them to the database.

    Keyword arguments:
    string_name -- the string representation of the type of docs
    pattern -- the section header pattern to find in the soup
    array -- the array to put items in after they have been parsed
    version -- the update version (also the index to write to)
    thread_status -- a list to write to on proper return
    '''
    # Pull out a list of tds from parse tree
    try:
        header = soup.find('h3', text=pattern)
        table = header.find_next_sibling('table')
        tds = table.find_all('td')

        # Get domains from table entries
        for td in tds:
            raw_scrape = td.string
            # Extract domains from "Suspicious DNS Query" parentheses
            result = re.search(r'\((.*)\)', raw_scrape)
            if result is None:
                array.append(raw_scrape)
            else:
                array.append(result.group(1))

        print(f"{len(array)} domains {string_name}, like {array[:3]}")
    except Exception as e:
        print(f"Parse of {string_name} failed. Are you sure this HTML file is the right format?")
        print(e)
        # If we can't parse out domains, don't write to the db; suggests a fundamental document
        # format change requiring more maintenance than a simple retry. Get a human to look at this.
        raise MaintenanceException

    # Write domains of all relevant documents back to index
    print(f'Writing {string_name} domains to database . . .')
    for raw in array:
        split_raw = raw.split(':')
        domain = split_raw[1]
        split_header = split_raw[0].split('.')
        # Create new DomainDocument in db
        domain_doc = DomainDocument(meta={'id':domain})
        domain_doc.meta.index = f'content_{version}'
        domain_doc.raw = raw
        domain_doc.header = split_raw[0]
        domain_doc.threatType = split_header[0]
        domain_doc.threatClass = split_header[1] if len(split_header) > 1 else None
        domain_doc.domain = split_raw[1]
        domain_doc.action = string_name
        domain_doc.processed = 0

        try:
            domain_doc.save()
        except Exception as e:
            print("Saving domain failed; check connection to database and retry.")
            print(e)
            raise RetryException # Retry immediately

    print(f'Finished writing {string_name} domains.')
    thread_status.append(string_name)


def run_parser(path, version, date):
    '''
    Get file with the path passed, parse, and write to database.
    '''

    # Domains get stored here
    added = []
    removed = []


    print('Opening release notes.')

    try:
        data = open(path)
    except Exception as e:
        print(f'Issue opening provided file at {path}.')
        raise e # Reraise so the script stops

    # Parse file
    soup = BeautifulSoup(data, 'html5lib')


    # Establish database connection (port 9200 by default)
    connections.create_connection(host=app.config['ELASTIC_IP'])

    print(f'Writing updates for version {version} (released {date}).')

    # Establish index to write to
    index = Index(f'content_{version}')

    # Stop if we've written this fully before; delete if it was a partial write
    try:
        if index.exists():
            # Search for metadoc to see if it was fully written
            meta_search = (Search(index='update-details')
                           .query('match', version=version))
            meta_search.execute()
            complete = 0 # By default, assume incomplete
            for hit in meta_search:
                complete = hit.status >= DocStatus.WRITTEN.value
            if complete:
                print("This version has already been written to the database. "
                      "Not rewriting the base index.")
                return # Everything's fine, no need to retry
            # Last write was incomplete; delete the index and start over
            print('Clearing index.')
            index.delete()
    except Exception as e:
        print(f"Issue with the existing index. Try checking your connection or "
              f"manually deleting the index and retry.")
        print(e)
        raise RetryException # Retry immediately

    # Create new index
    index.create()


    # Status gets stored here
    thread_status = []

    # Start threads for adds and removes
    added_thread = Thread(target=parse_and_write,
                          args=(soup, 'added', re.compile(app.config['ADD_REGEX']),
                                added, version, thread_status))
    added_thread.start()
    removed_thread = Thread(target=parse_and_write,
                            args=(soup, 'removed', re.compile(app.config['REM_REGEX']),
                                  removed, version, thread_status))
    removed_thread.start()
    added_thread.join()
    removed_thread.join()

    # Make sure both threads are okay before committing
    if len(thread_status) < 2:
        print(f"Incomplete run. Please retry. Only wrote {thread_status} to the database.")
    else:
        print(f"Finished writing to database.")


def try_parse(path, version, date):
    '''
    Retry parse repeatedly
    '''
    try:
        tries_left = int(app.config['NUM_TRIES'])
    except ValueError:
        # Can't convert to an int; use a default.
        tries_left = 5

    retry = True
    while retry:
        retry = False
        if tries_left < 1:
            print("Ran out of retries. Stopping without asking AutoFocus.")
            return
        try:
            run_parser(path=path, version=version, date=date)
        except RetryException:
            print(f"Script failed, retrying. (Will try again {tries_left} times before giving up.)")
            retry = True
        except MaintenanceException:
            print(f"Script may need maintenance. Find the programmer. "
                  f"Stopping without asking AutoFocus.")
            return
        except Exception as e:
            print("Uncaught exception from run_parser. Stopping without asking AutoFocus.")
            print(e)
            return
        tries_left -= 1

    # Tell update details that downloaded version has been consumed
    ubq = (UpdateByQuery(index='update-details')
           .query('match', version=version)
           .script(source='ctx._source.status=params.status',
                   lang='painless', params={'status':DocStatus.WRITTEN.value}))
    ubq.execute()

    # Process the index before stopping
    process_index(version)


def get_unanalyzed_version_details():
    '''
    Get all versions which have been downloaded only
    '''
    ret_list = []
    unanalyzed_search = Search(index='update-details').query('match', status=1)
    unanalyzed_search.execute()
    for hit in unanalyzed_search:
        obj = {}
        obj['version'] = hit.version
        obj['date'] = hit.date
        ret_list.append(obj)
    return ret_list


if __name__ == '__main__':
    # Download latest release notes
    scraper = FirewallScraper(ip=app.config['FW_IP'], username=app.config['FW_USERNAME'],
                              password=app.config['FW_PASSWORD'],
                              chrome_driver=app.config['DRIVER'],
                              binary_location=app.config['BINARY_LOCATION'],
                              download_dir=app.config['DOWNLOAD_DIR'],
                              elastic_ip=app.config['ELASTIC_IP'])
    scraper.full_download()

    versions = get_unanalyzed_version_details()
    print(f"Analyzing the following versions:")
    print(versions)
    for ver in versions:
        print(f"VERSION {ver['version']} FROM {ver['date']}")
        try_parse(path=f"{app.config['DOWNLOAD_DIR']}/Updates_{ver['version']}.html",
                  version=ver['version'], date=ver['date'])
