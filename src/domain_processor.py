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
Palo Alto Networks domain_processor.py

Provides methods to process domains by querying AutoFocus about them, and also calculate
residence/reinsert intervals.

Use this file as an include rather than running it on its own.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

import logging
from logging.config import dictConfig
from multiprocessing import Pool
import os

from dateutil import parser
from dotenv import load_dotenv
from elasticsearch_dsl import Search, Q
from elasticsearch.exceptions import ConflictError, ConnectionTimeout, NotFoundError, RequestError, TransportError

from domain_docs import DomainDocument
from lib.dnsutils import updateAfStats, getDomainDoc
from lib.setuputils import config_all



def date_difference(earlier, later):
    '''
    Calculates the positive difference between two dates.
    Tolerant of passsing either date first.
    '''
    # Convert to datetimes.
    early_date = parser.parse(earlier)
    late_date = parser.parse(later)
    # If the earlier date isn't really earlier, switch.
    if early_date > late_date:
        late_date, early_date = early_date, late_date
    # Calculate difference.
    difference = late_date - early_date
    return difference.days



def calculate_interval(domain_doc):
    '''
    Either return the date difference between this doc and the most recent one or, if no most recent one, False.

    Non-keyword arguments:
    domain_doc -- the DomainDoc, filled in with data, to look backwards from
    '''
    # Get the previous times we've seen this domain.
    prev_search = Search(index='content_*').query('match', domain__keyword=domain_doc.domain).query(Q('range', date={'lt': domain_doc.date})).sort('-date')
    if prev_search.count() > 0:
        # Calculate the interval since the last action with this domain.
        for prev_hit in prev_search:
            return date_difference(prev_hit.date, domain_doc.date)

    return False


def process_hit(hit):
    '''
    Ask AutoFocus about a single domain.

    Non-keyword arguments:
    hit -- a domain to process
    version -- the full version number
    '''
    logging.info(f"Looking up tags for {hit.domain} . . .")

    while True:
        try:
            # Make an autofocus request.
            document = getDomainDoc(hit.domain)
            break
        except (AttributeError, ConnectionTimeout):
            # Got a timeout or None doc, try again and maybe get a real one next time
            pass
        except TransportError:
            # Perhaps could be solved by retry. Probably getDomainDoc should handle, but whatever.
            logging.error(f"Encountered transport error on {hit.domain}.")

    try:
        # Break out tag
        write_dict = {}
        write_dict['tag'] = document.tags[0][2][0]
        write_dict['tag_name'] = write_dict['tag'][0]
        write_dict['public_tag_name'] = write_dict['tag'][1]
        write_dict['tag_class'] = write_dict['tag'][2]
        write_dict['tag_group'] = write_dict['tag'][3]
        write_dict['description'] = write_dict['tag'][4]
        write_dict['source'] = write_dict['public_tag_name'].split('.')[0]
    except (AttributeError, IndexError):
        # No tag available. Note that we have processed this entry (but with no tags) and stop.
        logging.info(f"No tag on {hit.domain}.")
        while True:
            try:
                domain_doc = DomainDocument.get(id=hit.meta.id, index=hit.meta.index)
            except (ConnectionError, ConnectionTimeout, NotFoundError, RequestError, TransportError):
                # Retry.
                pass
        domain_doc.processed = 1
        while True:
            try:
                domain_doc.save()
                return
            except ConflictError:
                # Can't be solved by retry. Skip for now.
                logging.error(f"Elasticsearch conflict (409) writing "
                              f"{hit.domain} to db. (No tag, which is not the problem.) Skipping.")
                return
            except (ConnectionError, ConnectionTimeout, NotFoundError, RequestError, TransportError):
                # Retry.
                pass

    logging.info(f"Tag on {hit.domain}.")

    # Write first tag to db.
    while True:
        try:
            domain_doc = DomainDocument.get(id=hit.meta.id, index=hit.meta.index)
        except (ConnectionError, ConnectionTimeout, NotFoundError, RequestError, TransportError):
            # Retry.
            pass
    domain_doc.tag = write_dict['tag']
    domain_doc.tag_name = write_dict['tag_name']
    domain_doc.public_tag_name = write_dict['public_tag_name']
    domain_doc.tag_class = write_dict['tag_class']
    domain_doc.tag_group = write_dict['tag_group']
    domain_doc.description = write_dict['description']
    domain_doc.source = write_dict['source']
    domain_doc.processed = 2
    # If there's an interval to be calculated, calculate it.
    interval = calculate_interval(domain_doc)
    if interval:
        if domain_doc.action == 'added':
            domain_doc.reinsert = interval
        else:
            domain_doc.residence = interval

    while True:
        try:
            domain_doc.save()
            return
        except ConflictError:
            # Can't be solved by retry. Skip for now.
            logging.error(f"Elasticsearch conflict (409) writing "
                          f"{hit.domain} to db. {write_dict['tag']} Skipping.")
            return
        except (ConnectionError, ConnectionTimeout, NotFoundError, RequestError, TransportError):
            # Retry.
            pass


def process_domains():
    '''
    Use AutoFocus to process all unprocessed non-generic domains in any index.
    Note that you MUST create a database connection first (with connections.create_connection)
    before running this function.
    '''

    # Search for non-processed and non-generic.
    new_nongeneric_search = (Search(index=f"content_*")
                             .exclude('term', header__keyword='generic')
                             .query('match', processed=0))
    new_nongeneric_search.execute()

    # Determine how many AutoFocus points we have.
    day_af_reqs_left = None
    while day_af_reqs_left is None:
        updateAfStats()
        af_stats_search = Search(index='af-details')
        af_stats_search.execute()

        for hit in af_stats_search:
            day_af_reqs_left = int(hit.daily_points_remaining / 12)

    with Pool() as pool:
        iterator = pool.imap(process_hit, new_nongeneric_search.scan())
        # Write IPs of all matching documents back to test index.
        while True:
            logging.debug(f"~{day_af_reqs_left} AutoFocus requests left today.")
            if day_af_reqs_left < 1:
                # Not enough points to do more today.
                return
            try:
                next(iterator)
            except StopIteration:
                logging.info("No more domains to process.")
                return
            except ConnectionTimeout:
                logging.error("Encountered connection timeout. Skipping this result.")
            # Decrement AF stats.
            day_af_reqs_left -= 1



if __name__ == '__main__':
    config_all()

    # Ask AutoFocus about all unprocessed non-generic domains
    # multiple times (in case of failure).
    for _ in range(3):
        process_domains()
