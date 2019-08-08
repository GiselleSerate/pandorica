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

Provides methods to process domains by querying AutoFocus about them.

Use this file as an include rather than running it on its own.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

import logging
from multiprocessing import Pool
import os

from elasticsearch_dsl import Search
from elasticsearch.exceptions import (ConflictError, ConnectionTimeout,
                                      NotFoundError)

from domain_docs import AFStatus, DomainDocument
from lib.dnsutils import updateAfStats, getDomainDoc
from lib.setuputils import config_all



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
        except Exception as e:
            # Just retry it.
            logging.warning(e)

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
    except (AttributeError, IndexError, TypeError):
        # No tag available. Note that we have processed this entry (but with no tags) and stop.
        logging.info(f"No tag on {hit.domain}.")
        while True:
            try:
                domain_doc = DomainDocument.get(id=hit.meta.id, index=hit.meta.index)
                # Break if we find the document
                if domain_doc:
                    break
            except Exception as e:
                # Retry.
                logging.warning(e)
        domain_doc.processed = AFStatus.NO_TAG.value
        while True:
            try:
                domain_doc.save()
                return
            except ConflictError:
                # Can't be solved by retry. Skip for now.
                logging.error(f"Elasticsearch conflict (409) writing "
                              f"{hit.domain} to db. (No tag, which is not the problem.) Skipping.")
                return
            except Exception as e:
                # Just retry it.
                logging.warning(e)

    logging.info(f"Tag on {hit.domain}.")

    # Write first tag to db.
    while True:
        try:
            domain_doc = DomainDocument.get(id=hit.meta.id, index=hit.meta.index)
            # Break if we find the document
            if domain_doc:
                break
        except Exception as e:
            # Just retry it.
            logging.warning(e)
    domain_doc.tag = write_dict['tag']
    domain_doc.tag_name = write_dict['tag_name']
    domain_doc.public_tag_name = write_dict['public_tag_name']
    domain_doc.tag_class = write_dict['tag_class']
    domain_doc.tag_group = write_dict['tag_group']
    domain_doc.description = write_dict['description']
    domain_doc.source = write_dict['source']
    domain_doc.processed = AFStatus.HAS_TAG.value
    while True:
        try:
            domain_doc.save()
            return
        except ConflictError:
            # Can't be solved by retry. Skip for now.
            logging.error(f"Elasticsearch conflict (409) writing "
                          f"{hit.domain} to db. {write_dict['tag']} Skipping.")
            return
        except Exception as e:
            # Just retry it.
            logging.warning(e)


def process_domains():
    '''
    Use AutoFocus to process all unprocessed applicable domains in any index.
    We'll check AUTOFOCUS_KEY_IS_UNLIMITED from your .panrc to determine whether this includes
    generic domains or not.
    '''
    # Check if our AF key is unlimited; if it is, we'll ask about generic domains as well as
    # non-generic domains.
    key_is_unlimited = os.getenv('AUTOFOCUS_KEY_IS_UNLIMITED') == 'True'

    if key_is_unlimited:
        logging.info("You have an unlimited AutoFocus key, so we'll tag all domains "
                     "(including generic).")
        # Search for non-processed and generic as well.
        to_tag_search = (Search(index=f"content_*")
                         .query('match', processed=0))
    else:
        logging.info("Your AutoFocus key is rate-limited, so we'll only tag non-generic domains.")
        # Search for non-processed and non-generic.
        to_tag_search = (Search(index=f"content_*")
                         .exclude('term', header__keyword='generic')
                         .query('match', processed=0))

    to_tag_search.execute()

    # If we need to worry about AF points, determine how many we have.
    if not key_is_unlimited:
        day_af_reqs_left = None
        while day_af_reqs_left is None:
            updateAfStats()
            af_stats_search = Search(index='af-details')
            af_stats_search.execute()

            for hit in af_stats_search:
                day_af_reqs_left = int(hit.daily_points_remaining / 12)

    with Pool() as pool:
        iterator = pool.imap(process_hit, to_tag_search.scan())
        # Write IPs of all matching documents back to test index.
        while True:
            if not key_is_unlimited:
                logging.debug(f"~{day_af_reqs_left} AutoFocus requests left today.")
                if day_af_reqs_left < 1:
                    # Not enough points to do more today.
                    return
            try:
                next(iterator)
            except StopIteration:
                logging.info("No more domains to process.")
                return
            except (NotFoundError, ConnectionTimeout) as e:
                logging.warning("Encountered temporary issue. Skipping this result.")
                logging.warning(e)
            if not key_is_unlimited:
                # Decrement AF stats.
                day_af_reqs_left -= 1



if __name__ == '__main__':
    config_all()

    # Ask AutoFocus about domains multiple times (in case of failure).
    for _ in range(3):
        process_domains()
