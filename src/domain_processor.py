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

from elasticsearch_dsl import connections, Search, UpdateByQuery

from lib.dnsutils import updateAfStats, getDomainDoc



def process_hit(hit):
    '''
    Ask AutoFocus about a single domain.

    Non-keyword arguments:
    hit -- a domain to process
    version -- the full version number
    '''
    logging.info(f"Looking up tags for {hit.domain} . . .")

    try:
        # Make an autofocus request.
        document = getDomainDoc(hit.domain)
    except Exception as e:
        logging.warning(f"Issue with getting the domain document: {e}")
        return

    logging.info(f'Finished {hit.domain}.')

    try:
        write_dict = {}
        write_dict['tag'] = document.tags[0][2][0]
        write_dict['tag_name'] = write_dict['tag'][0]
        write_dict['public_tag_name'] = write_dict['tag'][1]
        write_dict['tag_class'] = write_dict['tag'][2]
        write_dict['tag_group'] = write_dict['tag'][3]
        write_dict['description'] = write_dict['tag'][4]
        write_dict['source'] = write_dict['public_tag_name'].split('.')[0]

        # Write first tag to db.
        ubq = (UpdateByQuery(index=f"content_*")
               .query('match', domain=hit.domain)
               .script(source='ctx._source.tag=params.tag;'
                              'ctx._source.tag_name=params.tag_name;'
                              'ctx._source.public_tag_name=params.public_tag_name;'
                              'ctx._source.tag_class=params.tag_class;'
                              'ctx._source.tag_group=params.tag_group;'
                              'ctx._source.description=params.description;'
                              'ctx._source.source=params.source;'
                              'ctx._source.processed=1',
                       lang='painless', params=write_dict))
        ubq.execute()
    except (AttributeError, IndexError):
        # No tag available. Regardless, note that we have processed this entry.
        ubq = (UpdateByQuery(index=f"content_*")
               .query('match', domain=hit.domain)
               .script(source='ctx._source.processed=1', lang='painless'))
        ubq.execute()


def process_domains():
    '''Use AutoFocus to process all unprocessed non-generic domains in any index.'''

    # Necessary if you don't run the parser first.
    # Establish database connection (port 9200 by default).
    connections.create_connection(host='localhost')

    # Search for non-processed and non-generic.
    new_nongeneric_search = (Search(index=f"content_*")
                             .exclude('term', header='generic')
                             .query('match', processed=0))
    new_nongeneric_search.execute()

    # Determine how many AutoFocus points we have.
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
            except Exception as e:
                logging.warning(f"Issue getting next domain: {e}")
            # Decrement AF stats.
            day_af_reqs_left -= 1