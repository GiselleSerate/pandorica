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
Palo Alto Networks interval_calculator.py

Calculate residence/reinsert intervals and write to elasticsearch.

Run this file on its own.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

from datetime import datetime
import logging
from statistics import mean

from dateutil import parser
from elasticsearch_dsl import connections, DocType, Integer, Keyword, Q, Search, Text

from domain_docs import DomainDocument
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


def calculate_repeat_intervals():
    '''Determine residence and reinsert times over all indices.'''

    # Search for those with no repeat_status.
    uncalculated_search = Search(index='content_305*').query(~Q('exists', field='repeat_status'))
    logging.info(f"Calculating intervals for {uncalculated_search.count()} domains.")

    for hit in uncalculated_search.scan():
        domain_doc = DomainDocument.get(id=hit.domain, index=f"content_{hit.version}")

        # Get the previous times we've seen this domain.
        prev_search = Search(index='content_*').query('match', domain__keyword=hit.domain).query(Q('range', date={'lt': hit.date})).sort('-date')
        if prev_search.count() > 0:
            # Mark this as a non-first repeat domain.
            domain_doc.repeat_status = 2

            # Calculate the interval since the last action with this domain.
            for prev_hit in prev_search[:1]:
                difference = date_difference(prev_hit.date, hit.date)

            if hit.action == 'added':
                # The last time we saw this domain, we were removing it; now we are adding it.
                domain_doc.reinsert = difference
            else:
                # The last time we saw this domain, we were adding it; now we are removing it.
                domain_doc.residence = difference
        else:
            # Never seen this domain before this incident. Write this one as first: repeat_status=1.
            domain_doc.repeat_status = 1

        while True:
            try:
                domain_doc.save()
                break
            except ConnectionError:
                # Retry.
                pass



if __name__ == '__main__':
    config_all()
    calculate_repeat_intervals()
