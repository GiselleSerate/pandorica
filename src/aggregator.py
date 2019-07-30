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
Palo Alto Networks aggregator.py

Aggregates domains by domain, writing most seen domains back to elasticsearch in independent index.

Run this file on its own.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

from datetime import datetime
import logging
from logging.config import dictConfig
from statistics import mean

from elasticsearch_dsl import connections, DocType, Integer, Keyword, Search, Text


dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://sys.stdout',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})


class AggregateDocument(DocType):
    '''Contains update metadata.'''
    id = Text(analyzer='snowball', fields={'raw': Keyword()})
    domain = Keyword()
    tot_count = Integer()
    residence_avg = Integer()
    reinsert_avg = Integer()


    class Index:
        '''Defines the index to send documents to.'''
        name = 'domain-aggregate'


    @classmethod
    def get_indexable(cls):
        '''Getter for objects.'''
        return cls.get_model().get_objects()


    @classmethod
    def from_obj(cls, obj):
        '''Convert to class.'''
        return cls(
            id=obj.id,
            domain=obj.domain,
            tot_count=obj.tot_count,
            residence_avg=obj.residence_avg,
            reinsert_avg=obj.reinsert_avg
            )


    def save(self, **kwargs):
        return super(AggregateDocument, self).save(**kwargs)



def date_difference(earlier, later):
    '''
    Calculates the positive difference between two dates.
    Tolerant of passsing either date first.
    Dates accepted in formats like 2019-06-22T04:00:23-07:00.
    '''
    # Hour is in military time.
    fstring = "%Y-%m-%dT%H:%M:%S%z"
    # Rip final colon out so the dates are parseable.
    earlier = earlier[:-3] + earlier[-2:]
    later = later[:-3] + later[-2:]
    # Convert to datetimes.
    early_date = datetime.strptime(earlier, fstring)
    late_date = datetime.strptime(later, fstring)
    # If the earlier date isn't really earlier, switch.
    if early_date > late_date:
        late_date, early_date = early_date, late_date
    # Calculate difference.
    difference = late_date - early_date
    return difference.days


def aggregate_domains():
    '''Sum all domains over all indices.'''
    # connections.create_connection(host='localhost') # TODO

    handled = {}

    all_search = Search(index=f"content_*")
    all_search.execute()

    # Iterate over all events
    for hit in all_search.scan():
        data = {}
        data['action'] = hit['action']
        data['date'] = hit['date']
        # Add this event to the handled dictionary under the relevant domain.
        try:
            handled[hit['domain']].append(data)
        except KeyError:
            handled[hit['domain']] = []
            handled[hit['domain']].append(data)

    logging.info("Finished getting all domains. Here goes.")

    for domain, events in handled.items():
        if len(events) >= 2:
            handled[domain].sort(key=lambda event: event['date'])
            residences = []
            reinserts = []

            # Loop over the start dates except for the last.
            for index in range(len(handled[domain]) - 1):
                # Compare next date to this date.
                difference = date_difference(handled[domain][index]['date'],
                                             handled[domain][index + 1]['date'])
                if handled[domain][index]['action'] == 'added':
                    residences.append(difference)
                else:
                    reinserts.append(difference)

            # Save the document.
            logging.info(f"Saving {domain}")
            aggregate_doc = AggregateDocument(meta={'id':domain})
            aggregate_doc.domain = domain
            aggregate_doc.tot_count = len(events)
            if len(residences) >= 1:
                aggregate_doc.residence_avg = mean(residences)
                logging.info(f"Residence time: {aggregate_doc.residence_avg}")
            if len(reinserts) >= 1:
                aggregate_doc.reinsert_avg = mean(reinserts)
                logging.info(f"Reinsert time: {aggregate_doc.reinsert_avg}")
            aggregate_doc.save()



if __name__ == '__main__':
    aggregate_domains()
