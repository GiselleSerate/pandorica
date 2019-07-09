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

from elasticsearch_dsl import connections, DocType, Integer, Keyword, Search, Text, UpdateByQuery

import logging
from logging.config import dictConfig


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
            tot_count=obj.tot_count
            )


    def save(self, **kwargs):
        return super(AggregateDocument, self).save(**kwargs)



def aggregate_domains():
    '''Sum all domains over all indices.'''
    connections.create_connection(host='localhost')

    handled = {}

    all_search = Search(index=f"content_*")
    all_search.execute()

    for hit in all_search.scan():
        try:
            handled[hit['domain']] += 1
        except KeyError:
            handled[hit['domain']] = 1

    logging.info("Finished getting all domains. Here goes.")

    for key, value in handled.items():
        if value >= 3:
            logging.info(key)
            aggregate_doc = AggregateDocument()
            aggregate_doc.domain = key
            aggregate_doc.tot_count = value
            aggregate_doc.save()


if __name__ == '__main__':
    aggregate_domains()