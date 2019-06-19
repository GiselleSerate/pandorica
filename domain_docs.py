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
Palo Alto Networks domain_docs.py

Defines various useful classes for writing domains to Elasticsearch.

Use this file for including; do not run directly.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

from elasticsearch_dsl import DocType, Integer, Keyword, Text



class RetryException(Exception):
    '''Raised when the action should be retried.'''



class MaintenanceException(Exception):
    '''Raised when the script may be now obsolete due to format changes, etc.'''



class DomainDocument(DocType):
    '''Class for writing domains back to the database.'''
    # Use the domain as the id.
    id = Text(analyzer='snowball', fields={'raw': Keyword()})
    domain = Keyword()
    raw = Keyword()
    header = Keyword()
    threatType = Keyword()
    threatClass = Keyword()
    action = Text()
    tags = Text(multi=True)
    processed = Integer()


    class Index:
        '''TODO do we need?'''
        name = 'placeholder'


    @classmethod
    def get_indexable(cls):
        '''Getter for objects.'''
        return cls.get_model().get_objects()


    @classmethod
    def from_obj(cls, obj):
        '''Convert to class.''' # TODO is accurate?
        return cls(
            id=obj.id,
            domain=obj.domain,
            raw=obj.raw,
            header=obj.header,
            threatType=obj.threatType,
            threatClass=obj.threatClass,
            action=obj.action,
            tags=obj.tags,
            processed=obj.processed,
            )


    def save(self, **kwargs):
        return super(DomainDocument, self).save(**kwargs)
