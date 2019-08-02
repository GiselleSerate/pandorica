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

from enum import IntEnum, unique

from elasticsearch_dsl import Date, DocType, Integer, Keyword, Text



class RetryException(Exception):
    '''Raised when the action should be retried.'''



class MaintenanceException(Exception):
    '''Raised when the script may be now obsolete due to format changes, etc.'''



@unique
class DocStatus(IntEnum):
    '''Defines document statuses.'''
    DOWNLOADED = 1
    PARSED = 2
    AUTOFOCUSED = 3



class DomainDocument(DocType):
    '''Class for writing domains back to the database.'''
    # Use the domain as the id.
    id = Text(analyzer='snowball', fields={'raw': Keyword()})
    domain = Keyword()
    date = Date()
    version = Keyword()
    raw = Keyword()
    header = Keyword()
    threat_type = Keyword()
    threat_name = Keyword()
    action = Text()
    tags = Text(multi=True)
    processed = Integer()
    # Is this the first time we've seen this domain?
    # N/A uncalculated, also uncalculated rein/res
    # 1 first time!
    # 2 it's a duplicate
    repeat_status = Integer()
    reinsert = Integer()
    residence = Integer()

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
            date=obj.date,
            version=obj.version,
            raw=obj.raw,
            header=obj.header,
            threat_type=obj.threat_type,
            threat_name=obj.threat_name,
            action=obj.action,
            tags=obj.tags,
            processed=obj.processed,
            repeat_status=obj.repeat_status,
            reinsert=obj.reinsert,
            residence=obj.residence
            )


    def save(self, **kwargs):
        return super(DomainDocument, self).save(**kwargs)



class VersionDocument(DocType):
    '''Contains update metadata.'''
    id = Text(analyzer='snowball', fields={'raw': Keyword()})
    shortversion = Text()
    version = Text()
    date = Date()
    status = Integer()


    class Index:
        '''Defines the index to send documents to.'''
        name = 'update-details'


    @classmethod
    def get_indexable(cls):
        '''Getter for objects.'''
        return cls.get_model().get_objects()


    @classmethod
    def from_obj(cls, obj):
        '''Convert to class.'''
        return cls(
            id=obj.id,
            shortversion=obj.shortversion,
            version=obj.version,
            date=obj.date,
            status=obj.status,
            )


    def save(self, **kwargs):
        return super(VersionDocument, self).save(**kwargs)
