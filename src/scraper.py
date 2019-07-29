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
Palo Alto Networks scraper.py

Downloads the latest release notes off the engtools server.

Don't run this file independently; intended as an include. Make sure to configure your .panrc.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

from enum import IntEnum, unique
import logging
import os
import re
from time import sleep

from elasticsearch_dsl import connections, Date, DocType, Integer, Keyword, Search, Text
from urllib.request import urlretrieve
from urllib.error import HTTPError

from src.lib.dateutils import DateString



@unique
class DocStatus(IntEnum):
    '''Defines document statuses.'''
    DOWNLOADED = 1
    PARSED = 2
    AUTOFOCUSED = 3



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



class ElasticEngToolsDownloader():
    '''
    A utility that downloads release notes from the engineering tools server
    and writes this status to Elasticsearch.

    Non-keyword arguments:
    download_dir -- where to download the notes to
    elastic_ip -- the IP of the database
    version_override -- optional argument to specify the version BEFORE the one you want to
        download. Allows you to start downloading from a version besides the latest one from
        Elasticsearch; useful if Elastic has no version in it
    date_override -- optional argument used with version_override to set the date of the version
        specified (the version BEFORE the one you want to download); you need to set this
        correctly, or all future dates written to Elasticsearch will be wrong. Dates accepted in
        formats like 2019-06-22T04:00:23-07:00

    '''
    def __init__(self, download_dir='contentpacks', elastic_ip='localhost',
                 version_override=None, date_override=None):
        self._download_dir = download_dir

        self.num_new_releases = 0
        connections.create_connection(host=elastic_ip)

        if version_override is None and date_override is None:
            # No overrides; determine the latest release from Elastic
            version_search = Search(index='update-details').sort('-version.keyword')
            version_search = version_search[:1]
            for hit in version_search:
                self._last_version = hit.version
                self._last_date = DateString(hit.date)
        else:
            # Overrides; assume that version/date are okay for now; problems will get caught later
            self._last_version = version_override
            self._last_date = DateString(date_override)


    def full_download(self):
        '''
        Download releases past what we have already notated in Elasticsearch
        from the engtools server.
        '''
        logging.info("Downloading new releases from the engtools server.")
        while self._download_next_release():
            logging.info(f"Downloaded version {self._last_version}.")

        logging.info("Downloaded all new releases.")


    def _download_next_release(self):
        '''
        Try to download the next release from the engtools server and notate this in the database.
        '''
        # Increment the version and date to see if this version has been released yet
        download_version = '-'.join([str(int(num) + 1) for num in self._last_version.split('-')])

        # Try to download these release notes.
        try:
            urlretrieve('https://i.ytimg.com/vi/Lv4SQy_9VLI/maxresdefault.jpg',
                        f"{self._download_dir}/Updates_{download_version}.html")
        except HTTPError as e:
            # If we 404, dip early; this means we don't have the new updates
            # (and is expected behavior).
            if e.code == 404:
                return False
            # If it's not a 404, something bad is probably going on. Fail out.
            logging.error(f"Unexpected HTTPError when getting version {download_version}.")
            raise e

        # Write version and date to Elasticsearch.
        version_doc = VersionDocument(meta={'id':download_version})
        version_doc.shortversion = download_version.split('-')[0]
        version_doc.version = download_version
        version_doc.date = self._last_date.get_tomorrow_string()
        version_doc.status = DocStatus.DOWNLOADED.value
        version_doc.save()

        self.num_new_releases += 1
        self._last_version = download_version
        self._last_date.change_date(version_doc.date)
        return True
