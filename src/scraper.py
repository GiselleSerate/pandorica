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
from time import sleep

from bs4 import BeautifulSoup
from elasticsearch_dsl import connections, Date, DocType, Integer, Keyword, Search, Text
from urllib.request import urlretrieve
from urllib.error import HTTPError
from pan.xapi import PanXapi

from lib.dateutils import DateString



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
    def __init__(self, ip=None, username='admin', password='admin',
                 download_dir='contentpacks'):
        self._download_dir = download_dir
        self.num_new_releases = 0

        self._ip = ip
        self._username = username
        self._password = password

        self.latest_version = None
        self.latest_date = None
        self._determine_new_release()


    def _determine_new_release(self):
        api_instance = PanXapi(hostname=self._ip, api_username=self._username,
                               api_password=self._password)
        # Init status to nothing
        api_instance.status = None
        # Keep requesting until we get a successful response
        while api_instance.status != 'success':
            logging.info("Trying op command.")
            api_instance.op('show system info', cmd_xml=True)
            sleep(1)
        logging.debug(f"XML is: {api_instance.xml_document}")
        # Parse version and date out of document
        soup = BeautifulSoup(api_instance.xml_document, features='html5lib')
        version_el = soup.find('threat-version')
        date_el = soup.find('threat-release-date')
        self.latest_version = version_el.text
        self.latest_date = date_el.text
        logging.debug(f"Firewall says the latest version is {self.latest_version}, "
                      f"released {self.latest_date}.")


    def download_release(self):
        '''
        Download the release from the engtools server and notate this in the database.
        '''
        # First check if we have already downloaded the notes.
        # meta_search = (Search(index='update-details')
        #                .query('match', version__keyword=self.latest_version))
        # if meta_search.count() > 0:
        #     logging.info(f"{self.latest_version} already downloaded, not redownloading.")
        #     return

        # Try to download these release notes.
        tries = 5
        while True:
            try:
                urlretrieve(f"http://10.105.203.52/pub/repository/av/external/releasenotes/"
                            f"AntiVirusExternal-{self.latest_version.split('-')[0]}.html",
                            f"{self._download_dir}/Updates_{self.latest_version}.html")
                break
            except HTTPError as e:
                # Log and wait a bit; maybe the error will go away on retry.
                logging.warning(f"Unexpected HTTPError {e.code}"
                                f"when getting version {self.latest_version}.")
                logging.debug(e)
                tries -= 1
                # We're done waiting; fail for real.
                if tries == 0:
                    logging.error(f"Hit more than {tries} HTTPErrors; giving up.")
                    raise e
                sleep(1)

        # Write version and date to Elasticsearch.
        # version_doc = VersionDocument(meta={'id':self.latest_version})
        # version_doc.shortversion = self.latest_version.split('-')[0]
        # version_doc.version = self.latest_version
        # version_doc.date = self.latest_date
        # version_doc.status = DocStatus.DOWNLOADED.value
        # version_doc.save()
        logging.info(f"Finished downloading {self.latest_version}.")
