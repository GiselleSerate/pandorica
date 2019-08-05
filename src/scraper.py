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

import logging
from time import sleep
from urllib.request import urlretrieve
from urllib.error import HTTPError

from bs4 import BeautifulSoup
from dateutil import parser
from elasticsearch_dsl import Search
from pan.xapi import PanXapi

from domain_docs import DocStatus, VersionDocument



def format_datetime(dt):
    '''
    Returns a string when presented with a datetime object.
    Dates returned in formats like 2019-06-22T04:00:23-07:00.

    Non-keyword arguments:
    dt -- the datetime object to be converted to a string
    '''
    raw_string = dt.strftime("%Y-%m-%dT%H:%M:%S%z")
    # Now add the colon back in
    datestring = raw_string[:-2] + ':' + raw_string[-2:]
    return datestring



class EngToolsDownloader():
    '''
    A utility that downloads release notes from the engineering tools server.

    Keyword arguments:
    ip -- the IP of the firewall to check latest version
    username -- the username of the firewall
    password -- the password of the firewall
    download_dir -- where to download the notes to
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
        '''
        Helper function to figure out the latest version and release date from the firewall.
        '''
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
        logging.debug(api_instance.xml_document)
        version_el = soup.find('av-version')
        date_el = soup.find('av-release-date')
        self.latest_version = version_el.text
        # Reformat date to make sure it's the same as everything else I put in Elastic.
        dateobj = parser.parse(date_el.text)
        self.latest_date = format_datetime(dateobj)
        logging.debug(f"Firewall says the latest version is {self.latest_version}, "
                      f"released {self.latest_date}.")


    def download_release(self):
        '''
        Download the release from the engtools server.
        Returns a boolean reflecting whether we've downloaded a new version.
        '''
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
                    logging.error(f"Hit too many HTTPErrors; giving up.")
                    raise e
                sleep(1)

        logging.info(f"Finished downloading {self.latest_version}.")
        return True



class ElasticEngToolsDownloader(EngToolsDownloader):
    '''
    A utility that downloads release notes from the engineering tools server
    and writes this status to Elasticsearch.

    Keyword arguments:
    ip -- the IP of the firewall to check latest version
    username -- the username of the firewall
    password -- the password of the firewall
    download_dir -- where to download the notes to
    elastic_ip -- the IP of the database
    '''
    def __init__(self, ip=None, username='admin', password='admin',
                 download_dir='contentpacks', elastic_ip='localhost'):
        self.elastic_ip = elastic_ip
        super(ElasticEngToolsDownloader, self).__init__(ip, username, password, download_dir)

    def download_release(self):
        '''
        Download the release from the engtools server and notate this in the database.
        Returns a boolean reflecting whether we've downloaded a new version.
        '''
        # First check if we have already downloaded the notes.
        meta_search = (Search(index='update-details')
                       .query('match', version__keyword=self.latest_version))
        if meta_search.count() > 0:
            logging.info(f"{self.latest_version} already downloaded, not redownloading.")
            return False

        # Go download the notes.
        super(ElasticEngToolsDownloader, self).download_release()

        # Write version and date to Elasticsearch.
        version_doc = VersionDocument(meta={'id':self.latest_version})
        version_doc.shortversion = self.latest_version.split('-')[0]
        version_doc.version = self.latest_version
        version_doc.date = self.latest_date
        version_doc.status = DocStatus.DOWNLOADED.value
        version_doc.save()

        return True
