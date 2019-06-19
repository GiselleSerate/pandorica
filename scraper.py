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

Downloads the latest release notes off a PANW firewall.

Run this with an associated config.py (see README.md).

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

from enum import IntEnum, unique
import os
import re
from time import sleep

from elasticsearch_dsl import connections, Date, DocType, Integer, Keyword, Search, Text
from flask import Flask
from selenium import webdriver
from selenium.common.exceptions import (ElementClickInterceptedException, NoAlertPresentException,
                                        TimeoutException, UnexpectedAlertPresentException)
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait



app = Flask(__name__)
app.config.from_object('config.DebugConfig')



@unique
class DocStatus(IntEnum):
    '''
    Defines document statuses
    '''
    DOWNLOADED = 1
    WRITTEN = 2
    AUTOFOCUSED = 3



class VersionDocument(DocType):
    '''
    Update metadata document
    '''
    id = Text(analyzer='snowball', fields={'raw': Keyword()})
    shortversion = Text()
    version = Text()
    date = Date()
    status = Integer()


    class Index:
        name = 'update-details'


    @classmethod
    def get_indexable(cls):
        return cls.get_model().get_objects()


    @classmethod
    def from_obj(cls, obj):
        return cls(
            id=obj.id,
            shortversion=obj.shortversion,
            version=obj.version,
            date=obj.date,
            status=obj.status,
            )


    def save(self, **kwargs):
        return super(VersionDocument, self).save(**kwargs)



class FirewallScraper:
    '''A web scraping utility that downloads release notes from a firewall.'''
    def __init__(self, ip, username, password,
                 chrome_driver='chromedriver',
                 binary_location='/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary',
                 download_dir='contentpacks', elastic_ip='localhost'):
        # Set up session details
        self.ip = ip
        self.username = username
        self.password = password

        # Set up driver
        chrome_options = Options()
        chrome_options.binary_location = binary_location
        self.driver = webdriver.Chrome(executable_path=os.path.abspath(chrome_driver),
                                       options=chrome_options)

        # Init details
        self.download_dir = download_dir
        self.versions = []
        connections.create_connection(host=elastic_ip)


    def __del__(self):
        self.driver.close()


    def _login(self):
        '''Log into firewall.'''
        # Load firewall login interface.
        self.driver.get(f'https://{self.ip}')

        # Fill login form and submit.
        user_box = self.driver.find_element_by_id('user') # TODO maybe check this lol idk
        pwd_box = self.driver.find_element_by_id('passwd')
        user_box.clear()
        user_box.send_keys(self.username)
        pwd_box.clear()
        pwd_box.send_keys(self.password)
        pwd_box.send_keys(Keys.RETURN)

        timeout = 10

        # If the default creds box pops up, handle it.
        while True:
            timeout -= 1
            try:
                # Handle alert if we expect it to be there.
                if(self.username == 'admin' and self.password == 'admin'):
                    alert_box = self.driver.switch_to.alert
                    alert_box.accept()
                return
            except NoAlertPresentException:
                # We expect an alert, but haven't seen one yet.
                if timeout < 1:
                    return
                try:
                    # Firewall is not warning us about default creds, but might in a bit.
                    sleep(1)
                except UnexpectedAlertPresentException:
                    # Alert happened while we were sleeping; handle it.
                    alert_box = self.driver.switch_to.alert
                    alert_box.accept()
                    return


    def _find_update_page(self): # TODO: Sometimes we get stuck somewhere in this function. Fix it.
        '''Navigate to get the notes link and details.'''
        self.driver.get(f'https://{self.ip}')

        # Wait for page to load.
        timeout = 500
        try:
            device_tab_present = EC.presence_of_element_located((By.ID, 'device'))
            WebDriverWait(self.driver, timeout).until(device_tab_present)
        except TimeoutException:
            print('Timed out waiting for post-login page to load.')

        # Go to device tab.
        device_tab = self.driver.find_element_by_id('device')
        device_tab.click()

        # Go to Dynamic Updates.
        dynamic_updates = self.driver.find_element_by_css_selector("div[ext\\3Atree-node-id='device/dynamic-updates']")
        dynamic_updates.click()

        # Get latest updates.
        check_now = self.driver.find_element_by_css_selector("table[itemid='Device/Dynamic Updates-Check Now']")
        self.driver.execute_script("arguments[0].scrollIntoView(true)", check_now)

        # Click as soon as the element is in view.
        while True:
            try:
                check_now.click()
                break
            except ElementClickInterceptedException:
                sleep(1)

        # Wait for updates to load in.
        sleep(10)

        # Wait for page to load.
        timeout = 500
        try:
            av_table_present = EC.presence_of_element_located((By.ID, 'ext-gen468-gp-type-anti-virus-bd'))
            WebDriverWait(self.driver, timeout).until(av_table_present)
        except TimeoutException:
            print('Timed out waiting for updates to load.')

        av_table = self.driver.find_element_by_id('ext-gen468-gp-type-anti-virus-bd')
        av_children = av_table.find_elements_by_xpath('*')
        self.versions = []
        # Iterate all versions
        for child in av_children:
            source = child.get_attribute('innerHTML')
            # Iterate details of each version
            # Date should be formatted like 2019/06/14 04:02:07 PDT.
            date = re.search(r'[0-9]{4}\/[0-9]{2}\/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} PDT',
                             source).group(0)
            new_ver = {}
            new_ver['date'] = date
            # Version should be formatted like 3009-3519.
            new_ver['version'] = re.search(r'[0-9]{4}-[0-9]{4}', source).group(0)
            new_ver['link'] = re.search(r'https://downloads\.paloaltonetworks\.com/'
                                        r'virus/AntiVirusExternal-[0-9]*\.html'
                                        r'\?__gda__=[0-9]*_[a-z0-9]*', source).group(0)
            self.versions.append(new_ver)


    def _download_latest_release(self):
        '''Download the page source of only the latest release notes.'''
        # Get the absolute latest release notes
        latest = max(self.versions, key=lambda x: x['date'])
        self._download_release(latest)


    def _download_all_available_releases(self):
        '''Download the page source for all releases still on the firewall.'''
        for release in self.versions:
            self._download_release(release)


    def _download_all_new_releases(self):
        '''
        Download the specified release from the firewall if it isn't
        already registered in the database.
        '''
        for release in self.versions:
            version_search = (Search(index='update-details')
                              .query('match', version=release['version']))
            version_search.execute()
            downloaded = False
            for hit in version_search:
                downloaded = True
            if not downloaded:
                self._download_release(release)

    def _download_release(self, release):
        '''
        Download the specified release from the firewall and notate this in the database.
        '''
        os.chdir(self.download_dir)
        self.driver.get(release['link'])
        filename = f"Updates_{release['version']}.html"
        with open(filename, 'w') as file:
            file.write(self.driver.page_source)

        # Write version and date to elasticsearch
        version_doc = VersionDocument(meta={'id':release['version']})
        version_doc.shortversion = release['version'].split('-')[0]
        version_doc.version = release['version']
        version_doc.date = release['date']
        version_doc.status = DocStatus.DOWNLOADED.value
        version_doc.save()


    def latest_download(self):
        '''Download the single latest release from the firewall.'''
        self._login()
        self._find_update_page()
        self._download_latest_release()


    def full_download(self):
        '''Download any new releases from the firewall.'''
        self._login()
        self._find_update_page()
        self._download_all_new_releases()



if __name__ == '__main__':
    scraper = FirewallScraper(ip=app.config['FW_IP'], username=app.config['FW_USERNAME'],
                              password=app.config['FW_PASSWORD'], chrome_driver=app.config['DRIVER'],
                              binary_location=app.config['BINARY_LOCATION'], download_dir=app.config['DOWNLOAD_DIR'],
                              elastic_ip=app.config['ELASTIC_IP'])
    scraper.full_download()
