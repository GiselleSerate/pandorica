from datetime import datetime
import logging
import re # regex for parsing
import threading
import time # for timing database writes

from bs4 import BeautifulSoup
from elasticsearch.exceptions import NotFoundError # TODO found this in safe networking code, use it or nuke this
from elasticsearch_dsl import DocType, Keyword, Text, Bool, Date connections, Index
from flask import Flask
import urllib.request

import sys # TODO: only for the next line
sys.path.append('../content_downloader') # TODO: this is Bad and I'm Sorry.
from content_downloader import ContentDownloader

# Configuration
app = Flask(__name__)
app.config.from_object('config.DebugConfig')

class MetaDocument(DocType): # TODO hi. call this somewhere. 
    '''
    Unique class for writing metadata to an index
    '''
    id = Text(analyzer='snowball', fields={'raw': Keyword()})
    complete = Bool() # TODO is bool a thing? idk??
    version = Text()
    date = Date() # TODO is date a thing? idkkk??? probably because I've had problems with it

    class Index:
        name = 'placeholder'

    @classmethod
    def get_indexable(cls):
        return cls.get_model().get_objects()

    @classmethod
    def from_obj(cls, obj):
        return cls(
            id=obj.id,
            complete=obj.complete,
            version=obj.version,
            date=obj.date,
            )

    def save(self, **kwargs):
        return super(DomainDocument, self).save(**kwargs)

class DomainDocument(DocType):
    '''
    Class for writing domains back to the database
    '''
    # Use domain as id
    id = Text(analyzer='snowball', fields={'raw': Keyword()})
    domain = Keyword()
    raw = Keyword()
    header = Keyword()
    threatType = Keyword()
    threatClass = Keyword()
    action = Text()
    tags = Text(multi=True)

    class Index:
        name = 'placeholder'

    @classmethod
    def get_indexable(cls):
        return cls.get_model().get_objects()

    @classmethod
    def from_obj(cls, obj):
        return cls(
            id=obj.id,
            domain=obj.domain,
            added=obj.added,
            removed=obj.removed,
            )

    def save(self, **kwargs):
        return super(DomainDocument, self).save(**kwargs)


class ContentDownloaderWithDate(ContentDownloader):
    '''
    Extend ContentDownloader to provide the update date
    '''
    def find_latest_update(self, updates):
        '''
        Extend function to additionally return update date
        as its last argument
        '''
        updates_of_type = [u for u in updates if u['Key'] == self.key]
        updates_sorted = sorted(updates_of_type, key=lambda x: datetime.strptime(x['ReleaseDate'], '%Y-%m-%dT%H:%M:%S'))
        latest = updates_sorted[-1]
        return latest[self.filename_string], latest['FolderName'], latest['VersionNumber'], latest['ReleaseDate']


def parseAndWrite(stringName, pattern, array, version):
    '''
    Pulls all domains of one type from the soup
    and then writes them to the database.
    :param str stringName: The string representation of the type of docs
    :param regex pattern: The section header pattern to find in the soup
    :param list array: The array to put items in after they have been parsed

    '''
    # Pull out a list of tds from parse tree
    try:
        header = soup.find('h3', text=pattern)
        table = header.find_next_sibling('table')
        tds = table.find_all('td')

        # Get domains from table entries
        for td in tds:
            rawScrape = td.string
            result = re.search('\((.*)\)', rawScrape) # Extract domains from "Suspicious DNS Query" parentheses
            if result == None:
                array.append(rawScrape)
            else:
                array.append(result.group(1))

        print(f'{len(array)} domains {stringName}, like {array[:3]}')
    except Exception as e:
        print(f'Parse of {stringName} failed. Are you sure this HTML file is the right format?')
        print(e)
        # If we can't parse out domains, don't write to the db
        raise SystemExit

    # Write domains of all relevant documents back to index
    numDomains = "all" if app.config["NUM_DOMAINS"] == None else app.config["NUM_DOMAINS"]
    print(f'Writing {numDomains} {stringName} domains to database . . .')
    savedTime = time.time()
    for raw in array[:app.config['NUM_DOMAINS']]:
        splitRaw = raw.split(':')
        domain = splitRaw[1]
        splitHeader = splitRaw[0].split('.')
        # Create new DomainDocument in db
        myDoc = DomainDocument(meta={'id':domain})
        myDoc.meta.index = version
        myDoc.raw = raw
        myDoc.header = splitRaw[0]
        myDoc.threatType = splitHeader[0]
        myDoc.threatClass = splitHeader[1] if len(splitHeader) > 1 else None
        myDoc.domain = splitRaw[1]
        myDoc.action = stringName

        try:
            myDoc.save()
        except Exception as e:
            print('No connection to database.')
            print(e)
            raise SystemExit

    print(f'Writing {stringName} domains took {time.time() - savedTime} seconds.')


if __name__ == '__main__':
    # Time full program runtime
    initialTime = time.time()

    # Compile regexes for section headers
    addedPattern = re.compile(app.config['ADD_REGEX'])
    removedPattern = re.compile(app.config['REM_REGEX'])

    # Domains get stored here
    added = []
    removed = []


    print(f'Retrieving latest release notes from support portal . . .')

    username = app.config['USERNAME']
    password = app.config['PASSWORD']

    # Create contentdownloader object to get AV release notes
    downloader = ContentDownloaderWithDate(username=username, password=password, package='antivirus',
                                           debug=False, isReleaseNotes=True)

    # Check latest version. Login if necessary.
    token, updates = downloader.check()

    # Determine latest update
    filename, foldername, latestversion, date = downloader.find_latest_update(updates)

    # version = 'foobar'
    version = latestversion

    # Get download URL
    fileurl = downloader.get_download_link(token, filename, foldername)

    # Get HTML file to parse
    try:
        data = urllib.request.urlopen(fileurl)
    except urllib.error.URLError:
        print(f'Updates failed to download from {fileurl}')
        raise SystemExit


    # Parse file
    soup = BeautifulSoup(data, 'html5lib')


    # Establish database connection (port 9200 by default)
    connections.create_connection(host=app.config['HOST_IP'])

    print(f'Writing updates for latest version: {version} (released {date}).')

    # Create new index
    index = Index(version)
    index.create()


    # Start threads for adds and removes
    addedThread = threading.Thread(target=parseAndWrite, args=('added', addedPattern, added, version))
    addedThread.start()
    removedThread = threading.Thread(target=parseAndWrite, args=('removed', removedPattern, removed, version))
    removedThread.start()
    addedThread.join()
    removedThread.join()
    print(f'Finished running in {time.time() - initialTime} seconds.')
