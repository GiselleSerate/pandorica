from datetime import datetime
from logging.config import dictConfig
import re
from threading import Thread
import time # for timing database writes

from bs4 import BeautifulSoup
from elasticsearch_dsl import DocType, Boolean, Date, Keyword, Text, connections, Index, Search, UpdateByQuery
from flask import Flask
from flask.logging import default_handler
import urllib.request

import sys # TODO: only for the next line
sys.path.append('../content_downloader') # TODO: this is Bad and I'm Sorry.
from content_downloader import ContentDownloader

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

# Configuration
app = Flask(__name__)
app.config.from_object('config.DebugConfig')
app.logger.removeHandler(default_handler)

class MetaDocument(DocType):
    '''
    Unique class for writing metadata to an index
    '''
    id = Text(analyzer='snowball', fields={'raw': Keyword()})
    metadoc = Text()
    complete = Boolean()
    version = Text()
    date = Date()

    class Index:
        name = 'placeholder'

    @classmethod
    def get_indexable(cls):
        return cls.get_model().get_objects()

    @classmethod
    def from_obj(cls, obj):
        return cls(
            id=obj.id,
            metadoc=obj.metadoc,
            complete=obj.complete,
            version=obj.version,
            date=obj.date,
            )

    def save(self, **kwargs):
        return super(MetaDocument, self).save(**kwargs)

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


def parseAndWrite(stringName, pattern, array, version, threadStatus):
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

        app.logger.info(f'{len(array)} domains {stringName}, like {array[:3]}')
    except Exception as e:
        app.logger.error(f'Parse of {stringName} failed. Are you sure this HTML file is the right format?')
        app.logger.error(e)
        # If we can't parse out domains, don't write to the db
        raise SystemExit

    # Write domains of all relevant documents back to index
    numDomains = "all" if app.config["NUM_DOMAINS"] == None else app.config["NUM_DOMAINS"]
    app.logger.info(f'Writing {numDomains} {stringName} domains to database . . .')
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
            app.logger.error('Saving domain failed; check connection to database and retry.')
            app.logger.error(e)
            raise SystemExit

    app.logger.info(f'Writing {stringName} domains took {time.time() - savedTime} seconds.')
    threadStatus.append(stringName)


if __name__ == '__main__':
    # Time full program runtime
    initialTime = time.time()

    # Compile regexes for section headers
    addedPattern = re.compile(app.config['ADD_REGEX'])
    removedPattern = re.compile(app.config['REM_REGEX'])

    # Domains get stored here
    added = []
    removed = []


    app.logger.info(f'Retrieving latest release notes from support portal . . .')

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
        app.logger.error(f'Updates failed to download from {fileurl}')
        raise SystemExit


    # Parse file
    soup = BeautifulSoup(data, 'html5lib')


    # Establish database connection (port 9200 by default)
    connections.create_connection(host=app.config['HOST_IP'])

    app.logger.info(f'Writing updates for latest version: {version} (released {date}).')

    # Establish index to write to
    index = Index(version)

    # Stop if we've written this fully before; delete if it was a partial write
    try:
        if index.exists():
            # Search for metadoc complete
            metaSearch = Search().query('match', metadoc=True)
            completed = metaSearch.execute()
            if completed:
                app.logger.info('This version has already been written to the database. Stopping.')
                raise SystemExit
            else:
                # Last write was incomplete; delete the index and start over
                app.logger.info('Clearing index.')
                index.delete()
    except Exception as e:
        app.logger.error('OOPSIES we have a problem with the existing index stop pls') # TODO idk what could happen??
        app.logger.error(e)
        raise SystemExit

    # Create new index
    index.create()

    # Create new MetaDocument in db
    myDoc = MetaDocument()
    myDoc.meta.index = version
    myDoc.metadoc = True
    myDoc.complete = False
    myDoc.version = version
    myDoc.date = date
    try:
        myDoc.save()
    except Exception as e:
        app.logger.error('Saving metadocument failed; check connection to database and retry.')
        app.logger.error(e)
        raise SystemExit


    # Status gets stored here
    threadStatus = []

    # Start threads for adds and removes
    addedThread = Thread(target=parseAndWrite, args=('added', addedPattern, added, version, threadStatus))
    addedThread.start()
    removedThread = Thread(target=parseAndWrite, args=('removed', removedPattern, removed, version, threadStatus))
    removedThread.start()
    addedThread.join()
    removedThread.join()

    if(len(threadStatus) == 2):
        # TODO make sure both threads are okay before committinggg!
        try:
            # Finish by committing
            ubq = UpdateByQuery(index=version)      \
                  .query("match", metadoc=True)   \
                  .script(source="ctx._source.complete=true", lang="painless")
            response = ubq.execute()
        except Exception as e:
            app.logger.error('Can\'t commit to database')
            app.logger.error(e)
            raise SystemExit

        app.logger.info(f'Finished running in {time.time() - initialTime} seconds.')
    else:
        app.logger.info(f'Incomplete run. Please retry.')
