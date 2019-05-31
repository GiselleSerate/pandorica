import datetime
import re # regex for parsing
import threading
import time # for timing database writes

from bs4 import BeautifulSoup
import elasticsearch # for NotFoundError handling
from elasticsearch_dsl import DocType, Keyword, Text, connections
from flask import Flask
import urllib.request

import sys # TODO: only for the next line
sys.path.append('../content_downloader') # TODO: this is Bad and I'm Sorry.
import content_downloader

# Configuration
app = Flask(__name__)
app.config.from_object('config.DebugConfig')

class Document(DocType):
    '''
    Class for writing back to the database
    '''
    # Use domain as id
    id = Text(analyzer='snowball', fields={'raw': Keyword()})
    domain = Keyword()
    added = Text(multi=True)
    removed = Text(multi=True)

    class Index:
        name = app.config['DB_NAME']

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
        return super(Document, self).save(**kwargs)


def parseAndWrite(stringName, pattern, array):
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
            rawDomain = td.string
            array.append(rawDomain.split(':')[1][:-1] if stringName == 'removed' else rawDomain.split(':')[1])

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
    for domain in array[:app.config['NUM_DOMAINS']]:
        try:
            try:
                # Assume document exists in db; update array
                Document.get(id=domain) \
                        .update(script='if(!ctx._source.'+stringName+'.contains(params.dateAndVersion)) {ctx._source.'+stringName+'.add(params.dateAndVersion)}', dateAndVersion=[date, version])
            except elasticsearch.exceptions.NotFoundError:
                # Create new document in db
                myDoc = Document(meta={'id':domain})
                myDoc.domain = domain
                if(stringName == 'added'):
                    myDoc.added.append([date, version])
                else:
                    myDoc.removed.append([date, version])
                myDoc.save()
        except Exception as e:
            print('No connection to database.')
            print(e)
            raise SystemExit

    print(f'Writing {stringName} domains took {time.time() - savedTime} seconds.')


if __name__ == '__main__':
    # Time full program runtime
    initialTime = time.time()

    # Determine date to write to db
    date = datetime.date.today() if app.config['USE_CURR_DATE'] else app.config['ALT_DATE']

    # Compile regexes for section headers and version number
    addedPattern = re.compile(app.config['ADD_REGEX'])
    removedPattern = re.compile(app.config['REM_REGEX'])
    versionPattern = re.compile(app.config['VER_REGEX'])

    # Domains get stored here
    added = []
    removed = []
    

    username = app.config['USERNAME']
    password = app.config['PASSWORD']
    # username, password, download_dir = content_downloader.get_config('../content_downloader/content_downloader.conf')

    # Create contentdownloader object to get AV release notes
    content_downloader = content_downloader.ContentDownloader(username=username, password=password, package='antivirus',
                                           debug=False, isReleaseNotes=True)

    # Check latest version. Login if necessary.
    token, updates = content_downloader.check()

    # Determine latest update
    filename, foldername, latestversion = content_downloader.find_latest_update(updates)

    # Get download URL
    fileurl = content_downloader.get_download_link(token, filename, foldername)

    # Get HTML file to parse
    try:
        data = urllib.request.urlopen(fileurl)
    except urllib.error.URLError:
        print(f'Updates failed to download from {fileurl}')
        raise SystemExit


    # Parse file
    soup = BeautifulSoup(data, 'html5lib')

    # Get version number from title
    try:
        version = soup.find('title').string.split(' ')[1]
        if not versionPattern.match(version):
            raise Exception(f'Invalid version number scraped from file: {version}')
        print(f'Analyzing release notes for version {version}')
    except Exception as e:
        print('Could not find version number. Are you sure this HTML file is the right format?')
        print(e)
        # If we can't parse out domains, don't write to the db
        raise SystemExit


    # Establish database connection (port 9200 by default)
    connections.create_connection(host=app.config['HOST_IP'])


    # Start threads for adds and removes
    addedThread = threading.Thread(target=parseAndWrite, args=('added', addedPattern, added))
    addedThread.start()
    removedThread = threading.Thread(target=parseAndWrite, args=('removed', removedPattern, removed))
    removedThread.start()
    addedThread.join()
    removedThread.join()
    print(f'Finished running in {time.time() - initialTime} seconds.')
