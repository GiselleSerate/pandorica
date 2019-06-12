from datetime import datetime
from logging.config import dictConfig
import re
import sys
from threading import Thread

from bs4 import BeautifulSoup
from elasticsearch_dsl import connections, Index, Search, UpdateByQuery
from flask import Flask
from flask.logging import default_handler
import urllib.request

from domain_processor import processIndex
from domain_docs import RetryException, MaintenanceException, MetaDocument, DomainDocument

# import sys # TODO: only for local imports
# sys.path.append('../content_downloader') # TODO: this is Bad and I'm Sorry.
# from content_downloader import ContentDownloader


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
# app.logger.removeHandler(default_handler)

# NOTE: the following is how we call the content downloader, but it's currently broken. 
# # Create contentdownloader object to get AV release notes
# downloader = ContentDownloaderWithDate(username=username, password=password, package='antivirus',
#                                        debug=False, isReleaseNotes=True)

# # Check latest version. Login if necessary.
# token, updates = downloader.check()

# # Determine latest update
# filename, foldername, latestversion, date = downloader.find_latest_update(updates)

# # version = 'foobar'
# version = latestversion

# # Get download URL
# fileurl = downloader.get_download_link(token, filename, foldername)

# # Get HTML file to parse
# try:
#     data = urllib.request.urlopen(fileurl)
# except urllib.error.URLError:
#     print(f'Updates failed to download from {fileurl}')
#     raise RetryException # Retry immediately


# class ContentDownloaderWithDate(ContentDownloader):
#     '''
#     Extend ContentDownloader to provide the update date
#     '''
#     def find_latest_update(self, updates):
#         '''
#         Extend function to additionally return update date
#         as its last argument
#         '''
#         updates_of_type = [u for u in updates if u['Key'] == self.key]
#         updates_sorted = sorted(updates_of_type, key=lambda x: datetime.strptime(x['ReleaseDate'], '%Y-%m-%dT%H:%M:%S'))
#         latest = updates_sorted[-1]
#         return latest[self.filename_string], latest['FolderName'], latest['VersionNumber'], latest['ReleaseDate']


def parseAndWrite(soup, stringName, pattern, array, version, threadStatus):
    '''
    Pulls all domains of one type from the soup
    and then writes them to the database.
    :param str stringName: The string representation of the type of docs
    :param regex pattern: The section header pattern to find in the soup
    :param list array: The array to put items in after they have been parsed
    :param string version: The update version (also the index to write to)
    :param list threadStatus: A list to write to on proper return

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
        # If we can't parse out domains, don't write to the db; suggests a fundamental document 
        # format change requiring more maintenance than a simple retry. Get a human to look at this. 
        raise MaintenanceException

    # Write domains of all relevant documents back to index
    print(f'Writing {stringName} domains to database . . .')
    for raw in array:
        splitRaw = raw.split(':')
        domain = splitRaw[1]
        splitHeader = splitRaw[0].split('.')
        # Create new DomainDocument in db
        myDoc = DomainDocument(meta={'id':domain})
        myDoc.meta.index = f'content_{version}'
        myDoc.raw = raw
        myDoc.header = splitRaw[0]
        myDoc.threatType = splitHeader[0]
        myDoc.threatClass = splitHeader[1] if len(splitHeader) > 1 else None
        myDoc.domain = splitRaw[1]
        myDoc.action = stringName
        myDoc.processed = 0

        try:
            myDoc.save()
        except Exception as e:
            print('Saving domain failed; check connection to database and retry.')
            print(e)
            raise RetryException # Retry immediately

    print(f'Finished writing {stringName} domains.')
    threadStatus.append(stringName)


def runParser(path, version, date):
    '''
    Get file with the path passed, parse, and write to database. 
    '''

    # Compile regexes for section headers
    addedPattern = re.compile(app.config['ADD_REGEX'])
    removedPattern = re.compile(app.config['REM_REGEX'])

    # Domains get stored here
    added = []
    removed = []


    print('Opening release notes.')
    
    try:
        data = open(path)
    except Exception as e:
        print(f'Issue opening provided file at {path}.')
        raise e # Reraise so the script stops

    # Parse file
    soup = BeautifulSoup(data, 'html5lib')


    # Establish database connection (port 9200 by default)
    connections.create_connection(host=app.config['HOST_IP'])

    print(f'Writing updates for version {version} (released {date}).')

    # Establish index to write to
    index = Index(f'content_{version}')

    # Stop if we've written this fully before; delete if it was a partial write
    try:
        if index.exists():
            # Search for metadoc complete
            metaSearch = Search(index=f'content_{version}').query('match', metadoc=True)
            response = metaSearch.execute()
            complete = False # By default, assume incomplete
            for hit in metaSearch:
                complete = hit.complete
            if complete:
                print('This version has already been written to the database. Not rewriting the base index.')
                return # Everything's fine, no need to retry
            else:
                # Last write was incomplete; delete the index and start over
                print('Clearing index.')
                index.delete()
    except Exception as e:
        print('Issue with the existing index. Try checking your connection or manually deleting the index and retry.')
        print(e)
        raise RetryException # Retry immediately

    # Create new index
    index.create()

    # Create new MetaDocument in db
    myDoc = MetaDocument()
    myDoc.meta.index = f'content_{version}'
    myDoc.metadoc = True
    myDoc.complete = False
    myDoc.version = version
    myDoc.date = date
    try:
        myDoc.save()
    except Exception as e:
        print('Saving metadocument failed; check connection to database and retry.')
        print(e)
        raise RetryException # Retry immediately


    # Status gets stored here
    threadStatus = []

    # Start threads for adds and removes
    addedThread = Thread(target=parseAndWrite, args=(soup, 'added', addedPattern, added, version, threadStatus))
    addedThread.start()
    removedThread = Thread(target=parseAndWrite, args=(soup, 'removed', removedPattern, removed, version, threadStatus))
    removedThread.start()
    addedThread.join()
    removedThread.join()

    # Make sure both threads are okay before committing
    if(len(threadStatus) < 2):
        print(f'Incomplete run. Please retry. Only wrote {threadStatus} to the database.')
    else:
        try:
            # Finish by committing
            ubq = UpdateByQuery(index=f'content_{version}')     \
                  .query("match", metadoc=True)                 \
                  .script(source="ctx._source.complete=true", lang="painless")
            response = ubq.execute()
        except Exception as e:
            print('Failed to tell database that index was complete. Retry.')
            print(e)
            raise RetryException # Retry immediately

        print(f'Finished writing to database.')


def tryParse(path, version, date):
    '''
    Retry parse repeatedly
    '''
    try:
        triesLeft = int(app.config['NUM_TRIES'])
    except ValueError:
        # Can't convert to an int; use a default.
        triesLeft = 5
        
    retry = True
    while retry:
        retry = False
        if triesLeft < 1:
            print('Ran out of retries. Stopping without asking AutoFocus.')
            return
        try:
            runParser(path=path, version=version, date=date)
        except RetryException:
            print(f'Script failed, retrying. (Will try again {triesLeft} times before giving up.)')
            retry = True
        except MaintenanceException:
            print('Script may need maintenance. Find the programmer. Stopping without asking AutoFocus.')
            return
        except Exception as e:
            print('Uncaught exception from runParser. Stopping without asking AutoFocus.')
            print(e)
            return
        triesLeft -= 1
    
    # Process the index before stopping
    processIndex(version)

if __name__ == '__main__':
    tryParse(path=app.config['PATH'], version=app.config['VERSION'], date=app.config['DATE'])
