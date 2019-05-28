import datetime
import re # regex for parsing
import threading
import time # for timing database writes

from bs4 import BeautifulSoup
import elasticsearch # for NotFoundError handling
from elasticsearch_dsl import DocType, Keyword, Text, connections
import urllib.request


# Class for writing back to the database
class Document(DocType):
    # Use domain as id
    id = Text(analyzer='snowball', fields={'raw': Keyword()})
    domain = Keyword()
    added = Text(multi=True)
    removed = Text(multi=True)

    class Index:
        name = 'giselletest' # TODO update this

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


def parseAndWrite(stringName, pattern, array, hasParen):
    '''
    Pulls all domains of one type from the soup
    and then writes them to the database. 
    Designed for threadiness. 
    '''
    # Pull out a list of tds from parse tree
    try:
        header = soup.find('h3', text=pattern)
        table = header.find_next_sibling('table')
        tds = table.find_all('td')

        # Get domains from table entries
        for td in tds:
            rawDomain = td.string
            array.append(rawDomain.split(':')[1][:-1] if hasParen else rawDomain.split(':')[1])

        print(f'{len(array)} domains {stringName}, like {array[:3]}')
    except Exception as e:
        print(f'Parse of {stringName} failed. Are you sure this HTML file is the right format?')
        print(e)
        # If we can't parse out domains, don't write to the db
        raise SystemExit

    # Write domains of all relevant documents back to index
    print(f'Writing {numDomains} {stringName} domains to database . . .')
    savedTime = time.time()
    for domain in array[:numDomains]:
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
    initialTime = time.time()

    # For now, deal with fewer domains:
    numDomains = None

    # Determine date to write to db
    date = datetime.date.today()

    # Define regex so we can search for tags beginning with this
    addedPattern = re.compile(r'New Spyware DNS C2 Signatures')
    removedPattern = re.compile(r'Old Spyware DNS C2 Signatures')

    # Define regex to verify version numbers
    versionPattern = re.compile(r'^[0-9]+$')

    # Domains get stored here
    added = []
    removed = []


    try:
        # Get HTML file to parse
        data = urllib.request.urlopen('http://localhost:8020/updates.html')
        # data = open('./updates.html') # uncomment if you don't want to worry about hosting
    except urllib.error.URLError:
        print('Updates not found. Have you started server.py in the same directory as the updates file?')
        raise SystemExit


    # Establish database connection (port 9200 by default)
    # connections.create_connection(host='34.235.226.40') # TODO actually, I'm not sure this can even fail. 
    connections.create_connection(host='10.54.92.70')
    # connections.create_connection()


    # Parse file
    soup = BeautifulSoup(data, 'html5lib')


    try:
        # Get version number from title
        version = soup.find('title').string.split(' ')[1]
        if not versionPattern.match(version):
            raise Exception(f'Invalid version number scraped from file: {version}')
        print(f'Analyzing release notes for version {version}')
    except Exception as e:
        print('Could not find version number. Are you sure this HTML file is the right format?')
        print(e)
        # If we can't parse out domains, don't write to the db
        raise SystemExit


    # Start threads for adds and removes
    addedThread = threading.Thread(target=parseAndWrite, args=('added', addedPattern, added, False))
    addedThread.start()
    removedThread = threading.Thread(target=parseAndWrite, args=('removed', removedPattern, removed, True))
    removedThread.start()

    addedThread.join()
    removedThread.join()
    print(f'Finished running in {time.time()-initialTime} seconds.')
