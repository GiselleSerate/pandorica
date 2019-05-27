import datetime
import re # regex for parsing
import time # for timing database writes

from bs4 import BeautifulSoup
import elasticsearch # for NotFoundError handling
from elasticsearch_dsl import DocType, Keyword, Text, connections


# For now, deal with fewer domains:
numDomains = None


# Determine date to write to db
date = datetime.date.today()


# Domains get stored here
added = []
removed = []


try: # Wraps all the parsing logic. Maybe I can get more granular later. 
    # Open and parse file
    data = open('./updates.html')
    soup = BeautifulSoup(data, 'html5lib')

    # Define regex so we can search for tags beginning with this
    addedPattern = re.compile(r'New Spyware DNS C2 Signatures')
    removedPattern = re.compile(r'Old Spyware DNS C2 Signatures')

    # Get version number from title
    version = soup.find('title').string.split(' ')[1]
    print(f'Analyzing release notes for version {version}')


    # Added: Pull out a list of tds from parse tree
    header = soup.find('h3', text=addedPattern)
    table = header.find_next_sibling('table')
    tds = table.find_all('td')

    # Added: Get domains from table entries
    for td in tds:
        rawDomain = td.string
        added.append(rawDomain.split(':')[1])


    # Removed: Pull out a list of tds from parse tree
    header = soup.find('h3', text=removedPattern)
    table = header.find_next_sibling('table')
    tds = table.find_all('td')

    # Removed: Get domains from table entries
    for td in tds:
        rawDomain = td.string
        removed.append(rawDomain.split(':')[1][:-1]) # Removed has an extraneous close parenthesis


    # Print summary of parse
    print(f'{len(added)} domains added, like {added[:3]}')
    print(f'{len(removed)} domains removed, like {removed[:3]}')

except:
    print('Parse failed. Are you sure this HTML file is the right format?')
    # If we can't parse out domains, don't write to the db
    raise SystemExit


# Class for writing back to the database
class GiselleDoc(DocType):
    # Use domain as id
    id = Text(analyzer='snowball', fields={'raw': Keyword()})
    added = Text(multi=True)
    removed = Text(multi=True)

    class Index:
        name = 'giselletest'

    @classmethod
    def get_indexable(cls):
        return cls.get_model().get_objects()

    @classmethod
    def from_obj(cls, obj):
        return cls(
            id=obj.id,
            added=obj.added,
            removed=obj.removed,
            )

    def save(self, **kwargs):
        return super(GiselleDoc, self).save(**kwargs)


# Establish connection (port 9200 by default)
connections.create_connection(host='34.235.226.40')
print('Connection established.')


# Write domains of all added documents back to index
print(f'Writing {numDomains} added domains to database . . .')
savedTime = time.time()
for domain in added[:numDomains]:
    try:
        # Assume document exists in db; update added
        GiselleDoc.get(id=domain) \
                .update(script='if(!ctx._source.added.contains(params.dateAndVersion)) {ctx._source.added.add(params.dateAndVersion)}', dateAndVersion=[date, version])
    except elasticsearch.exceptions.NotFoundError:
        # Create new document in db
        myDoc = GiselleDoc(meta={'id':domain})
        myDoc.added.append([date, version])
        myDoc.save()

print(f'Writing added domains took {time.time() - savedTime} seconds.')


# Write domains of all removed documents back to index
print(f'Writing {numDomains} removed domains to database . . .')
savedTime = time.time()
for domain in removed[:numDomains]:
    try:
        # Assume document exists in db; update removed
        GiselleDoc.get(id=domain) \
                .update(script='if(!ctx._source.removed.contains(params.dateAndVersion)) {ctx._source.removed.add(params.dateAndVersion)}', dateAndVersion=[date, version])
    except elasticsearch.exceptions.NotFoundError:
        # Create new document in db
        myDoc = GiselleDoc(meta={'id':domain})
        myDoc.removed.append([date, version])
        myDoc.save()

print(f'Writing removed domains took {time.time() - savedTime} seconds.')