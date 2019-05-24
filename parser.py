from bs4 import BeautifulSoup
import re
from elasticsearch_dsl import DocType, Date, Text, Ip, Keyword, Search, connections


# Domains get stored here
added = []
removed = []


# Open and parse file
data = open('./updates.html')
soup = BeautifulSoup(data, 'html5lib')

# Define regex so we can search for tags beginning with this
addedPattern = re.compile(r'New Spyware DNS C2 Signatures')
removedPattern = re.compile(r'Old Spyware DNS C2 Signatures')


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


# Now that we've parsed, write back to the database
# Hard-coded for now:
date = '05/24/2019'

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
for domain in added[:6]: # GSERATE try the first six only
    # # Create search of existing database looking for this domain
    # eventSearch = Search(index='giselletest').query('match', id=domain) # TODO: Is this the most efficient way to do it? 
    # eventSearch.execute()
    # existing = eventSearch[0]['added']
    # print(existing)

    myDoc = GiselleDoc(meta={'id':domain})
    myDoc.added = existing + date
    # myDoc.added.append(date)
    myDoc.save()