from bs4 import BeautifulSoup
import re


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