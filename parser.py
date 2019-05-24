from bs4 import BeautifulSoup
import re # for regex

data = open('./updates.html')
soup = BeautifulSoup(data, 'html5lib')

addedPattern = re.compile(r'New Spyware DNS C2 Signatures')
removedPattern = re.compile(r'Old Spyware DNS C2 Signatures')

addedHeader = soup.find('h3', text=addedPattern)
print(addedHeader)
addedTable = addedHeader.find_next_sibling('table')
tds = addedTable.find_all('td')
for td in tds:
    print(td.string)

# removedHeader = soup.find('h3', text=removedPattern)
# print(removedHeader)