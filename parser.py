from bs4 import BeautifulSoup
import re # for regex

soup = BeautifulSoup(open("./updates.html"), "html.parser")

addedPattern = re.compile(r'New Spyware DNS C2 Signatures')
removedPattern = re.compile(r'Old Spyware DNS C2 Signatures')

addedHeader = soup.find('h3', text=addedPattern)
print(addedHeader)
addedTable = addedHeader.find_next_sibling('table')
for addedTableBody in addedTable.children: # TODO fix how much whitespace there is in here. wow
    print("foo")
    for addedItem in addedTableBody: 
      print("item:")
      print(addedItem)

# removedHeader = soup.find('h3', text=removedPattern)
# print(removedHeader)