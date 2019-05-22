# Basic search of elasticsearch db
from elasticsearch_dsl import Search, connections

# Establish connection (localhost:9200 by default, which works for us)
connections.create_connection()

# Create search of sample web data looking for deb extensions
eventSearch = Search(index='kibana_sample_data_logs').query('match', extension='deb')
eventSearch.execute()

# Print IPs of all matching documents
for hit in eventSearch:
    print(f"{hit['ip']}")