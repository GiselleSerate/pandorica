# Basic search of elasticsearch db
from elasticsearch_dsl import Search, connections

connections.create_connection()

eventSearch = Search(index='kibana_sample_data_logs').query('match', extension='deb')
eventSearch.execute()

for hit in eventSearch:
    print(f"{hit['ip']}")