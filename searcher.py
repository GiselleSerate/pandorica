# Basic search of elasticsearch db
from elasticsearch_dsl import DocType, Date, Text, Ip, Keyword, Search, connections


class GiselleDoc(DocType):
    # Use domain as id
    id = Text(analyzer='snowball', fields={'raw': Keyword()})
    time = Text()
    ip = Ip()
    url = Text()
    machine = Text()

    class Index:
        name = 'giselletest'

    @classmethod
    def get_indexable(cls):
        return cls.get_model().get_objects()

    @classmethod
    def from_obj(cls, obj):
        return cls(
            id=obj.id,
            time=obj.time,
            ip=obj.ip,
            url=obj.url,
            machine=obj.machine
            )

    def save(self, **kwargs):
        return super(GiselleDoc, self).save(**kwargs)


# Establish connection (localhost:9200 by default, which works for us)
connections.create_connection(host='10.54.76.50')

# Create search of sample web data looking for deb extensions
eventSearch = Search(index='kibana_sample_data_logs').query('match', extension='deb')
eventSearch.execute()

# Write IPs of all matching documents back to test index
for hit in eventSearch:
    myDoc = GiselleDoc(meta={'id':hit['ip']})
    myDoc.ip = hit['ip']
    myDoc.url = hit['url']
    myDoc.time = hit['utc_time']
    myDoc.machine = hit['machine']
    myDoc.save()