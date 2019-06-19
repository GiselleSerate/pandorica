from elasticsearch_dsl import Date, DocType, Index, Integer, Keyword, Text

class RetryException(Exception):
    '''
    Raised when the action should be retried
    '''
    pass

class MaintenanceException(Exception):
    '''
    Raised when the script may be now obsolete due to format changes, etc
    '''
    pass

class DomainDocument(DocType):
    '''
    Class for writing domains back to the database
    '''
    # Use domain as id
    id = Text(analyzer='snowball', fields={'raw': Keyword()})
    domain = Keyword()
    raw = Keyword()
    header = Keyword()
    threatType = Keyword()
    threatClass = Keyword()
    action = Text()
    tags = Text(multi=True)
    processed = Integer()

    class Index:
        name = 'placeholder'

    @classmethod
    def get_indexable(cls):
        return cls.get_model().get_objects()

    @classmethod
    def from_obj(cls, obj):
        return cls(
            id=obj.id,
            domain=obj.domain,
            raw=obj.raw,
            header=obj.header,
            threatType=obj.threatType,
            threatClass=obj.threatClass,
            action=obj.action,
            tags=obj.tags,
            processed=obj.processed,
            )

    def save(self, **kwargs):
        return super(DomainDocument, self).save(**kwargs)