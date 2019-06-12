from elasticsearch_dsl import DocType, Boolean, Date, Keyword, Text, Index

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

class MetaDocument(DocType):
    '''
    Unique class for writing metadata to an index
    '''
    id = Text(analyzer='snowball', fields={'raw': Keyword()})
    metadoc = Text()
    complete = Boolean()
    version = Text()
    date = Date()

    class Index:
        name = 'placeholder'

    @classmethod
    def get_indexable(cls):
        return cls.get_model().get_objects()

    @classmethod
    def from_obj(cls, obj):
        return cls(
            id=obj.id,
            metadoc=obj.metadoc,
            complete=obj.complete,
            version=obj.version,
            date=obj.date,
            )

    def save(self, **kwargs):
        return super(MetaDocument, self).save(**kwargs)

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
    processed = Boolean()

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