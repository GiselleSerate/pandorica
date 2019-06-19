from functools import partial
from multiprocessing import Pool

from elasticsearch_dsl import connections, Search, UpdateByQuery

import sys # TODO: only for local imports
sys.path.append('../safe-networking') # TODO: this is Bad and I'm Sorry.
from project.dns.dnsutils import updateAfStats, getDomainDoc
from project.dns.dns import DomainDetailsDoc, TagDetailsDoc

import sys # TODO: only for local imports
sys.path.append('../release_scraper') # TODO: this is Bad and I'm Sorry.
from scraper import DocStatus



def processHit(hit, version):
    '''
    Process single domain
    '''
    # Make an autofocus request
    print(f'Looking up tags for {hit.domain} . . .')

    try:
        document = getDomainDoc(hit.domain)
    except Exception as e:
        print(f'Issue with getting the domain document: {e}')
        return

    print(f'Finished {hit.domain}.')

    try:
        tag = document.tags[0][2][0]
        # Write first tag to db
        ubq = UpdateByQuery(index=f'content_{version}')     \
              .query("match", domain=hit.domain)            \
              .script(source="ctx._source.tag=params.tag; ctx._source.processed=1", lang="painless", params={'tag': tag})
        ubq.execute()
    except (AttributeError, IndexError): 
        # No tag available. Regardless, note that we have processed this entry
        ubq = UpdateByQuery(index=f'content_{version}')     \
              .query("match", domain=hit.domain)            \
              .script(source="ctx._source.processed=1", lang="painless")
        ubq.execute()


def processIndex(version):
    '''
    Use AutoFocus to process all parsed domains in an index
    '''
    print(f'Processing domains for version {version}.')

    if(version == None):
        print(f'{version} is not a valid version number. Stopping.')
        return

    # TODO: I stuck this in here but it's really only necessary if you run this interactively without running the parser first
    # Establish database connection (port 9200 by default)
    connections.create_connection(host='localhost')

    # Search for non-processed and non-generic
    newNonGenericSearch = Search(index=f'content_{version}').exclude('term', header='generic').query('match', processed=0)
    newNonGenericSearch.execute()

    # Determine how many AutoFocus points we have
    updateAfStats()
    afStatsSearch = Search(index='af-details')
    afStatsSearch.execute()
    for hit in afStatsSearch:
        dayAfReqsLeft = int(hit.daily_points_remaining / 12)

    with Pool() as pool:
        it = pool.imap(partial(processHit, version=version), newNonGenericSearch.scan())
        # Write IPs of all matching documents back to test index
        while True:
            print(f'~{dayAfReqsLeft} AutoFocus requests left today.')
            if(dayAfReqsLeft < 1):
                return # Nothing more to do today. 
            try:
                next(it)
            except StopIteration as si:
                print('No more domains to process.')
                return
            except Exception as e:
                print(f'Issue getting next domain: {e}')
            # Decrement AF stats
            dayAfReqsLeft -= 1

    # Tell update details that version has been AutoFocused
    ubq = UpdateByQuery(index='update-details') \
            .query('match', version=version)    \
            .script(source='ctx._source.status=params.status', lang='painless', params={'status':DocStatus.AUTOFOCUSED.value})
    ubq.execute()