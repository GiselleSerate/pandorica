# Test file; not part of the structure. 
import datetime
import json
import time

from elasticsearch_dsl import connections
from flask import Flask
import requests
from logging.config import dictConfig

import sys # TODO: only for the next line
sys.path.append('../safe-networking') # TODO: this is Bad and I'm Sorry.
from project.dns.dnsutils import getDomainDoc
from project.dns.dns import DomainDetailsDoc, TagDetailsDoc
# from parser import processIndex


# Establish database connection (port 9200 by default)
connections.create_connection(host='localhost')

document = getDomainDoc('fdasdjfjf')
print(document)
print(document.tags[0][2][0])
# processIndex('3006-3516')