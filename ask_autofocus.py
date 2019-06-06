import datetime
import json
import time

from elasticsearch_dsl import connections
from flask import Flask
import requests
from logging.config import dictConfig

import sys # TODO: only for the next line
sys.path.append('../safe-networking') # TODO: this is Bad and I'm Sorry.
from project.dns.dnsutils import getDomainInfo


# Establish database connection (port 9200 by default)
connections.create_connection(host='10.54.92.75')

print(getDomainInfo('www.ldlvchurch.com'))


# Get information about the tag
# /tag/{public_tag_name}