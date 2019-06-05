import datetime
import json
import time

from flask import Flask
import requests
from logging.config import dictConfig

import sys # TODO: only for the next line
sys.path.append('../safe-networking') # TODO: this is Bad and I'm Sorry.
from project.dns.dnsutils import getDomainInfo


print(getDomainInfo('www.ldlvchurch.com'))