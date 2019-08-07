# Copyright (c) 2019, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Author: Giselle Serate <gserate@paloaltonetworks.com>

'''
Palo Alto Networks setuputils.py

Various utilities to help when dealing with Elastic.

Use this file as an include only.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

import logging
from logging.config import dictConfig
import os

from dotenv import load_dotenv
from elasticsearch_dsl import connections
import requests



def connect_to_elastic(ip):
    '''
    Connect to Elastic and wait for it to be up.

    Non-keyword arguments:
    ip -- IP of Elasticsearch
    '''
    connections.create_connection(host=ip)

    logging.info("Waiting for Elasticsearch.")
    while True:
        try:
            response = requests.get(f"http://{ip}:9200")
            logging.info(f"Elasticsearch responds with {response}")
            if response.status_code == 200:
                break
        except requests.exceptions.ConnectionError:
            pass
    logging.info("Finished waiting for Elasticsearch.")


def config_all():
    '''
    Set up panrc variables and logging configuration.
    '''
    home = os.getenv('HOME')
    dot = os.getcwd()
    env_path = os.path.join(dot, 'src', 'lib', '.defaultrc')
    load_dotenv(dotenv_path=env_path, verbose=True)
    env_path = os.path.join(home, '.panrc')
    load_dotenv(dotenv_path=env_path, verbose=True, override=True)

    dictConfig({
        'version': 1,
        'formatters': {'default': {
            'format': '[%(asctime)s] %(levelname)s in %(module)s (%(lineno)s): %(message)s',
        }},
        'handlers': {'wsgi': {
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',
            'formatter': 'default'
        }},
        'root': {
            'level': os.getenv('LOGGING_LEVEL'),
            'handlers': ['wsgi']
        }
    })

    connect_to_elastic(os.getenv('ELASTIC_IP'))
