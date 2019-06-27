from logging.config import dictConfig
from dotenv import load_dotenv
import os


home = os.getenv('HOME')
env_path = os.path.join(home, '.panrc')
load_dotenv(dotenv_path=env_path, verbose=True)


dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': os.getenv('LOGGING_LEVEL'),
        'handlers': ['wsgi']
    }
})

print(os.getenv('DRIVER'))