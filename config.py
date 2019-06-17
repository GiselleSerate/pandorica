class Config(object):
    DEBUG = False # Currently release_scraper doesn't do work on not-debug. 
    FW_IP = '10.48.60.12'
    FW_USERNAME = 'admin'
    FW_PASSWORD = 'admin'
    BINARY_LOCATION = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    DRIVER = 'vanilladriver'
    DOWNLOAD_DIR = '../versiondocs'
    ELASTIC_IP = 'localhost'
    ADD_REGEX = r'New Spyware DNS C2 Signatures'
    REM_REGEX = r'Old Spyware DNS C2 Signatures'
    NUM_TRIES = 5

class DebugConfig(Config):
    DEBUG = True
