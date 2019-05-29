class Config(object):
    NUM_DOMAINS = None
    FILE_URL = 'http://localhost:8020/updates.html'
    HOST_IP = '34.235.226.40'
    DB_NAME = 'giselletest'
    ADD_REGEX = r'New Spyware DNS C2 Signatures'
    REM_REGEX = r'Old Spyware DNS C2 Signatures'
    VER_REGEX = r'^[0-9]+$'


class DebugConfig(Config):
    NUM_DOMAINS = 1000
    HOST_IP = '10.54.92.70'