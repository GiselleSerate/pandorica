class ParseTest():
    def __init__(self):
        # Keep the static version notes here (path rel to home directory)
        self.static_dir = 'static_notes'

        # Static version notes metadata
        self.version = '3026-3536'
        self.version_date = '2019-07-01T04:00:52-07:00'

        self.num_domains = 7107 + 7106
        # If we process this much or more, we pass
        self.percent_processed = 0.5


        # Establish cases to check are in the database.
        self.cases = [{'raw': 'generic:hailmaryfulloffacts.com', 'action': 'added'},
                      {'raw': 'TrojanDownloader.upatre:advancehomesbd.com', 'action': 'added'},
                      {'raw': 'generic:aceheartinstitute.com', 'action': 'removed'},
                      {'raw': 'Backdoor.bladabindi:linakamisa.duckdns.org', 'action': 'removed'}]
