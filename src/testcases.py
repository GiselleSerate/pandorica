class ParseTest():
    def __init__(self):
        # Keep the static version notes here (path rel to home directory)
        self.static_dir = 'static_notes'

        # Static version notes metadata
        self.version = '3026-3536'
        self.version_date = '2019-07-01T04:00:52-07:00'

        # If we process this much or more, we pass
        self.percent_processed = 0.5


        # Establish cases to check are in the database.
        self.cases = [{'raw': 'TrojanDownloader.upatre:hngdecor.com', 'action': 'added'},
                      {'raw': 'generic:cityofangelsmagazine.com', 'action': 'removed'},
                      {'raw': 'Virus.sality:www.greenbeach.de', 'action': 'added'},
                      {'raw': 'Trojan.delf:www.universal101.com', 'action': 'added'},
                      {'raw': 'Trojan.fakefolder:hohoho.ho.funpic.org', 'action': 'added'},
                      {'raw': 'Worm.ainslot:ilovebug.no-ip.org', 'action': 'added'},
                      {'raw': 'Worm.pykspa:zztxii.info', 'action': 'added'},
                      {'raw': 'Virus.sality:www.indiatouristtaxi.com', 'action': 'added'},
                      {'raw': 'Malware.gandcrab:booomaahuuoooapl.com', 'action': 'removed'},
                      {'raw': 'generic:bensoleimani.com', 'action': 'added'}]
