class ParseTest():
    def __init__(self):
        # Static version notes metadata
        self.version = '3026-3536'
        self.version_date = '2019-07-01T04:00:52-07:00'

        # If we process this much or more, we pass
        self.percent_processed = 0.5


        # Establish cases to check are in the database.
        self.cases = [{'raw': 'None:gacyqob.com', 'action': 'added'},
                      {'raw': 'Backdoor.simda:gahyraw.com', 'action': 'added'},
                      {'raw': 'None:pupycag.com', 'action': 'added'},
                      {'raw': 'PWS.simda:qetyhyg.com', 'action': 'added'},
                      {'raw': 'Backdoor.simda:vojykom.com', 'action': 'added'},
                      {'raw': 'Backdoor.simda:vowygem.com', 'action': 'added'},
                      {'raw': 'None:vowyzuk.com', 'action': 'added'},
                      {'raw': 'Worm.pykspa:agadss.biz', 'action': 'added'},
                      {'raw': 'Worm.pykspa:qgasocuiwcymao.info', 'action': 'added'},
                      {'raw': 'Worm.pykspa:ygsink.info', 'action': 'added'},
                      {'raw': 'Worm.ainslot:ryan12345.no-ip.biz', 'action': 'added'},
                      {'raw': 'TrojanDownloader.upatre:hngdecor.com', 'action': 'added'},
                      {'raw': 'TrojanDownloader.upatre:okeanbg.com', 'action': 'added'},
                      {'raw': 'TrojanDownloader.upatre:gert-hof.de', 'action': 'added'},
                      {'raw': 'Packed.fe:spaines.pw', 'action': 'added'},
                      {'raw': 'None:recdataoneveter.cc', 'action': 'added'},
                      {'raw': 'Suspicious DNS Query (Backdoor.vawtrak:mbbllmv.eu)', 'action': 'removed'},
                      {'raw': 'Suspicious DNS Query (None:mfkxyucmxwhw.com)', 'action': 'removed'},
                      {'raw': 'Suspicious DNS Query (Worm.pykspa:kegbceiq.info)', 'action': 'removed'},
                      {'raw': 'Suspicious DNS Query (Virus.gippers:microsoft.mypicture.info)', 'action': 'removed'},
                      {'raw': 'Suspicious DNS Query (DDoS.nitol:a7677767.vicp.net)', 'action': 'removed'},
                      {'raw': 'Suspicious DNS Query (Worm.pykspa:yeuawkuiwcymao.info)', 'action': 'removed'},
                      {'raw': 'Suspicious DNS Query (None:zief.pl)', 'action': 'removed'},
                      {'raw': 'Suspicious DNS Query (Virus.palevogen:.banjalucke-ljepotice.ru)', 'action': 'removed'},
                      {'raw': 'Suspicious DNS Query (VirTool.ceeinject:digitalmind.cn)', 'action': 'removed'},
                      {'raw': 'Suspicious DNS Query (Virus.virut:irc.zief.pl)', 'action': 'removed'},
                      {'raw': 'Suspicious DNS Query (Trojan.dorv:lyvyxor.com)', 'action': 'removed'},
                      {'raw': 'Suspicious DNS Query (Virus.sality:sungkhomwit.com)', 'action': 'removed'},
                      {'raw': 'Suspicious DNS Query (Virus.sality:asesoriaenexposicion.com)', 'action': 'removed'},
                      {'raw': 'Suspicious DNS Query (TrojanSpy.nivdort:doubledistant.net)', 'action': 'removed'},
                      {'raw': 'Suspicious DNS Query (None:extsc.3322.org)', 'action': 'removed'},
                      {'raw': 'Suspicious DNS Query (Virus.sality:solitaireinfo.com)', 'action': 'removed'}]
