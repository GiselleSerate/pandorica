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


# Establish database connection (port 9200 by default)
connections.create_connection(host='localhost')


document = getDomainDoc('www.ldlvchurch.com')
print(document.tags[0][2][0])


[
	['2019-04-18T06:35:42', 'RAR Archive', 
		[
			['AccessesWindowsVaultPasswords', 'Unit42.AccessesWindowsVaultPasswords', 'malicious_behavior', 'Undefined', 'These files attempt to access the locally keys used to encrypt passwords stored locally in order to decrypt them.'], 
			['FormBook', 'Unit42.FormBook', 'malware_family', 'InfoStealer', 'FormBook is a data stealer and form grabber that has been advertised in various hacking forums since early 2016. \nThe malware injects itself into various processes and installs function hooks to log keystrokes, steal clipboard contents, and extract data from HTTP sessions. The malware can also execute commands from a command and control (C2) server. The commands include instructing the malware to download and execute files, start processes, shutdown and reboot the system, and steal cookies and local passwords.\n\nOne of the malware\'s most interesting features is that it reads Windows’ ntdll.dll module from disk into memory, and calls its exported functions directly, rendering user-mode hooking and API monitoring mechanisms ineffective. The malware author calls this technique "Lagos Island method" (allegedly originating from a userland rootkit with this name). \n\nIt also features a persistence method that randomly changes the path, filename, file extension, and the registry key used for persistence. \n\nThe malware author does not sell the builder, but only sells the panel, and then generates the executable files as a service.']]]]