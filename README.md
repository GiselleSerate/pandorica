# GRIDDLE or PANDORICA or ExPANDS (Actual title TBD)

## Setup
- [ ] Secure a PANW firewall to scrape release notes from.
- [ ] Set up and start an elasticsearch instance using a Docker container (more detailed instructions TBD).
- [ ] Clone [Safe Networking](https://github.com/PaloAltoNetworks/safe-networking/) in the same directory as you clone this repo.
- [ ] Configure the `.panrc` in Safe Networking with your AutoFocus key.
- [ ] Configure the Elasticsearch index mappings using the [install script in Safe Networking](https://github.com/PaloAltoNetworks/safe-networking/blob/master/install/setup.sh).
- [ ] Fill in `config.py` with the details of your particular firewall.

## Usage
Run `parser.py` regularly. For a full set of data, run it at least once every five days, or else the release notes will not be available on the firewall. Sometimes domains' tags will not be retrieved properly from AutoFocus, so running the script more than once a day might be advisable to use AutoFocus points most efficiently.
