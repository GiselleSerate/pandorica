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
Palo Alto Networks pandorica.py

Full notes download and parse, AF tag, and aggregate.

Run this file directly as the base. Don't forget to configure the .panrc.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

from domain_processor import process_domains
from interval_calculator import calculate_repeat_intervals
from lib.setuputils import config_all
from notes_parser import download_then_parse_all


def pandorica():
    '''Full run of Pandorica pipeline.'''

    # Set up configuration.
    config_all()

    # Download latest release notes and parse any that haven't been.
    download_then_parse_all()

    # Ask AutoFocus about all unprocessed non-generic domains
    # multiple times (in case of failure).
    for _ in range(3):
        process_domains()


if __name__ == '__main__':
    pandorica()
