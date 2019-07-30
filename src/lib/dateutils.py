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
Palo Alto Networks dateutils.py

Handles date strings in a specific format.

Use this functions in this file as includes.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
'''

from datetime import datetime, timedelta
import logging



class DateString():
    '''
    A class built to store a date, making it available both as a datestring and a datetime object.
    Datestrings formatted like 2019-06-22T04:00:23-07:00.
    '''
    def __init__(self, input_date):
        # Hour is in military time.
        self.fstring = "%Y-%m-%dT%H:%M:%S%z"
        self.datetime = None
        self.datestring = None

        self.change_date(input_date)


    def _parse_datetime(self, dt):
        '''
        Returns a string when presented with a datetime object.
        Dates returned in formats like 2019-06-22T04:00:23-07:00.

        Non-keyword arguments:
        dt -- the datetime object to be converted to a string
        '''
        raw_string = dt.strftime(self.fstring)
        # Now add the colon back in
        datestring = raw_string[:-2] + ':' + raw_string[-2:]
        return datestring


    def _parse_datestring(self, datestring):
        '''
        Returns a datetime object when presented with a string.

        Non-keyword arguments:
        datestring -- a string of the format 2019-06-22T04:00:23-07:00
        '''
        # Rip final colon out so the date is parseable.
        datestring = datestring[:-3] + datestring[-2:]
        # Convert to datetime.
        return datetime.strptime(datestring, self.fstring)


    def change_date(self, new_date):
        '''
        Update date stored in this class

        Non-keyword arguments:
        new_date -- either a datestring of the format 2019-06-22T04:00:23-07:00 or a datetime with
            fields filled in
        '''
        try:
            # Try parsing as a string
            self.datetime = self._parse_datestring(new_date)
            # If we haven't yet excepted, we were given a string
            self.datestring = new_date
        except TypeError:
            # try:
            # Try as a datetime then
            self.datestring = self._parse_datetime(new_date)
            # If we haven't yet excepted, we were given a datetime
            self.datetime = new_date
            # except Exception as e:
            #     logging.error(e)


    def get_tomorrow_string(self):
        '''
        Get the datestring for tomorrow.
        '''
        # Increment the day
        return self._parse_datetime(self.datetime + timedelta(days=1))
