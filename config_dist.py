# encoding: utf-8

"""
Copyright (c) 2012 - 2016, Ernesto Ruge
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import os

SQLALCHEMY_DATABASE_URI = 'mysql://egov-monitor:XXXXXXXXXX@localhost/egov-monitor'
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ECHO = False

BASIC_AUTH_USERNAME = 'admin'
BASIC_AUTH_PASSWORD = 'XXXXXXXXXX'
BASIC_AUTH_REALM = 'Bitte geben Sie Nutzername und Passwort fuer das Admin-Interface ein.'

SECURITY_PASSWORD_HASH = 'sha512_crypt'
SECURITY_PASSWORD_SALT = 'XXXXXXXXXX'
SECRET_KEY = 'XXXXXXXXXX'

SECURITY_REGISTERABLE = False

# Mail
MAIL_SERVER = 'XXXXXXXXXX'
MAIL_PORT = 465
MAIL_USE_SSL = True
MAIL_USERNAME = 'XXXXXXXXXX'
MAIL_PASSWORD = 'XXXXXXXXXX'

BOOTSTRAP_SERVE_LOCAL = True

SSLYZE_PATH = 'XXXXXXXXXX/egov-monitor/venv/bin/sslyze_cli.py'

REGION_ES = 'XXXXXXXXXX'

REGION_CSV = 'XXXXXXXXXX/egov-monitor/import/AuszugGV1QAktuell.csv'
WIKIDATA_SITES_AGS = 'XXXXXXXXXX/egov-monitor/import/wikidata-sites-ags.json'
WIKIDATA_SITES_RGS = 'XXXXXXXXXX/egov-monitor/import/wikidata-sites-rgs.json'
ONLINECHECK_CSV = 'XXXXXXXXXX/egov-monitor/import/nrw-survey-2016.csv'


