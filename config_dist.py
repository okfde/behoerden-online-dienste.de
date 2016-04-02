# encoding: utf-8

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


