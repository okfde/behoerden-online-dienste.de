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

from flask.ext.script import Manager
from flask.ext.migrate import Migrate, MigrateCommand

from webapp import app, db, util, encryption, visualisation, dataimport

manager = Manager(app)
migrate = Migrate(app, db)

manager.add_command('db', MigrateCommand)

@manager.command
def import_data(which):
  if which == 'regions':
    dataimport.import_regions()
  elif which == 'wikidata_sites_ags':
    dataimport.import_wikidata_sites_ags()
  elif which == 'wikidata_sites_rgs':
    dataimport.import_wikidata_sites_rgs()
  elif which == 'onlinecheck':
    dataimport.import_onlinecheck()
  elif 'osm':
    dataimport.import_osm()
  elif 'basic_services':
    dataimport.import_basic_services()
  else:
    print "Bitte Unterbefehl angeben!"

@manager.command
def extract_mailserver(start_with):
  util.extract_mailserver(start_with)

@manager.command
def extract_mailserver_single():
  util.extract_mailserver_single()

@manager.command
def delete(which, object_id):
  if which == 'service_site':
    util.service_site_delete(object_id)
  else:
    print "Bitte Unterbefehl angeben!"

@manager.command
def check_database():
  util.check_database()

@manager.command
def user_submission(which, object_id):
  if which == 'accept':
    util.user_submission_accept(object_id)
  elif which == 'deny':
    util.user_submission_deny(object_id)
  else:
    print "Bitte Unterbefehl angeben!"

@manager.command
def es_import_regions():
  util.regions_to_elastic()

@manager.command
def ssl(which, start):
  if which == 'check':
    encryption.ssl_check(start)
  elif which == 'check_single':
    encryption.ssl_check_single(start)
  elif which == 'validate':
    encryption.ssl_check_validate()
  elif which == 'summary':
    encryption.ssl_check_summary()
  elif which == 'summary_single':
    encryption.ssl_check_summary_single(start)
  elif which == 'export_cipher':
    encryption.update_export_cipher()
  else:
    print "Bitte Unterbefehl angeben!"

@manager.command
def generate_visualisations():
  util.generate_visualisations()

if __name__ == "__main__":
  manager.run()