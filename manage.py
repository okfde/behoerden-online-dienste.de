# encoding: utf-8

from flask.ext.script import Manager
from flask.ext.migrate import Migrate, MigrateCommand

from webapp import app, db, util

manager = Manager(app)
migrate = Migrate(app, db)

manager.add_command('db', MigrateCommand)

@manager.command
def import_regions():
  util.import_regions()

@manager.command
def import_wikidata_sites_ags():
  util.import_wikidata_sites_ags()

@manager.command
def import_wikidata_sites_rgs():
  util.import_wikidata_sites_rgs()
  
@manager.command
def import_onlinecheck():
  util.import_onlinecheck()
  
@manager.command
def import_osm():
  util.import_osm()

@manager.command
def host_ssl_check(host_id):
  util.update_host_check(host_id)

@manager.command
def es_import_regions():
  util.regions_to_elastic()

if __name__ == "__main__":
  manager.run()