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
def import_basic_services():
  util.import_basic_services()


@manager.command
def es_import_regions():
  util.regions_to_elastic()


@manager.command
def ssl_check(start_with):
  util.ssl_check(start_with)

@manager.command
def ssl_check_single(host_id):
  util.ssl_check_single(host_id)

@manager.command
def ssl_check_validate():
  util.ssl_check_validate()

@manager.command
def ssl_check_summary():
  util.ssl_check_summary()

@manager.command
def ssl_check_summary_single(host_id):
  util.ssl_check_summary_single(host_id)


@manager.command
def generate_visualisations():
  util.generate_visualisations()

if __name__ == "__main__":
  manager.run()