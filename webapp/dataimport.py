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

import datetime, calendar, email.utils, re, urllib, urllib2, json, math, subprocess, socket, sys, unicodecsv, translitcodec, requests, urllib3
from lxml import etree
from sqlalchemy import or_, desc, asc
from models import *
from webapp import app, db, es
import util

def import_regions():
  print "Importing %s" % app.config['REGION_CSV']
  with open(app.config['REGION_CSV'], 'rb') as region_file:
    region_list = unicodecsv.reader(region_file, delimiter=',', quotechar='"', quoting=unicodecsv.QUOTE_MINIMAL)
    old_ids = {}
    rgs_before = ''
    name_before = ''
    region_save = None
    region_level_before = -1
    for region in region_list:
      # generate region
      rgs = region[2]
      if region[3]:
        rgs += region[3]
      else:
        rgs += "0"
      if region[4]:
        rgs += region[4]
      else:
        rgs += "00"
      if region[5]:
        rgs += region[5]
      else:
        rgs += "0000"
      if region[6]:
        rgs += region[6]
      else:
        rgs += "000"
      # save last if current row is no duplicate
      if region_save:
        if region_save.rgs != rgs and not (region[7] == region_save.name and rgs == region_save.rgs[0:9] + region_save.rgs[6:9]):
          print u"save data from %s (%s)" % (region_save.name, region_save.rgs)
          db.session.add(region_save)
          db.session.commit()
          
          old_ids[region_save.region_level] = region_save.id
          
      # get / generate new region_ave
      region_save = Region.query.filter_by(rgs=rgs)
      if not region_save.count():
        region_save = Region()
        region_save.created = datetime.datetime.now()
      else:
        region_save = region_save.first()
      # assign data
      region_save.updated = datetime.datetime.now()
      region_save.rgs = rgs
      region_save.postalcode = region[14]
      if region[16]:
        region_save.lat = region[16].replace(',', '.')
      if region[15]:
        region_save.lon = region[15].replace(',', '.')
      region_save.region_level = int(region[0])
      if region_save.region_level not in [10, 20, 30, 40, 50, 60]:
        print "Unknown Region ID found at RGS %s" % rgs
      region_save.name = region[7]
      region_save.slug = slugify(region[7] + '-' + rgs)
      #calculate parent id
      temp_level = region_save.region_level
      while temp_level <= 60:
        old_ids[temp_level] = -1
        temp_level += 10
      temp_level = region_save.region_level - 10
      parent_id = -1
      while temp_level > 0:
        if old_ids[temp_level] != -1:
          parent_id = old_ids[temp_level]
          break
        temp_level -= 10
      if parent_id != -1:
        region_save.region_parent_id = parent_id
    # save last item
    db.session.add(region_save)
    db.session.commit()

def import_wikidata_sites_rgs():
  with open(app.config['WIKIDATA_SITES_RGS']) as data_file:    
    data = json.load(data_file)
  
  data = data['results']['bindings']
  
  for item in data:
    region = Region.query.filter(Region.rgs.like(item['rgs']['value']))
    import_wikidata_sites_process(item, region)

def import_wikidata_sites_ags():
  with open(app.config['WIKIDATA_SITES_AGS']) as data_file:    
    data = json.load(data_file)
  
  data = data['results']['bindings']
  
  for item in data:
    region = Region.query.filter(Region.rgs.like(item['ags']['value'][0:5] + '%' + item['ags']['value'][5:8]))
    import_wikidata_sites_process(item, region)


def import_wikidata_sites_process(item, region):
  if region.count() == 1:
    region = region.first()
    service_site = ServiceSite.query.filter_by(region_id=region.id)
    if service_site.count() == 0:
      service_site = ServiceSite()
      service_site.created = datetime.datetime.now()
      service_site.updated = datetime.datetime.now()
      service_site.active = 1
      service_site.region_id = region.id
      service_site.service_id = 1
      service_site.quality_show = 1
      service_site.quality = 'online'
    else:
      service_site = service_site.first()
    service_site.updated = datetime.datetime.now()
    service_site.url = item['website']['value']
    
    # get / set host
    service_site.host_id = util.save_host(get_host(service_site.url), region)
    
    # save service_site
    db.session.add(service_site)
    db.session.commit()


def import_basic_services():
  service_group_data = {
    1: {
      'name': 'Allgemein'
    },
    2: {
      'name': 'eGovernment-Dienste'
    },
    3: {
      'name': 'Daten-Dienste'
    }
  }
  for key, service_group_item in service_group_data.iteritems():
    service_group = ServiceGroup()
    service_group.created = datetime.datetime.now()
    service_group.updated = datetime.datetime.now()
    service_group.active = 1
    service_group.name = service_group_item['name']
    db.session.add(service_group)
    db.session.commit()
    
  service_data = {
    1: {
      'name': 'Website',
      'fa_icon': 'globe',
      'descr_short': 'Die Website.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 1
    },
    2: {
      'name': 'Ratsinformationssystem',
      'fa_icon': 'file-text',
      'descr_short': 'Dokumentation aller politischen Entscheidungen.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 3
    },
    3: {
      'name': 'Wunschkennzeichen',
      'fa_icon': 'car',
      'descr_short': 'Wunschkennzeichen online beantragen.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 2
    },
    4: {
      'name': 'Bauantrag',
      'fa_icon': 'home',
      'descr_short': 'Bauantrag online stellen.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 2
    },
    5: {
      'name': 'Bibliothek',
      'fa_icon': 'book',
      'descr_short': 'Online Katalog einsehen und Bücher ausleihen.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 2 
    },
    6: {
      'name': 'Dokumenten-Status',
      'fa_icon': 'file',
      'descr_short': 'Online-Check, ob z.B. der Personalausweis fertiggestellt wurde.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 2
    },
    7: {
      'name': 'Urkunden-Bestellung',
      'fa_icon': 'file-text',
      'descr_short': 'Urkunden online bestellen',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 2
    },
    8: {
      'name': 'Gewerbe-Anmeldung',
      'fa_icon': 'industry',
      'descr_short': 'Gewerbe online anmelden.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 2
    },
    9: {
      'name': 'Hunde-Anmeldung',
      'fa_icon': 'paw',
      'descr_short': 'Hund online anmelden.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 2
    },
    10: {
      'name': 'Vergabe-Plattform',
      'fa_icon': 'briefcase',
      'descr_short': 'Eigene Vergabe-Plattform.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 3
    },
    11: {
      'name': 'Termin-Buchung',
      'fa_icon': 'calendar',
      'descr_short': 'Termin für Behördengang buchen.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 2
    },
    12: {
      'name': 'Kita-Anmeldung',
      'fa_icon': 'child',
      'descr_short': 'Online Kita finden und Kind anmelden',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 2
    },
    13: {
      'name': 'Smartphone-App',
      'fa_icon': 'mobile',
      'descr_short': 'Smartphone-Applikation der Verwaltung.',
      'descr': '',
      'make_ssl_test': 0,
      'service_group_id': 1
    },
    14: {
      'name': 'Wahldaten',
      'fa_icon': 'pie-chart',
      'descr_short': 'Die Ergebnisse der vergangenen Wahlen.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 3
    },
    15: {
      'name': 'Statistiken',
      'fa_icon': 'bar-chart',
      'descr_short': 'Wissenswerte Zahlen.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 3
    },
    16: {
      'name': 'OpenData-Portal',
      'fa_icon': 'database',
      'descr_short': 'Portal mit offenen Daten.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 3
    },
    17: {
      'name': 'Anliegen-Management',
      'fa_icon': 'commenting',
      'descr_short': 'Vorschläge einsehen und melden.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 2
    },
    18: {
      'name': 'Facebook',
      'fa_icon': 'facebook',
      'descr_short': 'Facebook-Präsenz.',
      'descr': '',
      'make_ssl_test': 0,
      'service_group_id': 1
    },
    19: {
      'name': 'Twitter',
      'fa_icon': 'twitter',
      'descr_short': 'Twitter-Account.',
      'descr': '',
      'make_ssl_test': 0,
      'service_group_id': 1
    },
    20: {
      'name': 'Responsive',
      'fa_icon': 'mobile',
      'descr_short': 'Smartphone-Optimierte Website.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 1
    },
    21: {
      'name': u'Fundbüro',
      'fa_icon': 'umbrella',
      'descr_short': 'Fundsachen online einsehen.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 3
    },
    22: {
      'name': u'Bewohner-Parkausweis',
      'fa_icon': 'car',
      'descr_short': 'Bewohner-Parkausweis online beantragen',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 2
    },
    23: {
      'name': u'Haushalt-Daten',
      'fa_icon': 'umbrella',
      'descr_short': 'Fundsachen online einsehen.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 3
    },
    24: {
      'name': u'Gewerberegister',
      'fa_icon': 'industry',
      'descr_short': 'Öffentliches Gewerberegister.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 3
    },
    25: {
      'name': u'Flüchtlingshilfe',
      'fa_icon': 'info-circle',
      'descr_short': 'Übersicht für Flüchtende und Helfer.',
      'descr': '',
      'make_ssl_test': 1,
      'service_group_id': 1
    }
  }
  for key, service_item in service_data.iteritems():
    service = Service()
    service.created = datetime.datetime.now()
    service.updated = datetime.datetime.now()
    service.active = 1
    service.name = service_item['name']
    service.fa_icon = service_item['fa_icon']
    service.descr_short = service_item['descr_short']
    service.descr = service_item['descr']
    service.make_ssl_test = service_item['make_ssl_test']
    service.service_group_id = service_item['service_group_id']
    db.session.add(service)
    db.session.commit()
  
def extract_mailserver(start_with):
  service_sites = ServiceSite.query.filter_by(active=1).filter_by(service_id=1).filter(ServiceSite.id > int(start_with)).all()
  for service_site in service_sites:
    extract_mailserver_single(service_site.region_id, service_site.url)
  
def extract_mailserver_single(region_id, url):
  base_host = '.'.join(get_host(url).split('.')[-2:])
  try:
    mx_hosts = dns.resolver.query(base_host, 'MX')
    print "Adding MX Record Hosts for %s" % base_host
    for mx_host in mx_hosts:
      mx_host_name = str(mx_host.exchange)
      if mx_host_name[-1] == '.':
        mx_host_name = mx_host_name[0:-1]
      host = Host.query.filter_by(type=2).filter_by(host=mx_host_name)
      if host.count():
        host = host.first()
      else:
        host = Host()
        host.created = datetime.datetime.now()
        host.host = mx_host_name
        host.type = 2
      host.active = 1
      host.updated = datetime.datetime.now()
      host.ip = get_ip(host.host)
      if host.ip:
        host.reverse_hostname = get_reverse_hostname(host.ip)
      host.regions.append(Region.query.filter_by(id=region_id).first())
      db.session.add(host)
      db.session.commit()
  except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
    print "WARNING: %s has no valid MX record!" % base_host



def import_onlinecheck():
  # mapping
  mapping = {
    # 2: RGS
    3: 2, # Ratsinformationssystem
    8: 3, # Wunschkennzeichen
    10: 4, # Bauantrag
    12: 5, # Bibliothek
    14: 6, # Personalausweis-Status
    16: 7, # Urkunden-Bestellung
    18: 8, # Gewerbe-Anmeldung
    20: 22, #Bewohner-Parkausweis
    22: 9, # Hunde-Anmeldung
    24: 10, # Vergabe-Plattform
    26: 11, # Termin-Buchung
    28: 21, # Fundbüro
    30: 12, # Kita-Anmeldung
    36: 13, # Verwaltungs-App
    40: 23, # Haushalt
    44: 14, # Wahldaten
    60: 24, # Gewerberegister
    62: 15, # Statistiken
    64: 16, # OpenData-Portal
    68: 17, # Anliegen-Management
    78: 18, # Facebook
    80: 19, # Twitter
    88: 25, # Flüchtlingshilfe
    94: 20 # Responsive
  }
  
  with open(app.config['ONLINECHECK_CSV'], 'rb') as region_file:
    onlinecheck_list = unicodecsv.reader(region_file, delimiter=',', quotechar='"', quoting=unicodecsv.QUOTE_MINIMAL)
    for item in onlinecheck_list:
      region = Region.query.filter_by(rgs=item[2])
      if region.count() == 1:
        region = region.first()
        for key in mapping:
          if item[key] != '':
            if not item[key + 1] or item[key + 1][0:7] == 'http://' or item[key + 1][0:8] == 'https://':
              service_site = ServiceSite.query.filter_by(region_id=region.id).filter_by(service_id=mapping[key])
              if service_site.count():
                service_site = service_site.first()
              else:
                service_site = ServiceSite()
                service_site.created = datetime.datetime.now()
                service_site.active = 1
                service_site.region_id = region.id
                service_site.service_id = mapping[key]
              service_site.updated = datetime.datetime.now()
              service_site.url = item[key + 1]
              service_site.quality_show = 1 if item[key] == '1' else 0
              # Ratsinformationssystem: all public
              # Anliegen-Management
              if key == 68:
                if item[key] != '1':
                  service_site.quality = 'offline'
                elif item[key + 3] == '1':
                  service_site.quality = 'public'
                else:
                  service_site.quality = 'nonpublic'
              # Responsive
              elif key == 94:
                service_site.quality = 'yes' if item[key] == '1' else 'no'
              else:
                service_site.quality = 'online' if item[key] == '1' else 'offline'
              if service_site.url:
                service_site.host = util.save_host(get_host(service_site.url), region)
              print "add url %s at RGS %s field %s as %s" % (item[key + 1], item[2], key, service_site.quality)
              db.session.add(service_site)
              db.session.commit()
            else:
              print "malformed url %s at RGS %s field %s" % (item[key + 1], item[2], key)



def import_osm():
  "http://overpass-api.de/api/interpreter?data=[out:json];(rel(62644);>;);out;"
  pass

