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
from sqlalchemy import or_, desc, asc, text
from models import *
from webapp import app, db, es

slugify_re = re.compile(r'[\t !"#$%&\'()*\-/<=>?@\[\\\]^_`{|},.]+')


def hoster_check():
  #do it with http://secynic.github.io/ipwhois/README.html
  pass

def execute(cmd):
  output, error = subprocess.Popen(
    cmd, shell=True, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE).communicate()
  return(output, error)

def get_host(host):
  if host[0:8] == 'https://':
    host = host[8:]
  if host[0:7] == 'http://':
    host = host[7:]
  host = host.split('/')[0]
  host_regexp = re.compile(r"^([\w.-]*)$")
  host_check = host_regexp.match(host)
  if host_check:
    if host_check.group(1) == host:
      return host
  return ""

def get_ip(host):
  try:
    ip = socket.gethostbyname(host)
  except socket.gaierror:
    return False
  return ip

def get_reverse_hostname(ip):
  try:
    reverse_hostname = socket.gethostbyaddr(ip)
    return reverse_hostname[0]
  except socket.herror:
    return False

def save_host(hostname, region):
  host = Host.query.filter_by(host=hostname)
  if host.count() == 0:
    host = Host()
    host.created = datetime.datetime.now()
    host.updated = datetime.datetime.now()
    host.type = 1
    host.active = 1
    host.host = hostname
    host.ip = get_ip(hostname)
    if host.ip:
      host.reverse_hostname = get_reverse_hostname(host.ip)
    host.regions.append(region)
    db.session.add(host)
    db.session.commit()
  else:
    host = host.first()
    if not region in host.regions:
      host.regions.append(region)
    db.session.add(host)
    db.session.commit()
  return host


def service_site_delete(object_id):
  service_site = ServiceSite.query.filter_by(id=object_id).first()
  if ServiceSite.query.filter_by(host_id = service_site.host_id).count() == 1:
    host = Host.query.filter_by(id=service_site.host_id).first()
    db.session.delete(host)
    ssl_tests = SslTest.query.filter_by(host_id=service_site.host_id).all()
    for ssl_test in ssl_tests:
      db.session.delete(ssl_test)
  db.session.delete(service_site)
  db.session.commit()
  
def check_database():
  # remove duplicates in hosts_regions
  query = text("SELECT host_id, region_id, count(*) FROM hosts_regions GROUP BY host_id, region_id HAVING count(*) > 1")
  duplicates = db.engine.execute(query)
  counter = 0
  for duplicate in duplicates:
    query = text("DELETE FROM hosts_regions WHERE host_id = %s AND region_id = %s LIMIT %s" % (duplicate[0], duplicate[1], duplicate[2] - 1))
    db.engine.execute(query)
    counter += 1
  print "Removed %s duplicates" % (counter)

def user_submission_accept(object_id):
  suggestion = Suggestion.query.filter_by(id=object_id).first()
  if suggestion.type == 'service-site-new':
    data = json.loads(suggestion.suggestion)
    service_site = ServiceSite()
    service_site.created = datetime.datetime.now()
    service_site.updated = datetime.datetime.now()
    service_site.active = 1
    service_site.url = data['url']
    service_site.quality = 'online' if data['status'] else 'offline'
    service_site.quality_show = data['status']
    service_site.region_id = data['region']
    region = Region.query.filter_by(id=data['region']).first()
    host = save_host(get_host(data['url']), region)
    service_site.host_id = host.id
    if 'service' in data:
      service_site.service_id = data['service']
    else:
      service = Service()
      service.created = datetime.datetime.now()
      service.updated = datetime.datetime.now()
      service.active = 0
      service.name = data['service-string']
      db.session.delete(service)
      db.session.commit()
      print "Added Service with ID %s, please provide details" % (service.id)
      service_site.service_id = service_id
    db.session.add(service_site)
    db.session.commit()

def user_submission_deny(object_id):
  suggestion = Suggestion.query.filter_by(id=object_id).first()
  db.session.delete(suggestion)
  db.session.commit()


def regions_to_elastic():
  new_index = "%s-%s" % (app.config['REGION_ES'], datetime.datetime.utcnow().strftime('%Y%m%d-%H%M'))
  try:
    es.indices.delete_index(new_index)
  except:
    pass
  
  print "Creating index %s" % new_index
  index_init = {
    'settings': {
      'index': {
        'analysis': {
          'analyzer': {
            'my_simple_german_analyzer': {
              'type': 'custom',
              'tokenizer': 'standard',
              'filter': ['standard', 'lowercase']
            }
          }
        }
      }
    },
    'mappings': {
    }
  }
  index_init['regions'] = {
    'properties': {
      'ID': {
        'store': True,
        'type': 'string'
      },
      'name': {
        'store': True,
        'type': 'string',
        'index': 'analyzed',
        'analyzer': 'my_simple_german_analyzer'
      },
      'slug': {
        'store': True,
        'type': 'string'
      },
      'postalcode': {
        'store': True,
        'type': 'string'
      },
      'location': {
        'store': True,
        'type': 'geo_point',
        'lat_lon': True
      }
    }
  }
  es.indices.create(index=new_index, ignore=400, body=index_init)
  regions = Region.query.all()
  for region in regions:
    dataset = {
      'name': region.name,
      'slug': region.slug,
      'postalcode': region.postalcode,
      'location': "%s,%s" % (region.lat, region.lon)
    }
    es.index(index=new_index,
             doc_type='regions',
             body=dataset)
  latest_name = '%s-latest' % app.config['REGION_ES']
  alias_update = []
  try:
    latest_before = es.indices.get_alias(latest_name)
    for single_before in latest_before:
      alias_update.append({
        'remove': {
          'index': single_before,
          'alias': latest_name
        }
      })
  except:
    pass
  alias_update.append({
    'add': {
      'index': new_index,
      'alias': latest_name
    }
  })
  print "Aliasing index %s to '%s'" % (new_index, latest_name)
  es.indices.update_aliases({ 'actions': alias_update })
  index_before = es.indices.get('%s*' % app.config['REGION_ES'])
  for single_index in index_before:
    if new_index != single_index:
      print "Deleting index %s" % single_index
      es.indices.delete(single_index)
  

  
# Creates a slug
def slugify(text, delim=u'-'):
  """Generates an ASCII-only slug."""
  result = []
  for word in slugify_re.split(text.lower()):
    word = word.encode('translit/long')
    if word:
      result.append(word)
  return unicode(delim.join(result))

def rfc1123date(value):
  """
  Gibt ein Datum (datetime) im HTTP Head-tauglichen Format (RFC 1123) zurück
  """
  tpl = value.timetuple()
  stamp = calendar.timegm(tpl)
  return email.utils.formatdate(timeval=stamp, localtime=False, usegmt=True)

def expires_date(hours):
  """Date commonly used for Expires response header"""
  dt = datetime.datetime.now() + datetime.timedelta(hours=hours)
  return rfc1123date(dt)

def cache_max_age(hours):
  """String commonly used for Cache-Control response headers"""
  seconds = hours * 60 * 60
  return 'max-age=' + str(seconds)

def obscuremail(mailaddress):
  return mailaddress.replace('@', '__AT__').replace('.', '__DOT__')
app.jinja_env.filters['obscuremail'] = obscuremail

class MyEncoder(json.JSONEncoder):
  def default(self, obj):
    return str(obj)
