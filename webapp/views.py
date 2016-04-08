# encoding: utf-8

"""
Copyright (c) 2014 Ernesto Ruge

Hiermit wird unentgeltlich jeder Person, die eine Kopie der Software und
der zugehörigen Dokumentationen (die "Software") erhält, die Erlaubnis
erteilt, sie uneingeschränkt zu benutzen, inklusive und ohne Ausnahme, dem
Recht, sie zu verwenden, kopieren, ändern, fusionieren, verlegen,
verbreiten, unterlizenzieren und/oder zu verkaufen, und Personen, die diese
Software erhalten, diese Rechte zu geben, unter den folgenden Bedingungen:

Der obige Urheberrechtsvermerk und dieser Erlaubnisvermerk sind in allen
Kopien oder Teilkopien der Software beizulegen.

Die Software wird ohne jede ausdrückliche oder implizierte Garantie
bereitgestellt, einschließlich der Garantie zur Benutzung für den
vorgesehenen oder einen bestimmten Zweck sowie jeglicher Rechtsverletzung,
jedoch nicht darauf beschränkt. In keinem Fall sind die Autoren oder
Copyrightinhaber für jeglichen Schaden oder sonstige Ansprüche haftbar zu
machen, ob infolge der Erfüllung eines Vertrages, eines Delikts oder anders
im Zusammenhang mit der Software oder sonstiger Verwendung der Software
entstanden.
"""

from webapp import app, es, basic_auth, mail
from flask import render_template, make_response, abort, request, Response, redirect, flash, send_file
from flask.ext.mail import Message
from models import *
from forms import *
import util
import json, time, os, datetime
from subprocess import call
from sqlalchemy import or_, desc, asc
import re, time, elasticsearch

URL_REGEX = re.compile(
    u"^"
    # protocol identifier
    u"(?:(?:https?|ftp)://)"
    # user:pass authentication
    u"(?:\S+(?::\S*)?@)?"
    u"(?:"
    # IP address exclusion
    # private & local networks
    u"(?!(?:10|127)(?:\.\d{1,3}){3})"
    u"(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})"
    u"(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})"
    # IP address dotted notation octets
    # excludes loopback network 0.0.0.0
    # excludes reserved space >= 224.0.0.0
    # excludes network & broadcast addresses
    # (first & last IP address of each class)
    u"(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])"
    u"(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}"
    u"(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))"
    u"|"
    # host name
    u"(?:(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)"
    # domain name
    u"(?:\.(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)*"
    # TLD identifier
    u"(?:\.(?:[a-z\u00a1-\uffff]{2,}))"
    u")"
    # port number
    u"(?::\d{2,5})?"
    # resource path
    u"(?:/\S*)?"
    u"$"
    , re.UNICODE)

@app.route('/')
def index():
  return render_template('index.html')

@app.route("/api/region-search-live")
def region_search():
  start_time = time.time()
  result = []
  search_string = request.args.get('q', False)
  # generate fulltext search string
  if not search_string:
    search_results = []
  else:
    search_string = search_string.split()
    search_string_to_complete = search_string[-1]
    query_parts = []
    query_parts.append({
      'match_phrase_prefix': {
        'name': search_string_to_complete.lower()
      }
    })
    if len(search_string[0:-1]):
      query_parts.append({
        'query_string': {
          'fields': ['name'],
          'query': " ".join(search_string[0:-1]),
          'default_operator': 'and'
        }
      })
    try:
      result = es.search(
        index = "%s-latest" % app.config['REGION_ES'],
        doc_type = 'regions',
        fields = 'name,slug,postalcode,location',
        body = {
          'query': {
            'bool': {
              'must': query_parts
            }
          },
          'aggs': {
            'fragment': {
              'terms': {
                'field': 'name',
                'include': {
                  'pattern': search_string_to_complete.lower() + '.*',
                  'flags': 'CANON_EQ|CASE_INSENSITIVE',
                },
                'min_doc_count': 0,
                'size': 10
              }
            }
          }
        },
        size = 10
      )
    except elasticsearch.NotFoundError:
      abort(403)
    search_results = []
    for dataset in result['hits']['hits']:
      tmp_search_result = {
        'name': dataset['fields']['name'][0],
        'postalcode': dataset['fields']['postalcode'][0] if len(dataset['fields']['postalcode']) else None,
        'slug': dataset['fields']['slug'][0]
      }
      search_results.append(tmp_search_result)

  ret = {
    'status': 0,
    'duration': round((time.time() - start_time) * 1000),
    'response': search_results
  }
  json_output = json.dumps(ret, cls=util.MyEncoder, sort_keys=True)
  response = make_response(json_output, 200)
  response.mimetype = 'application/json'
  response.headers['Expires'] = util.expires_date(hours=24)
  response.headers['Cache-Control'] = util.cache_max_age(hours=24)
  return(response)

@app.route("/region/<region_slug>", methods=['GET', 'POST'])
def region(region_slug):
  region = Region.query.filter_by(slug=region_slug).first_or_404()
  service_sites_raw = ServiceSite.query.filter_by(region_id=region.id).filter_by(quality_show=1).join(Service).order_by(Service.service_group_id).order_by(Service.name).all()
  service_sites = {1: [], 2: [], 3: []}
  for service_site in service_sites_raw:
    service_sites[service_site.Service.service_group_id].append(service_site)
  hosts = Host.query.filter_by(active=1).join(ServiceSite).filter_by(region_id=region.id).filter_by(active=1).join(Service).filter_by(make_ssl_test=1).all()
  services_raw = Service.query.filter_by(active=1).order_by(Service.name).all()
  services = {}
  for service in services_raw:
    if service.ServiceGroup.name not in services:
      services[service.ServiceGroup.name] = []
    services[service.ServiceGroup.name].append(service)
  if request.method == 'POST':
    url = request.form.get('new-service-site-url', None)
    service = request.form.get('new-service-site-service', None, type=int)
    service_string = request.form.get('new-service-site-service-string', None)
    status = request.form.get('new-service-site-status', None, type=int)
    error = False
    if not re.match(URL_REGEX, url):
      flash(u'Bitte korrekte URL angeben.', 'error')
    if not service and not service_string:
      flash(u'Bitte Service wählen', 'error')
      error = True
    if status not in [1, 2]:
      flash(u'Bitte Status wählen.', 'error')
      error = True
    if not error:
      suggestion = Suggestion()
      suggestion.created = datetime.datetime.now()
      suggestion.updated = datetime.datetime.now()
      suggestion.type = 'service-site-new'
      suggestion_data = {
        'url': url,
        'status': 1 if status == 1 else 0,
      }
      if service:
        suggestion_data['service'] = service
      else:
        suggestion_data['service-string'] = service_string
      suggestion.suggestion = json.dumps(suggestion_data)
      
      db.session.add(suggestion)
      db.session.commit()
      flash(u'Seite erfolgreich hinzugefügt!', 'success')
  return render_template('region.html', region=region, service_sites=service_sites, hosts=hosts, services=services)

"""
      if service:
        service_id = Service.query.filter_by(id=service)
        if not service_id.count():
          abort(403)
        service_id = service_id.first().id
      else:
        service = Service()
        service.created = datetime.datetime.now()
        service.updated = datetime.datetime.now()
        service_site.active = 0
        service.name = service_string
        db.session.add(service)
        db.session.commit()
        service_id = service.id
      service_site = ServiceSite()
      service_site.created = datetime.datetime.now()
      service_site.updated = datetime.datetime.now()
      service_site.active = 0
      service_site.url = url
      service_site.quality_show = 1 if status == 1 else 0
      service_site.host_id = util.save_host(url)
      servive_site.service_id = service_id
      service_site.region_id = region.id
      
      db.session.add(servive_site)
      db.session.commit()
"""

@app.route("/host/<host>")
def host(host):
  ssl_test = SslTest.query.join(Host).filter_by(host=host).order_by(desc(SslTest.created)).first_or_404()
  return render_template('host_encryption.html', ssl_test=ssl_test)


@app.route("/analysis/basics")
def analysis_basics():
  visualisations_raw = Visualisation.query.all()
  visualisations = {}
  for visualisation_raw in visualisations_raw:
    visualisations[visualisation_raw.identifier] = visualisation_raw
  return render_template('analysis_basics.html', visualisations=visualisations)

@app.route("/analysis/egovernment")
def analysis_egovernment():
  visualisations_raw = Visualisation.query.all()
  visualisations = {}
  for visualisation_raw in visualisations_raw:
    visualisations[visualisation_raw.identifier] = visualisation_raw
  return render_template('analysis_egovernment.html', visualisations=visualisations)

@app.route("/analysis/data")
def analysis_data():
  visualisations_raw = Visualisation.query.all()
  visualisations = {}
  for visualisation_raw in visualisations_raw:
    visualisations[visualisation_raw.identifier] = visualisation_raw
  return render_template('analysis_data.html', visualisations=visualisations)

@app.route("/analysis/encryption")
def analysis_encryption():
  visualisations_raw = Visualisation.query.all()
  visualisations = {}
  for visualisation_raw in visualisations_raw:
    visualisations[visualisation_raw.identifier] = visualisation_raw
  return render_template('analysis_encryption.html', visualisations=visualisations)


@app.route("/info/ueber")
def info_ueber():
  return render_template('info_ueber.html')

@app.route("/info/services")
def info_services():
  services_raw = Service.query.order_by(Service.service_group_id).order_by(Service.name).all()
  services = {1: [], 2: [], 3: []}
  for service in services_raw:
    services[service.service_group_id].append(service)
  return render_template('info_services.html', services=services)

@app.route("/info/encryption")
def info_encryption():
  return render_template('info_encryption.html')

@app.route("/info/data")
def info_data():
  return render_template('info_data.html')

@app.route("/info/faq")
def info_faq():
  return render_template('info_faq.html')

@app.route("/impress")
def impressum():
  return render_template('impress.html')

@app.route("/privacy")
def api():
  return render_template('privacy.html')
