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
  return render_template('region.html', region=region, service_sites=service_sites, hosts=hosts)


@app.route("/host/<host>")
def host(host):
  ssl_test = SslTest.query.join(Host).filter_by(host=host).order_by(desc(SslTest.created)).first_or_404()
  return render_template('host_encryption.html', ssl_test=ssl_test)


@app.route("/analysis/basics")
def analysis_basics():
  return render_template('analysis_basics.html')

@app.route("/analysis/egovernment")
def analysis_egovernment():
  return render_template('analysis_egovernment.html')

@app.route("/analysis/data")
def analysis_data():
  return render_template('analysis_data.html')

@app.route("/analysis/encryption")
def analysis_encryption():
  visualisations_raw = Visualisation.query.filter_by(identifier='encryption_total').all()
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
