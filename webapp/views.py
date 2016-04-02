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

@app.route("/region/<region_slug>", methods=['GET', 'POST'])
def region(region_slug):
  region = Region.query.filter_by(slug=region_slug).first_or_404()
  service_sites_raw = ServiceSite.query.filter_by(region_id=region.id).filter_by(quality_show=1).join(Service).order_by(Service.service_group_id).order_by(Service.name).all()
  service_sites = {1: [], 2: [], 3: []}
  for service_site in service_sites_raw:
    service_sites[service_site.Service.service_group_id].append(service_site)
  hosts = Host.query.filter_by(active=1).join(ServiceSite).filter_by(region_id=region.id).filter_by(active=1).join(Service).filter_by(make_ssl_test=1).all()
  """
  if request.method == 'POST':
    host = request.form.get('new-site-host')
    host_type = request.form.get('new-site-type')
    host = util.get_host(host)
    if host:
      if Host.query.filter_by(host=host).filter_by(region_id=region.id).count():
        flash(u'Website bereits vorhanden.', 'error')
      else:
        new_host = Host()
        new_host.host = host
        new_host.active = 0
        new_host.ip = util.get_ip(host)
        new_host.reverse_hostname = util.get_reverse_hostname(new_host.ip)
        new_host.created = datetime.datetime.now()
        new_host.updated = datetime.datetime.now()
        new_host.type = host_type
        new_host.region_id = region.id
        db.session.add(new_host)
        db.session.commit()
        # TODO: Get Mail Server
        flash(u'Website wurde hinzugefügt und muss nun freigeschaltet werden.', 'success')
    else:
      flash(u'Host in falschem Format.', 'error')
  """
  return render_template('region.html', region=region, service_sites=service_sites, hosts=hosts)


@app.route("/host/<host>")
def host(host):
  ssl_test = SslTest.query.join(Host).filter_by(host=host).order_by(desc(SslTest.created)).first_or_404()
  return render_template('host_ssl.html', ssl_test=ssl_test)


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
    """
    # generate facet terms
    rest = True
    x = 0
    factet_list = []
    while rest:
      y = facets.find(":", x)
      if y == -1:
        break
      temp = facets[x:y]
      x = y + 1
      if facets[x:x+5] == "&#34;":
        y = facets.find("&#34;", x+5)
        if y == -1:
          break
        factet_list.append((temp, facets[x+5:y]))
        x = y + 6
        if x > len(facets):
          break
      else:
        y = facets.find(";", x)
        if y == -1:
          factet_list.append((temp, facets[x:len(facets)]))
          break
        else:
          factet_list.append((temp, facets[x:y]))
          x = y + 1
    for facet in factet_list:
      query_parts.append({
        'term': {
          facet[0]: facet[1]
        }
      })
    """
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



"""
@app.route('/site-ssl-check', methods=['GET', 'POST'])
def site_ssl_check():
  site_ssl_check = SiteSslCheck(request.form)
  hosters = Hoster.query.order_by(Hoster.name).all()
  hosters_result = []
  hosters_result.append((0, u'- bitte wählen -'))
  for hoster in hosters:
    hosters_result.append((hoster.id, hoster.name))
  hosters_result.append((-1, u'Neuer Hoster'))
  site_ssl_check.hoster.choices = hosters_result
  if site_ssl_check.validate_on_submit():
    error = False
    # check hoster
    hoster = request.form.get('hoster', 0, type=int)
    if not hoster:
      error = True
      site_ssl_check.hoster.errors.append('Bitte geben Sie einen Hoster an.')
    elif hoster == -1:
      hoster_new = request.form.get('hoster-new', None)
      if not hoster_new:
        error = True
        site_ssl_check.hoster.errors.append('Bitte geben Sie einen Hoster an.')
    # check type
    host_type = request.form.get('type', 0, type=int)
    if host_type == -1:
      host_type_new = request.form.get('type-new', None)
      if not host_type_new:
        error = True
        site_ssl_check.type.errors.append('Bitte geben Sie einen Typus an.')
    elif host_type < 1 or host_type > 5:
      error = True
      site_ssl_check.type.errors.append('Bitte geben Sie einen Typus an.')
    # check service_name
    service_name = request.form.get('service_name', None)
    if not service_name:
      site_ssl_check.service_name.errors.append(u'Bitte geben Sie den ungefähren Zeitpunkt Ihres Vertagsabschlusses an.X')
      error = True
    # check service_start
    service_start = request.form.get('service_start', None)
    if not service_start:
      site_ssl_check.service_start.errors.append(u'Bitte geben Sie den ungefähren Vertragsabschluss an.')
      error = True
    legal = request.form.get('legal', None)
    if legal != 'y':
      error = True
      site_ssl_check.legal.errors.append(u'Bitte bestätigen Sie, dass Sie legal handeln.')
    # check website
    website = request.form.get('website')
    if website[0:8] == 'https://':
      website = website[8:]
    if website[0:7] == 'http://':
      website = website[7:]
    website = website.split('/')[0]
    website_regexp = re.compile(r"^([\w.-]*)$")
    website_check = website_regexp.match(website)
    if website_check:
      if website_check.group(1) == website:
        ip = util.get_ip(website)
        if ip:
          reverse_hostname = util.get_reverse_hostname(ip)
          if reverse_hostname != False:
            if not error:
              region = Hoster.query.filter_by(id=hoster).first_or_404()
              site = Site()
              site.host = website
              site.reverse_hostname = reverse_hostname
              site.type = host_type
              site.service_name = service_name
              site.service_start = service_start
              site.hoster_id = hoster.id
              site.owner_ip = request.remote_addr
              site.owner_hostname = util.get_reverse_hostname(request.remote_addr)
              site.created = datetime.datetime.now()
              site.updated = datetime.datetime.now()
              site.active = 0
              db.session.add(site)
              db.session.commit()
              return redirect('/site-ssl-check/%s' % website)
  return render_template('site-ssl-check.html', site_ssl_check=site_ssl_check)
"""

@app.route('/region/<string:host>', methods=['GET', 'POST'])
def site_ssl_check_result(host):
  # some input validation
  if host:
    host_regexp = re.compile(r"^([\w.-]*)$")
    host_check = host_regexp.match(host)
    if host_check:
      if host_check.group(1) == host:
        # check if site was already added
        site_count = Site.query.filter_by(host=host).count()
        if not site_count:
          return redirect('/site-ssl-check')
  return render_template('site-ssl-check-result.html', host=host)


@app.route("/faq")
def faq():
  return render_template('faq.html')

@app.route("/faq/ssl")
def faq_ssl():
  return render_template('faq_ssl.html')

@app.route("/impress")
def impressum():
  return render_template('impress.html')

@app.route("/privacy")
def api():
  return render_template('privacy.html')

"""
@app.route('/api/ssl-details')
def api_ssl_details_basic():
  start_time = time.time()
  result = {}
  host = request.args.get('host', False)
  # some input validation
  if host:
    host_regexp = re.compile(r"^([\w.-]*)$")
    host_check = host_regexp.match(host)
    if host_check:
      if host_check.group(1) == host:
        # check if site was already added
        site_count = Site.query.filter_by(host=host).count()
        if not site_count:
          abort(403)
        # ssl available?
        result['port-443-available'] = util.check_port_443_available(host)
        # if yes: check ssl avaiable
        if result['port-443-available']:
          result.update(util.get_sslyze(host))
          if result['protocol-num'] > 1:
            result['fallback-scsv-available'] = util.check_fallback_scsv_available(host, result['protocol-best'])
  ret = {
    'status': 0,
    'duration': round((time.time() - start_time) * 1000),
    'response': result
  }
  json_output = json.dumps(ret, cls=util.MyEncoder, sort_keys=True)
  response = make_response(json_output, 200)
  response.mimetype = 'application/json'
  response.headers['Expires'] = util.expires_date(hours=24)
  response.headers['Cache-Control'] = util.cache_max_age(hours=24)
  return(response)
"""

@app.route('/api/ssl-details-html')
def api_ssl_details_basic():
  host = request.args.get('host', False)
  result = {}
  # some input validation
  if host:
    host_regexp = re.compile(r"^([\w.-]*)$")
    host_check = host_regexp.match(host)
    if host_check:
      if host_check.group(1) == host:
        # check if site was already added
        site = Site.query.filter_by(host=host).first_or_404()
        result = util.update_site_check(site.id)
  return render_template('site_ssl_check_result_api.html', data=result)
