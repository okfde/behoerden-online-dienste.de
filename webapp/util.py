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

import datetime, calendar, email.utils, re, urllib, urllib2, json, math, subprocess, socket, sys, unicodecsv, translitcodec
from lxml import etree
from models import *
from webapp import app, db, es


slugify_re = re.compile(r'[\t !"#$%&\'()*\-/<=>?@\[\\\]^_`{|},.]+')

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

def get_sslyze(host):
  result = {}
  ciphers = []
  data, error = subprocess.Popen(
    ['python', app.config['SSLYZE_PATH'], '--xml_out=-', '--regular', '--hsts', '--sni=' + host,  host],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE).communicate()
  
  parser = etree.XMLParser(recover=True)
  tree = etree.fromstring(data, parser=parser)
  for leaf in tree:
    if leaf.tag == 'invalidTargets':
      if len(leaf):
        if leaf[0] == 'Could not complete an SSL handshake':
          return {'ssl_ok': 0}
    elif leaf.tag == 'results':
      for target in leaf:
        if target.attrib['host'] == host:
          result['protocol_best'] = ''
          result['protocol_num'] = 0
          for module in target:
            if module.tag == 'certinfo':
              pass
            elif module.tag == 'certificateChain':
              if module.attr['hasSha1SignedCertificate'] == 'True':
                result['sha1_cert'] = True
              else:
                result['sha1_cert'] = False
            elif module.tag == 'compression':
              pass
            elif module.tag == 'heartbleed':
              if len(module):
                for child in module:
                  if child.tag == 'openSslHeartbleed':
                    if child.attrib['isVulnerable'] == 'False':
                      result['heartbleed'] = False
                    else:
                      result['heartbleed'] = True
                  else:
                    print "Unknown result in heartbleed reneg: %s" % child.tag
              else:
                result['heartbleed'] = False
            elif module.tag == 'hsts':
              if module[0].attrib['isSupported'] == 'True':
                result['hsts_available'] = True
              else:
                result['hsts_available'] = False
            elif module.tag == 'reneg':
              for child in module:
                if child.tag == 'sessionRenegotiation':
                  if child.attrib['isSecure'] == 'False':
                    result['session_renegotiation_secure'] = False
                  else:
                    result['session_renegotiation_secure'] = True
                  if child.attrib['canBeClientInitiated'] == 'False':
                    result['session_renegotiation_client'] = False
                  else:
                    result['session_renegotiation_client'] = True
                else:
                  print "Unknown result in module reneg: %s" % child.tag
            elif module.tag == 'resum':
              # not security relevant
              pass
            elif module.tag == 'openssl_ccs':
              for child in module:
                if child.tag == 'openSslCcsInjection':
                  if child.attrib['isVulnerable'] == 'True':
                    result['ccs_injection'] = True
                  else:
                    result['ccs_injection'] = False
            elif module.tag == 'fallback':
              for child in module:
                if child.tag == 'tlsFallbackScsv':
                  if child.attrib['isSupported'] == 'True':
                    result['fallback_scsv_available'] = True
                  else:
                    result['fallback_scsv_available'] = False
              pass
            elif module.tag == 'certinfo_basic':
              for child in module:
                if child.tag == 'certificateValidation':
                  for subchild in child:
                    if subchild.tag == 'hostnameValidation':
                      if subchild.attrib['certificateMatchesServerHostname'] == 'True':
                        result['cert_matches'] = True
                      else:
                        result['cert_matches'] = False
                elif child.tag == 'ocspStapling':
                  if child.attrib['isSupported'] == 'True':
                    result['ocsp_stapling'] = True
                  else:
                    result['ocsp_stapling'] = False
            elif module.tag == 'sslv2':
              result, ciphers = ssl_protocols(host, module, result, ciphers, 'sslv2')
            elif module.tag == 'sslv3':
              result, ciphers = ssl_protocols(host, module, result, ciphers, 'sslv3')
            elif module.tag == 'tlsv1':
              result, ciphers = ssl_protocols(host, module, result, ciphers, 'tlsv1')
            elif module.tag == 'tlsv1_1':
              result, ciphers = ssl_protocols(host, module, result, ciphers, 'tlsv1_1')
            elif module.tag == 'tlsv1_2':
              result, ciphers = ssl_protocols(host, module, result, ciphers, 'tlsv1_2')
            else:
              print "Unknown module: %s" % module.tag
        else:
          print "Unknown host: %s" % target.attrib['host']
    else:
      print "Unknown leaf: %s" % leaf.tag
  cipher_string = ' '.join(ciphers)
  if result['tlsv1_2_available']:
    result['protocol_best'] = 'tlsv1_2'
  elif result['tlsv1_1_available']:
    result['protocol_best'] = 'tlsv1_1'
  elif result['tlsv1_available']:
    result['protocol_best'] = 'tlsv1'
  elif result['sslv3_available']:
    result['protocol_best'] = 'sslv3'
  elif result['sslv2_available']:
    result['protocol_best'] = 'sslv2'
  result['rc4_available'] = 'RC4' in cipher_string
  result['md5_available'] = 'MD5' in cipher_string
  result['pfs_available'] = 'ECDHE_' in cipher_string or 'DHE_' in cipher_string
  result['ssl_ok'] = 1
  return result

def ssl_protocols(host, module, result, ciphers, current_protocol):
  if module.attrib['isProtocolSupported'] == "True":
    result['protocol_num'] += 1
    result['%s_available' % current_protocol] = True
  else:
    result['%s_available' % current_protocol] = False
  for child in module:
    if child.tag == 'errors':
      pass
    elif child.tag == 'rejectedCipherSuites':
      pass
    elif child.tag == 'acceptedCipherSuites':
      result['%s_cipher_suites_accepted' % current_protocol] = []
      for cipher_suite in child:
        result['%s_cipher_suites_accepted' % current_protocol].append(cipher_suite.attrib['name'])
        if len(cipher_suite) and ('DHE_' == cipher_suite.attrib['name'][0:4] or 'TLS_DHE_' == cipher_suite.attrib['name'][0:8] or 'EXP_EDH_' in cipher_suite.attrib['name'] or 'EDH-' == cipher_suite.attrib['name'][0:4]):
          if cipher_suite[0].tag == 'keyExchange':
            if 'dhe_key' in result:
              if int(cipher_suite[0].attrib['GroupSize']) < result['dhe_key']:
                result['dhe_key'] = int(cipher_suite[0].attrib['GroupSize'])
            else:
              result['dhe_key'] = int(cipher_suite[0].attrib['GroupSize'])
          else:
            print "Unknown data in cipherSuite %s" % etree.tostring(cipher_suite)
        elif len(cipher_suite) and 'ECDHE_' in cipher_suite.attrib['name']:
          if cipher_suite[0].tag == 'keyExchange':
            if 'ecdhe_key' in result:
              if int(cipher_suite[0].attrib['GroupSize']) < result['ecdhe_key']:
                result['ecdhe_key'] = int(cipher_suite[0].attrib['GroupSize'])
            else:
              result['ecdhe_key'] = int(cipher_suite[0].attrib['GroupSize'])
          else:
            print "%s: Unknown data in cipherSuite %s" % (host, etree.tostring(cipher_suite))
        elif len(cipher_suite):
          print "%s: Unknown data in cipherSuite %s" % (host, etree.tostring(cipher_suite))
      ciphers += result['%s_cipher_suites_accepted' % current_protocol]
    elif child.tag == 'preferredCipherSuite':
      result['%s_cipher_suites_preferred' % current_protocol] = []
      for cipher_suite in child:
        result['%s_cipher_suites_preferred' % current_protocol].append(cipher_suite.attrib['name'])
  return (result, ciphers)

def check_port_443_available(host):
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    s.connect((host, 443))
    s.close()
    return True
  except:
    return False

""" TODO: really ugly ciphers
EDH-RSA-DES-CBC-SHA     SSLv3 Kx=DH       Au=RSA  Enc=DES(56)   Mac=SHA1
EDH-DSS-DES-CBC-SHA     SSLv3 Kx=DH       Au=DSS  Enc=DES(56)   Mac=SHA1
DES-CBC-SHA             SSLv3 Kx=RSA      Au=RSA  Enc=DES(56)   Mac=SHA1
EXP-EDH-RSA-DES-CBC-SHA SSLv3 Kx=DH(512)  Au=RSA  Enc=DES(40)   Mac=SHA1 export
EXP-EDH-DSS-DES-CBC-SHA SSLv3 Kx=DH(512)  Au=DSS  Enc=DES(40)   Mac=SHA1 export
EXP-DES-CBC-SHA         SSLv3 Kx=RSA(512) Au=RSA  Enc=DES(40)   Mac=SHA1 export
EXP-RC2-CBC-MD5         SSLv3 Kx=RSA(512) Au=RSA  Enc=RC2(40)   Mac=MD5  export
EXP-RC4-MD5             SSLv3 Kx=RSA(512) Au=RSA  Enc=RC4(40)   Mac=MD5  export
"""

def update_site_checks():
  hosts = Host.query.filter_by(active=1).all()
  for host in hosts:
    update_site_check(host.id)

def update_host_check(host_id):
  host = Host.query.filter_by(id=host_id).first()

  # Check URL
  result = {}
  result['port_443_available'] = check_port_443_available(host.host)

  test_result = SslTest()
  test_result.created = datetime.datetime.now()
  test_result.host_id = host_id
  test_result.host = host.host
  test_result.ip = host.ip
  
  # 1 = nicht existent, 2 = rot, 3 = gelb, 4 = grün, 5 = grünplus
  summary = 1
  
  # if yes: check ssl avaiable
  if result['port_443_available']:
    test_result.port_443_available = result['port_443_available']
    result.update(get_sslyze(host.host))
    if 'ssl_ok' in result:
      test_result.ssl_ok = result['ssl_ok']
      if test_result.ssl_ok:
        if 'cert_matches' in result:
          test_result.cert_matches = result['cert_matches']
          if test_result.cert_matches:
            summary = 5
            if 'rc4_available' in result:
              test_result.rc4_available = result['rc4_available']
              if test_result.rc4_available and summary > 2:
                summary = 2
            if 'md5_available' in result:
              test_result.md5_available = result['md5_available']
              if test_result.md5_available and summary > 2:
                summary = 2
            if 'dhe_key' in result:
              test_result.dhe_key = result['dhe_key']
              if test_result.dhe_key < 2048 and summary > 4:
                summary = 4
              if test_result.dhe_key < 1024 and summary > 2:
                summary = 2
            if 'ecdhe_key' in result:
              test_result.ecdhe_key = result['ecdhe_key']
              if test_result.ecdhe_key < 256 and summary > 4:
                summary = 4
            if 'fallback_scsv_available' in result:
              test_result.fallback_scsv_available = result['fallback_scsv_available']
              if not test_result.fallback_scsv_available and summary > 4:
                summary = 4
            if 'protocol_num' in result:
              test_result.protocol_num = result['protocol_num']
            if 'protocol_best' in result:
              test_result.protocol_best = result['protocol_best']
              if (test_result.protocol_best == 'tlsv1_1' or test_result.protocol_best == 'tlsv1') and summary > 3:
                summary = 3
            if 'hsts_available' in result:
              test_result.hsts_available = result['hsts_available']
              if not test_result.hsts_available and summary > 4:
                summary = 4
            if 'session_renegotiation_secure' in result:
              test_result.session_renegotiation_secure = result['session_renegotiation_secure']
              if not test_result.session_renegotiation_secure and summary > 2:
                summary = 2
            if 'session_renegotiation_client' in result:
              test_result.session_renegotiation_client = result['session_renegotiation_client']
            if 'heartbleed' in result:
              test_result.heartbleed = result['heartbleed']
              if test_result.heartbleed and summary > 2:
                summary = 2
            if 'sha1_cert' in result:
              test_result.sha1_cert = result['sha1_cert']
              if test_result.sha1_cert and summary > 3:
                summary = 3
            if 'ocsp_stapling' in result:
              test_result.ocsp_stapling = result['ocsp_stapling']
            if 'pfs_available' in result:
              test_result.pfs_available = result['pfs_available']
              if not test_result.pfs_available and summary > 3:
                summary = 3
            
            if 'sslv2_available' in result:
              test_result.sslv2_available = result['sslv2_available']
              if test_result.sslv2_available and summary > 2:
                summary = 2
            if 'sslv3_available' in result:
              test_result.sslv3_available = result['sslv3_available']
              if test_result.sslv3_available and summary > 2:
                summary = 2
            if 'tlsv1_available' in result:
              test_result.tlsv1_available = result['tlsv1_available']
            if 'tlsv1_1_available' in result:
              test_result.tlsv1_1_available = result['tlsv1_1_available']
            if 'tlsv1_2_available' in result:
              test_result.tlsv1_2_available = result['tlsv1_2_available']
            
            if 'sslv2_cipher_suites_accepted' in result:
              test_result.sslv2_cipher_suites_accepted = ', '.join(result['sslv2_cipher_suites_accepted'])
            if 'sslv3_cipher_suites_accepted' in result:
              test_result.sslv3_cipher_suites_accepted = ', '.join(result['sslv3_cipher_suites_accepted'])
            if 'tlsv1_cipher_suites_accepted' in result:
              test_result.tlsv1_cipher_suites_accepted = ', '.join(result['tlsv1_cipher_suites_accepted'])
            if 'tlsv1_1_cipher_suites_accepted' in result:
              test_result.tlsv1_1_cipher_suites_accepted = ', '.join(result['tlsv1_1_cipher_suites_accepted'])
            if 'tlsv1_2_cipher_suites_accepted' in result:
              test_result.tlsv1_2_cipher_suites_accepted = ', '.join(result['tlsv1_2_cipher_suites_accepted'])
            
            if 'sslv2_cipher_suites_preferred' in result:
              test_result.sslv2_cipher_suites_preferred = ', '.join(result['sslv2_cipher_suites_preferred'])
            if 'sslv3_cipher_suites_preferred' in result:
              test_result.sslv3_cipher_suites_preferred = ', '.join(result['sslv3_cipher_suites_preferred'])
            if 'tlsv1_cipher_suites_preferred' in result:
              test_result.tlsv1_cipher_suites_preferred = ', '.join(result['tlsv1_cipher_suites_preferred'])
            if 'tlsv1_1_cipher_suites_preferred' in result:
              test_result.tlsv1_1_cipher_suites_preferred = ', '.join(result['tlsv1_1_cipher_suites_preferred'])
            if 'tlsv1_2_cipher_suites_preferred' in result:
              test_result.tlsv1_2_cipher_suites_preferred = ', '.join(result['tlsv1_2_cipher_suites_preferred'])

  host.ssl_result = summary
  
  db.session.add(test_result)
  db.session.add(host)
  db.session.commit()
  return result
  
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
    else:
      service_site = service_site.first()
    service_site.updated = datetime.datetime.now()
    service_site.url = item['website']['value']
    
    # get / set host
    service_site.host = save_host(get_host(service_site.url), region)
    
    # save service_site
    db.session.add(service_site)
    db.session.commit()


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
    20: 9, # Hunde-Anmeldung
    22: 10, # Vergabe-Plattform
    24: 11, # Termin-Buchung
    26: 21, # Fundbüro
    28: 12, # Kita-Anmeldung
    36: 13, # Verwaltungs-App
    40: 14, # Wahldaten
    62: 15, # Statistiken
    64: 16, # OpenData-Portal
    68: 17, # Anliegen-Management
    78: 18, # Facebook
    80: 19, # Twitter
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
                service_site.host = save_host(get_host(service_site.url), region)
              print "add url %s at RGS %s field %s as %s" % (item[key + 1], item[2], key, service_site.quality)
              db.session.add(service_site)
              db.session.commit()
            else:
              print "malformed url %s at RGS %s field %s" % (item[key + 1], item[2], key)


def save_host(hostname, region):
  host = Host.query.filter_by(host=hostname)
  if host.count() == 0:
    host = Host()
    host.created = datetime.datetime.now()
    host.updated = datetime.datetime.now()
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
    host.regions.append(region)
    db.session.add(host)
    db.session.commit()
  return host


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
  


def import_osm():
  "http://overpass-api.de/api/interpreter?data=[out:json];(rel(62644);>;);out;"
  pass

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
