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

import dns.resolver
from sslyze.plugins_finder import PluginsFinder
from sslyze.plugins_process_pool import PluginsProcessPool
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.ssl_settings import TlsWrappedProtocolEnum
import sslyze.plugins.plugin_base


def get_sslyze(host, host_type):
  result = {
    'ssl_ok': 1
  }
  try:
    if host_type == '1':
      server_connection = ServerConnectivityInfo(hostname = host,
                                                 port = 443,
                                                 tls_server_name_indication = host)
    elif host_type == '2':
      server_connection = ServerConnectivityInfo(hostname = host,
                                                 port = 25,
                                                 tls_server_name_indication = host,
                                                 tls_wrapped_protocol = TlsWrappedProtocolEnum.STARTTLS_SMTP)
    server_connection.test_connectivity_to_server()
  except ServerConnectivityError:
    return {'ssl_ok': 0}
  
  sslyze_plugins = PluginsFinder()
  plugins_process_pool = PluginsProcessPool(sslyze_plugins)

  plugins_process_pool.queue_plugin_task(server_connection, 'sslv2')
  plugins_process_pool.queue_plugin_task(server_connection, 'sslv3')
  plugins_process_pool.queue_plugin_task(server_connection, 'tlsv1')
  plugins_process_pool.queue_plugin_task(server_connection, 'tlsv1_1')
  plugins_process_pool.queue_plugin_task(server_connection, 'tlsv1_2')
  plugins_process_pool.queue_plugin_task(server_connection, 'reneg')
  plugins_process_pool.queue_plugin_task(server_connection, 'certinfo_basic')
  plugins_process_pool.queue_plugin_task(server_connection, 'compression')
  plugins_process_pool.queue_plugin_task(server_connection, 'heartbleed')
  plugins_process_pool.queue_plugin_task(server_connection, 'openssl_ccs')
  plugins_process_pool.queue_plugin_task(server_connection, 'fallback')
  if host_type == '1':
    plugins_process_pool.queue_plugin_task(server_connection, 'hsts')
  
  ciphers = []
  result['protocol_num'] = 0
  for plugin_result in plugins_process_pool.get_results():
    if isinstance(plugin_result, sslyze.plugins.plugin_base.PluginRaisedExceptionResult):
      #plugins_process_pool.emergency_shutdown()
      if len(plugin_result.as_text()) == 2:
        if 'errors' not in result:
          result['errors'] = []
        result['errors'].append("%s: %s" % (plugin_result.as_text()[0], plugin_result.as_text()[1]))
      else:
        print 'Scan command failed: {}'.format(plugin_result.as_text())
    elif plugin_result.plugin_command in ['sslv2', 'sslv3', 'tlsv1', 'tlsv1_1' ,'tlsv1_2']:
      result, ciphers = ssl_protocols(result, plugin_result, plugin_result.plugin_command, ciphers)
    elif plugin_result.plugin_command == 'reneg':
      result['session_renegotiation_client'] = plugin_result.accepts_client_renegotiation
      result['session_renegotiation_secure'] = plugin_result.supports_secure_renegotiation
    elif plugin_result.plugin_command == 'certinfo_basic':
      result['cert_matches'] = plugin_result.hostname_validation_result
      cns_in_certificate_chain = []
      has_sha1_signed_certificate = False
      for cert in plugin_result.certificate_chain:
        cert_identity = plugin_result._extract_subject_cn_or_oun(cert)
        cns_in_certificate_chain.append(cert_identity)
        if not plugin_result._is_root_certificate(cert) and "sha1" in cert.as_dict['signatureAlgorithm']:
          has_sha1_signed_certificate = True
      
      result['sha1_cert'] = has_sha1_signed_certificate
      # TODO: ocsp_stapling
    elif plugin_result.plugin_command == 'compression':
      result['compression'] = 1 if plugin_result.compression_name else 0
    elif plugin_result.plugin_command == 'heartbleed':
      result['heartbleed'] = plugin_result.is_vulnerable_to_heartbleed
    elif plugin_result.plugin_command == 'openssl_ccs':
      result['ccs_injection'] = plugin_result.is_vulnerable_to_ccs_injection
    elif plugin_result.plugin_command == 'fallback':
      result['fallback_scsv_available'] = plugin_result.supports_fallback_scsv
    elif plugin_result.plugin_command == 'hsts':
      result['hsts_available'] = 1 if plugin_result.hsts_header else 0
  if not result['ssl_ok']:
    return result
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
  if result['protocol_num'] == 1:
    result['fallback_scsv_available'] = 0
  result['rc4_available'] = 'RC4' in cipher_string
  result['md5_available'] = 'MD5' in cipher_string
  result['pfs_available'] = 'ECDHE_' in cipher_string or 'DHE_' in cipher_string
  result['anon_suite_available'] = 'anon_' in cipher_string
  return result

def ssl_protocols(result, plugin_result, current_protocol, ciphers):
  result['%s_cipher_accepted' % current_protocol] = []
  if plugin_result.preferred_cipher:
    result['%s_cipher_preferred' % current_protocol] = plugin_result.preferred_cipher.name
  for cipher in plugin_result.accepted_cipher_list:
    result['%s_cipher_accepted' % current_protocol].append(cipher.name)
    ciphers.append(cipher.name)
    if cipher.dh_info:
      if cipher.dh_info['Type'] == 'DH':
        if 'dhe_key' in cipher.dh_info:
          if cipher.dh_info['dhe_key'] > int(cipher.dh_info['GroupSize']):
            result['dhe_key'] = int(cipher.dh_info['GroupSize'])
        else:
          result['dhe_key'] = int(cipher.dh_info['GroupSize'])
      elif cipher.dh_info['Type'] == 'ECDH':
        if 'ecdhe_key' in cipher.dh_info:
          if cipher.dh_info['ecdhe_key'] > int(cipher.dh_info['GroupSize']):
            result['ecdhe_key'] = int(cipher.dh_info['GroupSize'])
        else:
          result['ecdhe_key'] = int(cipher.dh_info['GroupSize'])
  if len(result['%s_cipher_accepted' % current_protocol]):
    result['%s_available' % current_protocol] = 1
    result['protocol_num'] += 1
  else:
    result['%s_available' % current_protocol] = 0
    del result['%s_cipher_accepted' % current_protocol]
  return (result, ciphers)

def check_port_available(host, port):
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    s.connect((host, port))
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

def ssl_check(start_with=None):
  hosts = Host.query.filter_by(active=1)
  if start_with:
    hosts = hosts.filter(Host.id >= start_with)
  hosts = hosts.order_by(Host.id).all()
  for host in hosts:
    print "Check ID %s: %s" % (host.id, host.host)
    ssl_check_single(host.id)


def ssl_check_validate():
  hosts = Host.query.filter_by(active=1).filter_by(ssl_result=1).all()
  for host in hosts:
    ssl_test = SslTest.query.filter_by(host_id=host.id).order_by(desc(SslTest.created)).filter_by(type=1).first()
    if not ssl_test.port_443_available:
      if check_port_443_available(host.host):
        print "Updating %s" % host.host
        ssl_check_single(host.id)
    

def ssl_check_single(host_id):
  host = Host.query.filter_by(id=host_id).first()
  requests.packages.urllib3.disable_warnings()

  # Check URL
  result = {}
  result['port_available'] = False
  
  if host.type == '1':
    result['port_443_available'] = check_port_available(host.host, 443)
    result['port_available'] = result['port_443_available']
  elif host.type == '2':
    result['port_25_available'] = check_port_available(host.host, 25)
    result['port_available'] = result['port_25_available']

  test_result = SslTest()
  test_result.created = datetime.datetime.now()
  test_result.host_id = host_id
  test_result.host = host.host
  test_result.ip = host.ip
  
  # if yes: check ssl avaiable
  if result['port_available']:
    if 'port_443_available' in result:
      test_result.port_443_available = result['port_443_available']
    elif 'port_25_available' in result:
      test_result.port_25_available = result['port_25_available']
    result.update(get_sslyze(host.host, host.type))
    
    if 'errors' in result:
      print result['errors']
      test_result.errors = '; '.join(result['errors'])
    if 'ssl_ok' in result:
      test_result.ssl_ok = result['ssl_ok']
      if test_result.ssl_ok:
        if 'cert_matches' in result:
          test_result.cert_matches = result['cert_matches']
        if 'rc4_available' in result:
          test_result.rc4_available = result['rc4_available']
        if 'md5_available' in result:
          test_result.md5_available = result['md5_available']
        if 'anon_suite_available' in result:
          test_result.anon_suite_available = result['anon_suite_available']
        if 'dhe_key' in result:
          test_result.dhe_key = result['dhe_key']
        if 'ecdhe_key' in result:
          test_result.ecdhe_key = result['ecdhe_key']
        if 'fallback_scsv_available' in result:
          test_result.fallback_scsv_available = result['fallback_scsv_available']
        if 'protocol_num' in result:
          test_result.protocol_num = result['protocol_num']
        if 'protocol_best' in result:
          test_result.protocol_best = result['protocol_best']
        if 'hsts_available' in result:
          test_result.hsts_available = result['hsts_available']
        if 'session_renegotiation_secure' in result:
          test_result.session_renegotiation_secure = result['session_renegotiation_secure']
        if 'session_renegotiation_client' in result:
          test_result.session_renegotiation_client = result['session_renegotiation_client']
        if 'heartbleed' in result:
          test_result.heartbleed = result['heartbleed']
        if 'sha1_cert' in result:
          test_result.sha1_cert = result['sha1_cert']
        if 'ocsp_stapling' in result:
          test_result.ocsp_stapling = result['ocsp_stapling']
        if 'pfs_available' in result:
          test_result.pfs_available = result['pfs_available']
        if 'ccs_injection' in result:
          test_result.ccs_injection = result['ccs_injection']
        if 'compression' in result:
          test_result.compression = result['compression']
        
        if 'sslv2_available' in result:
          test_result.sslv2_available = result['sslv2_available']
        if 'sslv3_available' in result:
          test_result.sslv3_available = result['sslv3_available']
        if 'tlsv1_available' in result:
          test_result.tlsv1_available = result['tlsv1_available']
        if 'tlsv1_1_available' in result:
          test_result.tlsv1_1_available = result['tlsv1_1_available']
        if 'tlsv1_2_available' in result:
          test_result.tlsv1_2_available = result['tlsv1_2_available']
        
        if 'sslv2_cipher_accepted' in result:
          test_result.sslv2_cipher_accepted = ', '.join(result['sslv2_cipher_accepted'])
        if 'sslv3_cipher_accepted' in result:
          test_result.sslv3_cipher_accepted = ', '.join(result['sslv3_cipher_accepted'])
        if 'tlsv1_cipher_accepted' in result:
          test_result.tlsv1_cipher_accepted = ', '.join(result['tlsv1_cipher_accepted'])
        if 'tlsv1_1_cipher_accepted' in result:
          test_result.tlsv1_1_cipher_accepted = ', '.join(result['tlsv1_1_cipher_accepted'])
        if 'tlsv1_2_cipher_accepted' in result:
          test_result.tlsv1_2_cipher_accepted = ', '.join(result['tlsv1_2_cipher_accepted'])
        
        if 'sslv2_cipher_preferred' in result:
          test_result.sslv2_cipher_preferred = result['sslv2_cipher_preferred']
        if 'sslv3_cipher_preferred' in result:
          test_result.sslv3_cipher_preferred = result['sslv3_cipher_preferred']
        if 'tlsv1_cipher_preferred' in result:
          test_result.tlsv1_cipher_preferred = result['tlsv1_cipher_preferred']
        if 'tlsv1_1_cipher_preferred' in result:
          test_result.tlsv1_1_cipher_preferred = result['tlsv1_1_cipher_preferred']
        if 'tlsv1_2_cipher_preferred' in result:
          test_result.tlsv1_2_cipher_preferred = result['tlsv1_2_cipher_preferred']
        
        if 'port_443_available' in result and 'cert_matches' in result:
          # make request to check if there is an forward
          if result['cert_matches']:
            headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36' }
            try:
              request = requests.get('http://%s' % host.host, verify=False, timeout=30, headers=headers)
              if request.url[0:8] == 'https://':
                test_result.ssl_forward = 1
              else:
                test_result.ssl_forward = 0
            except (requests.exceptions.SSLError, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects):
              print "CRITICAL SSL ERROR"
  db.session.add(test_result)
  db.session.commit()
  ssl_check_summary_single(host.id)
  return result


def ssl_check_summary():
  hosts = Host.query.filter(Host.ssl_result > 1).filter_by(active=1).all()
  for host in hosts:
    ssl_check_summary_single(host.id)
  

def ssl_check_summary_single(host_id):
  host = Host.query.filter_by(id=host_id).first()
  ssl_test = SslTest.query.filter_by(host_id=host.id).order_by(desc(SslTest.created)).first()
  
  # 1 = nicht existent, 2 = rotminus, 3 = rot, 4 = gelb, 5 = grün, 6 = grünplus
  summary = 1
  if ssl_test.port_25_available and ssl_test.ssl_ok:
    summary = 3
  if (ssl_test.port_443_available or ssl_test.port_25_available) and ssl_test.ssl_ok and ssl_test.cert_matches:
    summary = 6
  if summary > 1:
    # bad ciphers
    if ssl_test.anon_suite_available and summary > 3:
      summary = 3
    if (ssl_test.protocol_best == 'tlsv1_1' or ssl_test.protocol_best == 'tlsv1') and summary > 4:
      summary = 4
    if ssl_test.sslv2_available and summary > 2:
      summary = 2
    if ssl_test.sslv3_available and ssl_test.fallback_scsv_available and summary > 4:
      summary = 4
    if ssl_test.sslv3_available and not ssl_test.fallback_scsv_available and summary > 3:
      summary = 3
    if ssl_test.rc4_available and summary > 4:
      summary = 4
    if ssl_test.md5_available and summary > 4:
      summary = 4
      
    # bad cipher, part 2
    for version in ['1', '1_1', '1_2']:
      if getattr(ssl_test, 'tlsv%s_cipher_accepted' % version):
        if getattr(ssl_test, 'tlsv%s_cipher_preferred' % version):
          if 'RC4' in getattr(ssl_test, 'tlsv%s_cipher_preferred' % version) and summary > 3:
            summary = 3
          if (not len(getattr(ssl_test, 'tlsv%s_cipher_preferred' % version)) and 'RC4' in getattr(ssl_test, 'tlsv%s_cipher_accepted' % version)) and summary > 3:
            summary = 3
        else:
          if 'RC4' in getattr(ssl_test, 'tlsv%s_cipher_accepted' % version) and summary > 3:
            summary = 3
    
    # bad pfs
    if not ssl_test.pfs_available and summary > 4:
      summary = 4
    if ssl_test.dhe_key:
      if ssl_test.dhe_key < 2048 and ssl_test.dhe_key != None and summary > 4:
        summary = 4
      if ssl_test.dhe_key < 1024 and summary > 3:
        summary = 3
    if ssl_test.ecdhe_key:
      if ssl_test.ecdhe_key < 256 and ssl_test.ecdhe_key != None and summary > 4:
        summary = 4
    
    #misc
    if not ssl_test.fallback_scsv_available and summary > 5:
      summary = 5
    if not ssl_test.hsts_available and summary > 5:
      summary = 5
    if not ssl_test.session_renegotiation_secure and summary > 3:
      summary = 3
    if ssl_test.heartbleed and summary > 2:
      summary = 2
    if ssl_test.sha1_cert and summary > 4:
      summary = 4
    if ssl_test.ssl_forward == 0 and summary > 4:
      summary = 4
    if ssl_test.export_cipher == 1 and summary > 2:
      summary = 2
  
  host.ssl_result = summary
  db.session.add(host)
  db.session.commit()


def update_export_cipher():
  ssl_tests = SslTest.query.all()
  for ssl_test in ssl_tests:
    export_cipher = 0
    if ssl_test.sslv2_cipher_accepted:
      if 'EXP' in ssl_test.sslv2_cipher_accepted:
        export_cipher = 1
    if ssl_test.sslv3_cipher_accepted:
      if 'EXP' in ssl_test.sslv3_cipher_accepted:
        export_cipher = 1
    if ssl_test.tlsv1_cipher_accepted:
      if 'EXP' in ssl_test.tlsv1_cipher_accepted:
        export_cipher = 1
    ssl_test.export_cipher = export_cipher
    db.session.add(ssl_test)
    db.session.commit()
  

