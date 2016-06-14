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


def get_visualisation(identifier):
  visualisation = Visualisation.query.filter_by(identifier=identifier)
  if visualisation.count():
    visualisation = visualisation.first()
  else:
    visualisation = Visualisation()
    visualisation.created = datetime.datetime.now()
    visualisation.active = 1
    visualisation.identifier = identifier
  visualisation.updated = datetime.datetime.now()
  return visualisation


def generate_visualisations():
  ##############################
  ### eGovernment-Service-Count ###
  ##############################
  visualisation = Visualisation.query.filter_by(identifier='egovernment_service_count')
  if visualisation.count():
    visualisation = visualisation.first()
  else:
    visualisation = Visualisation()
    visualisation.created = datetime.datetime.now()
    visualisation.active = 1
    visualisation.identifier = 'egovernment_service_count'
  visualisation.updated = datetime.datetime.now()
  service_list = []
  services = Service.query.filter_by(active=1).filter_by(service_group_id=2).order_by(Service.name).all()
  for service in services:
    service_list.append(service.id)
  
  result_raw = []
  for i in range(0, 100):
    result_raw.append(0)
    
  hosts = Host.query.filter_by(active=1).all()
  for host in hosts:
    service_count = ServiceSite.query.filter_by(quality_show=1).filter_by(host_id=host.id).filter(ServiceSite.service_id.in_(service_list)).count()
    result_raw[service_count] += 1
  
  while result_raw[-1] == 0:
    result_raw.pop()
  del result_raw[0]
  descr = []
  for i in range(1, len(result_raw)):
    descr.append(i)
  
  result_data = {
    'labels': descr,
    'datasets': [
      {
        'data': result_raw
      }
    ]
  }
  visualisation.data = json.dumps(result_data)
  db.session.add(visualisation)
  db.session.commit()
  
  ##############################
  ### Ratsinformationssystem ###
  ##############################
  visualisation = Visualisation.query.filter_by(identifier='ris_available')
  if visualisation.count():
    visualisation = visualisation.first()
  else:
    visualisation = Visualisation()
    visualisation.created = datetime.datetime.now()
    visualisation.active = 1
    visualisation.identifier = 'ris_available'
  visualisation.updated = datetime.datetime.now()
  service_sites = ServiceSite.query.filter_by(active=1).filter_by(service_id=2).filter(ServiceSite.quality_show!=None).filter_by().all()
  result_raw = {
    1: 0,
    2: 0
  }
  for service_site in service_sites:
    result_raw[2 if service_site.quality_show else 1] += 1
  result_data = {
    'labels': [
      u'Kein Ratsinformationssystem',
      u'Ratsinformationssystem Online'
    ],
    'datasets': [
      {
        'data': [
          result_raw[1],
          result_raw[2]
        ],
        'backgroundColor': [
          '#d9534f',
          '#5cb85c'
        ]
      }
    ]
  }
  visualisation.data = json.dumps(result_data)
  db.session.add(visualisation)
  db.session.commit()
  
  ##############################
  ### Data-Service-Count ###
  ##############################
  visualisation = get_visualisation('data_service_count')
  service_list = []
  services = Service.query.filter_by(active=1).filter_by(service_group_id=3).order_by(Service.name).all()
  for service in services:
    service_list.append(service.id)
  
  result_raw = []
  for i in range(0, 30):
    result_raw.append(0)
    
  hosts = Host.query.filter_by(active=1).all()
  for host in hosts:
    service_count = ServiceSite.query.filter_by(quality_show=1).filter_by(host_id=host.id).filter(ServiceSite.service_id.in_(service_list)).count()
    result_raw[service_count] += 1
  
  while result_raw[-1] == 0:
    result_raw.pop()
  del result_raw[0]
  descr = []
  for i in range(1, len(result_raw)):
    descr.append(i)
  
  result_data = {
    'labels': descr,
    'datasets': [
      {
        'data': result_raw
      }
    ]
  }
  visualisation.data = json.dumps(result_data)
  db.session.add(visualisation)
  db.session.commit()
  
  ########################
  ### Encryption Total ###
  ########################
  visualisation = get_visualisation('encryption_yes_no')
  result_raw = [0, 0]
  visualisation_website = get_visualisation('encryption_yes_no_website')
  result_raw_website = [0, 0]
  
  visualisation_type = {}
  visualisation_type_deref = {
    1: 'web',
    2: 'mail'
  }
  
  visualisation_type = {}
  visualisation_region = {}
  visualisation_type_region = {}
  visualisation_website_region = {}
  result_raw_type = {}
  result_raw_region = {}
  result_raw_type_region = {}
  result_raw_website_region = {}
  
  for i in range(1, 17):
    visualisation_region[i] = get_visualisation('encryption_yes_no_%s' % i)
    result_raw_region[i] = [0, 0]
    visualisation_website_region[i] = get_visualisation('encryption_yes_no_website_%s' % i)
    result_raw_website_region[i] = [0, 0]
  
  for i in range (1, 3):
    visualisation_type[i] = get_visualisation('encryption_yes_no_%s' % visualisation_type_deref[i])
    result_raw_type[i] = [0, 0]
    visualisation_type_region[i] = {}
    result_raw_type_region[i] = {}
    for j in range(1, 17):
      visualisation_type_region[i][j] = get_visualisation('encryption_yes_no_%s_%s' % (visualisation_type_deref[i], j))
      result_raw_type_region[i][j] = [0, 0]
  
  hosts = Host.query.filter(Host.ssl_result >= 1).filter(Host.host != 'twitter.com').filter(Host.host != 'www.facebook.com').all()
  for host in hosts:
    for region in host.regions:
      # Count host multible times
      result_raw[1 if host.ssl_result > 1 else 0] += 1
      result_raw_type[int(host.type)][1 if host.ssl_result > 1 else 0] += 1
      # Region related
      result_raw_region[int(region.rgs[0:2])][1 if host.ssl_result > 1 else 0] += 1
      result_raw_type_region[int(host.type)][int(region.rgs[0:2])][1 if host.ssl_result > 1 else 0] += 1
    for service_site in host.service_sites:
      if service_site.service_id == 1:
        result_raw_website[1 if host.ssl_result > 1 else 0] += 1
        result_raw_website_region[int(region.rgs[0:2])][1 if host.ssl_result > 1 else 0] += 1
  
  visualisation.data = json.dumps(result_raw)
  db.session.add(visualisation)
  db.session.commit()
  visualisation_website.data = json.dumps(result_raw_website)
  db.session.add(visualisation_website)
  db.session.commit()
  
  for i in range(1, 17):
    visualisation_region[i].data = json.dumps(result_raw_region[i])
    db.session.add(visualisation_region[i])
    db.session.commit()
    visualisation_website_region[i].data = json.dumps(result_raw_website_region[i])
    db.session.add(visualisation_website_region[i])
    db.session.commit()
  
  for i in range(1, 3):
    visualisation_type[i].data = json.dumps(result_raw_type[i])
    db.session.add(visualisation_type[i])
    db.session.commit()
    for j in range(1, 17):
      visualisation_region[i].data = json.dumps(result_raw_region[i])
      db.session.add(visualisation_region[i])
      db.session.commit()
      visualisation_type_region[i][j].data = json.dumps(result_raw_type_region[i][j])
      db.session.add(visualisation_type_region[i][j])
      db.session.commit()
  
  
  
  ##########################
  ### Encryption Quality ###
  ##########################
  visualisation = get_visualisation('encryption_quality')
  visualisation_website = get_visualisation('encryption_quality_website')
  result_raw = [0, 0, 0, 0, 0]
  result_raw_website = [0, 0, 0, 0, 0]
  
  visualisation_type = {}
  visualisation_type_deref = {
    1: 'web',
    2: 'mail'
  }
  
  visualisation_type = {}
  visualisation_region = {}
  visualisation_type_region = {}
  visualisation_website_region = {}
  result_raw_type = {}
  result_raw_region = {}
  result_raw_type_region = {}
  result_raw_website_region = {}
  
  for i in range(1, 17):
    visualisation_region[i] = get_visualisation('encryption_quality_%s' % i)
    result_raw_region[i] = [0, 0, 0, 0, 0]
    visualisation_website_region[i] = get_visualisation('encryption_quality_website_%s' % i)
    result_raw_website_region[i] = [0, 0, 0, 0, 0]
  
  for i in range (1, 3):
    visualisation_type[i] = get_visualisation('encryption_quality_%s' % visualisation_type_deref[i])
    result_raw_type[i] = [0, 0, 0, 0, 0]
    visualisation_type_region[i] = {}
    result_raw_type_region[i] = {}
    for j in range(1, 17):
      visualisation_type_region[i][j] = get_visualisation('encryption_quality_%s_%s' % (visualisation_type_deref[i], j))
      result_raw_type_region[i][j] = [0, 0, 0, 0, 0]
  
  hosts = Host.query.filter(Host.ssl_result >= 2).filter(Host.host != 'twitter.com').filter(Host.host != 'www.facebook.com').all()
  for host in hosts:
    for region in host.regions:
      # Count host multible times
      result_raw[host.ssl_result - 2] += 1
      result_raw_type[int(host.type)][host.ssl_result - 2] += 1
      # Region related
      result_raw_region[int(region.rgs[0:2])][host.ssl_result - 2] += 1
      result_raw_type_region[int(host.type)][int(region.rgs[0:2])][host.ssl_result - 2] += 1
    for service_site in host.service_sites:
      if service_site.service_id == 1:
        result_raw_website[host.ssl_result - 2] += 1
        result_raw_website_region[int(region.rgs[0:2])][host.ssl_result - 2] += 1
    
  
  visualisation.data = json.dumps(result_raw)
  db.session.add(visualisation)
  db.session.commit()
  visualisation_website.data = json.dumps(result_raw_website)
  db.session.add(visualisation_website)
  db.session.commit()
  
  for i in range(1, 17):
    visualisation_region[i].data = json.dumps(result_raw_region[i])
    db.session.add(visualisation_region[i])
    db.session.commit()
    visualisation_website_region[i].data = json.dumps(result_raw_website_region[i])
    db.session.add(visualisation_website_region[i])
    db.session.commit()
  
  for i in range(1, 3):
    visualisation_type[i].data = json.dumps(result_raw_type[i])
    db.session.add(visualisation_type[i])
    db.session.commit()
    for j in range(1, 17):
      visualisation_type_region[i][j].data = json.dumps(result_raw_type_region[i][j])
      db.session.add(visualisation_type_region[i][j])
      db.session.commit()
  