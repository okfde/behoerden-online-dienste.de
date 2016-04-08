# encoding: utf-8

from sqlalchemy.ext.declarative import declarative_base
from webapp import db
from flask.ext.security import UserMixin, RoleMixin

Base = declarative_base()

roles_users = db.Table('roles_users',
  db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
  db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class User(db.Model, UserMixin):
  __tablename__ = 'user'

  id = db.Column(db.Integer, primary_key=True)
  sex = db.Column(db.Integer())
  firstname = db.Column(db.String(255))
  lastname = db.Column(db.String(255))
  
  email = db.Column(db.String(255))
  
  roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))


class Role(db.Model, RoleMixin):
  __tablename__ = 'role'

  id = db.Column(db.Integer(), primary_key=True)
  name = db.Column(db.String(120), unique=True)
  description = db.Column(db.String(255))
  
  def __repr__(self):
    return '<Role %r>' % self.name



hosts_regions = db.Table('hosts_regions',
  db.Column('host_id', db.Integer(), db.ForeignKey('host.id')),
  db.Column('region_id', db.Integer(), db.ForeignKey('region.id')))


class Region(db.Model):
  __tablename__ = 'region'
  
  id = db.Column(db.Integer(), primary_key=True)
  name = db.Column(db.String(255))
  slug = db.Column(db.String(255), unique=True)
  created = db.Column(db.DateTime())
  updated = db.Column(db.DateTime())
  active = db.Column(db.Integer())
  
  osm_id = db.Column(db.Integer())
  geo_json = db.Column(db.Text())
  rgs = db.Column(db.String(255))
  region_level = db.Column(db.Integer())
  postalcode = db.Column(db.String(255))
  
  lat = db.Column(db.Numeric(precision=10,scale=7))
  lon = db.Column(db.Numeric(precision=10,scale=7))
  
  region_parent_id = db.Column(db.Integer, db.ForeignKey('region.id'))
  region_parent = db.relationship("Region", backref="region_children", remote_side=[id])
  service_sites = db.relationship("ServiceSite", backref="region", lazy='dynamic')
  # hosts as defined in Host
  
  def __init__(self):
    pass

  def __repr__(self):
    return '<Hoster %r>' % self.name
  

class ServiceGroup(db.Model):
  __tablename__ = 'service_group'
  id = db.Column(db.Integer(), primary_key=True)
  
  created = db.Column(db.DateTime())
  updated = db.Column(db.DateTime())
  active = db.Column(db.Integer())
  
  name = db.Column(db.Text())
  
  services = db.relationship("Service", backref="ServiceGroup", lazy='dynamic')
  
  def __init__(self):
    pass

  def __repr__(self):
    return '<ServiceGroup %r>' % self.name

  
class Service(db.Model):
  __tablename__ = 'service'
  id = db.Column(db.Integer(), primary_key=True)
  
  created = db.Column(db.DateTime())
  updated = db.Column(db.DateTime())
  active = db.Column(db.Integer())
  
  name = db.Column(db.Text())
  fa_icon = db.Column(db.String(64))
  descr_short = db.Column(db.Text())
  descr = db.Column(db.Text())
  make_ssl_test = db.Column(db.Integer())
  
  service_group_id = db.Column(db.Integer, db.ForeignKey('service_group.id'))
  service_sites = db.relationship("ServiceSite", backref="Service", lazy='dynamic')
  
  def __init__(self):
    pass

  def __repr__(self):
    return '<Service %r>' % self.name


class ServiceSite(db.Model):
  __tablename__ = 'service_site'
  
  id = db.Column(db.Integer(), primary_key=True)
  created = db.Column(db.DateTime())
  updated = db.Column(db.DateTime())
  active = db.Column(db.Integer())
  
  url = db.Column(db.Text())
  quality = db.Column(db.String(255)) # 'offline', 'mail', 'online'
  quality_show = db.Column(db.Integer())
  
  host_id = db.Column(db.Integer, db.ForeignKey('host.id'))
  region_id = db.Column(db.Integer, db.ForeignKey('region.id'))
  service_id = db.Column(db.Integer, db.ForeignKey('service.id'))
  
  def __init__(self):
    pass

  def __repr__(self):
    return '<ServiceSite %r>' % self.name
  

class Host(db.Model):
  __tablename__ = 'host'
  
  id = db.Column(db.Integer(), primary_key=True)
  created = db.Column(db.DateTime())
  updated = db.Column(db.DateTime())
  active = db.Column(db.Integer())
  
  host = db.Column(db.String(255))
  type = db.Column(db.String(255))
  ip = db.Column(db.Text())
  reverse_hostname = db.Column(db.Text())
  ssl_result = db.Column(db.Integer())
  
  service_sites = db.relationship("ServiceSite", backref="host", lazy='dynamic')
  ssl_tests = db.relationship("SslTest", backref="Host", lazy='dynamic')
  regions = db.relationship('Region', secondary=hosts_regions, backref=db.backref('hosts', lazy='dynamic'))
  
  def __init__(self):
    pass

  def __repr__(self):
    return '<Host %r>' % self.host

class SslTest(db.Model):
  __tablename__ = 'ssl_test'
  
  id = db.Column(db.Integer(), primary_key=True)
  created = db.Column(db.DateTime())
  
  host = db.Column(db.Text())
  ip = db.Column(db.Text())
  
  port_443_available = db.Column(db.Integer())
  ssl_ok = db.Column(db.Integer())
  cert_matches = db.Column(db.Integer())
  
  rc4_available = db.Column(db.Integer())
  md5_available = db.Column(db.Integer())
  anon_suite_available = db.Column(db.Integer())
  dhe_key = db.Column(db.Integer())
  ecdhe_key = db.Column(db.Integer())
  pfs_available = db.Column(db.Integer())
  fallback_scsv_available = db.Column(db.Integer())
  protocol_num = db.Column(db.Integer())
  protocol_best = db.Column(db.String(255))
  
  sslv2_available = db.Column(db.Integer())
  sslv3_available = db.Column(db.Integer())
  tlsv1_available = db.Column(db.Integer())
  tlsv1_1_available = db.Column(db.Integer())
  tlsv1_2_available = db.Column(db.Integer())
  
  sslv2_cipher_suites_accepted = db.Column(db.Text())
  sslv3_cipher_suites_accepted = db.Column(db.Text())
  tlsv1_cipher_suites_accepted = db.Column(db.Text())
  tlsv1_1_cipher_suites_accepted = db.Column(db.Text())
  tlsv1_2_cipher_suites_accepted = db.Column(db.Text())
  
  sslv2_cipher_suites_preferred = db.Column(db.String(255))
  sslv3_cipher_suites_preferred = db.Column(db.String(255))
  tlsv1_cipher_suites_preferred = db.Column(db.String(255))
  tlsv1_1_cipher_suites_preferred = db.Column(db.String(255))
  tlsv1_2_cipher_suites_preferred = db.Column(db.String(255))
  
  hsts_available = db.Column(db.Integer())
  session_renegotiation_secure = db.Column(db.Integer())
  session_renegotiation_client = db.Column(db.Integer())
  heartbleed = db.Column(db.Integer())
  ccs_injection = db.Column(db.Integer())
  sha1_cert = db.Column(db.Integer())
  ocsp_stapling = db.Column(db.Integer())
  ssl_forward = db.Column(db.Integer())
  
  host_id = db.Column(db.Integer, db.ForeignKey('host.id'))


class Suggestion(db.Model):
  __tablename__ = 'suggestion'
  id = db.Column(db.Integer(), primary_key=True)
  created = db.Column(db.DateTime())
  updated = db.Column(db.DateTime())
  type = db.Column(db.String(128))
  suggestion = db.Column(db.Text())

class Visualisation(db.Model):
  __tablename__ = 'visualisation'
  id = db.Column(db.Integer(), primary_key=True)
  
  created = db.Column(db.DateTime())
  updated = db.Column(db.DateTime())
  active = db.Column(db.Integer())
  
  name = db.Column(db.Text())
  identifier = db.Column(db.String(128), unique=True)
  descr = db.Column(db.Text())
  data = db.Column(db.Text())
