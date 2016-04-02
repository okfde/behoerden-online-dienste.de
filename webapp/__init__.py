# encoding: utf-8

from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.mail import Mail
from flask.ext.security import Security
from flask.ext.bootstrap import Bootstrap, WebCDN
from flask.ext.basicauth import BasicAuth
from flask.ext.cache import Cache
from flask.ext.elasticsearch import FlaskElasticsearch


app = Flask(__name__)
app.debug = True
app.config.from_pyfile('../config.py')

# Bootstrap
Bootstrap(app)
app.extensions['bootstrap']['cdns']['jquery'] = WebCDN(
  '/static/lib/jquery/1.11.3/'
)
app.extensions['bootstrap']['cdns']['bootstrap'] = WebCDN(
  '/static/lib/bootstrap/3.3.6/'
)

# Cache
cache = Cache(app, config={'CACHE_TYPE': 'memcached', 'CACHE_MEMCACHED_SERVERS': ['127.0.0.1:11211']})
cache.init_app(app)

# SimpleAuth
basic_auth = BasicAuth(app)

#Mail
mail = Mail(app)

db = SQLAlchemy(app)
es = FlaskElasticsearch(app)
from models import *
from forms import *

import webapp.views