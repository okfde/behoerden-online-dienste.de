# encoding: utf-8

from flask.ext.wtf import Form
from wtforms import validators
from models import *
from wtforms import SubmitField, TextField, SelectField, FileField, TextAreaField, HiddenField, BooleanField
from wtforms.widgets import FileInput
from webapp import app, db
import util

class SiteSslCheck(Form):
  website = TextField(
    label='Ihre Website',
    validators=[
      validators.Required(message=u'Um Ihre Seite zu testen, müssen Sie diese schon angeben.')
    ],
    description=u'Bitte geben Sie die zu testende Seite an. Ihre Seite wird nicht veröffentlicht.')
  region = SelectField(
    label=u'Zugehörige Region (Stadt, Kreis, ...)',
    choices=[],
    coerce=int,
    validators = [],
    description='Bitte geben Sie die zugehörige Region an.')
  service_description = TextField(
    label=u'Bezeichnung des Services',
    description=u'Bitte geben Sie wenn möglich die Funktion der Website an (Hauptseite, Ratsinformationssystem, ...).')
  legal = BooleanField(
    label=u'Hiermit bestätige ich, dass ich diesen Webservice nicht zum Angriff auf Websites, Server oder andere IT-Infrastuktur <a href="https://de.wikipedia.org/wiki/Vorbereiten_des_Aussp%C3%A4hens_und_Abfangens_von_Daten">im Sinne von § 202c StGB</a> nutzen werde.'
  )
  submit = SubmitField(
    label=u'Verschlüsselung testen')

