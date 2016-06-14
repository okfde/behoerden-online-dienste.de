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

