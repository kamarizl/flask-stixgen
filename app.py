#!/bin/python3

from mySimpleStixGenerator import main
from flask import Flask, request, redirect, url_for, render_template
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired


SECRET_KEY = 'secret'

app = Flask('__name__')
app.config.from_object(__name__)


class MyForm(FlaskForm):
    ip = StringField('IP Address', validators=[DataRequired()])


@app.route('/', methods=['GET', 'POST'])
def home():
  form = MyForm()
  
  if form.validate_on_submit():
    ip = request.form['ip']
    result = main()
    return render_template('info.html', form=form, result=result)
  
  return render_template("info.html", form=form)

