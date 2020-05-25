#!/bin/python3

from mySimpleStixGenerator import main
from flask import Flask, request, redirect, url_for, render_template
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired


SECRET_KEY = 'secret'

app = Flask('__name__')
app.config.from_object(__name__)


class MyForm(FlaskForm):
    title = StringField('STIX Title', validators=[DataRequired()])
    desc = TextAreaField('Description')
    ip = TextAreaField('IP Address')
    hashes = TextAreaField('Hashes')
    fname = TextAreaField('Filename')
    urls = TextAreaField('URLs')
    subject = TextAreaField('Email Subject')


@app.route('/', methods=['GET', 'POST'])
def home():
    form = MyForm()

    if form.validate_on_submit():
       
        iocs = {
            'title': request.form['title'],
            'desc': request.form['desc'],
            'hash': request.form['hashes'].splitlines(),
            'ips': request.form['ip'].splitlines(),
            'fname': request.form['fname'].splitlines(),
            'urls': request.form['urls'].splitlines(),
            'subject': request.form['subject'].splitlines()
        }
        
        result = main(iocs=iocs)

        return render_template('info.html', form=form, result=result)

    return render_template("info.html", form=form)
