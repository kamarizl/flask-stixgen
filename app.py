from mySimpleStixGenerator import main

from flask import Flask, request, render_template, send_file
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired
from io import BytesIO


app = Flask('__name__')
app.config['SECRET_KEY']= 'secret'


class MyForm(FlaskForm):
    title = StringField('STIX Title', validators=[DataRequired()])
    desc = TextAreaField('Description')
    ip = TextAreaField('IP Addresses')
    hashes = TextAreaField('Hashes')
    fname = TextAreaField('Filenames')
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

        # convert str object to bytes object. it seem flask use StringIO only for real file
        data = BytesIO(result.encode())
        
        filename = iocs['title'].title().replace(" ","")
            
        # return render_template('info.html', form=form, result=result)
        return send_file(data, as_attachment=True, attachment_filename=filename+".xml")

    return render_template("info.html", form=form)

 
if __name__ == '__main__':
    app.run(host='0.0.0.0')