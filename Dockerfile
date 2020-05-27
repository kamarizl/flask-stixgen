FROM python:3.6-buster
COPY . /app
WORKDIR /app
RUN pip3 install -r requirements.txt
EXPOSE 5000
CMD [ "python3", "app.py" ]