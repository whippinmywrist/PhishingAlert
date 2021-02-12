FROM python:3.10-rc-alpine

RUN apk add zeromq-dev linux-headers g++
COPY requirements.txt ./

RUN pip install -r requirements.txt

COPY requirements.txt run.py config.py ./
COPY app app

ENV FLASK_APP=run.py
EXPOSE 5000

ENTRYPOINT python -u run.py