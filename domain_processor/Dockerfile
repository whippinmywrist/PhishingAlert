FROM python:3.10-rc-alpine

RUN apk add zeromq-dev linux-headers g++ libffi-dev musl-dev openssl-dev cargo bind-tools

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY core.py main.py modules.py ml_client.py ./

COPY dictionaries dictionaries

EXPOSE 43001

ENV PRODUCTION=1

ENTRYPOINT python -u main.py