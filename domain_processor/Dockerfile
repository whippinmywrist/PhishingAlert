FROM python:3.10-rc-alpine

RUN apk add zeromq-dev linux-headers g++ libffi-dev musl-dev openssl-dev cargo

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY core.py main.py modules.py ./

EXPOSE 43001

ENV PYTHONUNBUFFERED=1

ENTRYPOINT python -u main.py