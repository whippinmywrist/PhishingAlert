FROM python:3.10-rc-alpine

COPY app.py requirements.txt ./
COPY static static
COPY templates templates

RUN pip install -r requirements.txt

ENV FLASK_APP app.py

EXPOSE 5000

ENTRYPOINT flask run -h 0.0.0.0