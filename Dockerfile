FROM python:3.10-rc-alpine

COPY app/home/routes.py requirements.txt ./
COPY app/home/static static
COPY app/home/templates templates

RUN pip install -r requirements.txt

ENV FLASK_APP run.py

EXPOSE 5000

ENTRYPOINT flask run -h 0.0.0.0