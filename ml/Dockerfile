FROM continuumio/miniconda3:4.9.2-alpine

COPY main.py requirements.txt ./


RUN pip install -r requirements.txt

EXPOSE 43000

ENV PRODUCTION=1

ENTRYPOINT python main.py