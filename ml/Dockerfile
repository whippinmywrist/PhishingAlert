FROM continuumio/miniconda3:4.9.2-alpine

COPY requirements.txt ./

RUN pip install -r requirements.txt

COPY main.py ./

EXPOSE 43000

ENV PRODUCTION=1

ENTRYPOINT python -u main.py