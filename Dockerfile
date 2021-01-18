FROM python:3.9

COPY app.py requirements.txt ./
COPY static static
COPY templates templates

RUN pip install -r requirements.txt

EXPOSE 5000

ENV FLASK_APP app.py

CMD python -m flask run