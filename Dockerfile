FROM python:3.12-alpine

ENV FLASK_APP=flasky.py
ENV FLASK_CONFIG=docker

RUN adduser -D flasky
USER flasky

WORKDIR /home/flasky

COPY requirements requirements
RUN python -m venv venv
RUN venv/bin/pip install -r requirements/docker.txt

COPY app app
COPY migrations migrations
COPY flasky.py config.py boot.sh ./

EXPOSE 5000
ENTRYPOINT [ "./boot.sh" ]