FROM python:3-alpine

RUN apk update && apk add --no-cache nmap nmap-scripts

ADD vulscan /usr/share/nmap/scripts/vulscan

ADD code /opt/nuvlabox/

ADD code/patch/ /usr/share/nmap/scripts/vulscan

VOLUME /srv/nuvlabox/shared
