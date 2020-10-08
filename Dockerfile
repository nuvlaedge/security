FROM python:3-alpine

RUN apk update && apk add --no-cache nmap nmap-scripts

COPY vulscan /usr/share/nmap/scripts/vulscan

COPY code /opt/nuvlabox/

COPY code/patch/ /usr/share/nmap/scripts/vulscan

WORKDIR /opt/nuvlabox

VOLUME /srv/nuvlabox/shared
