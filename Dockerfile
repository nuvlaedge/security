FROM python:3-alpine

RUN apk update && apk add --no-cache nmap nmap-scripts

COPY vulscan /usr/share/nmap/scripts/vulscan

COPY code LICENSE /opt/nuvlabox/

WORKDIR /opt/nuvlabox

VOLUME /srv/nuvlabox/shared

ONBUILD RUN ./license.sh