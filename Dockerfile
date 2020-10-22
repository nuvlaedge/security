FROM python:3-alpine

RUN apk update && apk add --no-cache nmap nmap-scripts

COPY vulscan /usr/share/nmap/scripts/vulscan

COPY code LICENSE /opt/nuvlabox/

WORKDIR /opt/nuvlabox

RUN cp -f patch/vulscan.nse /usr/share/nmap/scripts/vulscan/

VOLUME /srv/nuvlabox/shared

ONBUILD RUN ./license.sh