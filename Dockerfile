FROM python:3-alpine

RUN apk update && apk add --no-cache nmap nmap-scripts

COPY vulscan /usr/share/nmap/scripts/vulscan

COPY code LICENSE /opt/nuvlabox/

WORKDIR /opt/nuvlabox

RUN pip install -r requirements.txt

RUN cp -f patch/vulscan.nse /usr/share/nmap/scripts/vulscan/

ENV VULSCAN_DB_DIR /usr/share/nmap/scripts/vulscan

ADD vuln-db/databases/all.aggregated.csv.gz ${VULSCAN_DB_DIR}

RUN gunzip -c ${VULSCAN_DB_DIR}/all.aggregated.csv.gz > ${VULSCAN_DB_DIR}/cve.csv && \
      rm -f ${VULSCAN_DB_DIR}/all.aggregated.csv.gz

VOLUME /srv/nuvlabox/shared

ONBUILD RUN ./license.sh

ENTRYPOINT ["./app.py"]