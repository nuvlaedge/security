FROM python:3-alpine3.12

ARG GIT_BRANCH
ARG GIT_COMMIT_ID
ARG GIT_BUILD_TIME
ARG GITHUB_RUN_NUMBER
ARG GITHUB_RUN_ID
ARG PROJECT_URL

LABEL git.branch=${GIT_BRANCH}
LABEL git.commit.id=${GIT_COMMIT_ID}
LABEL git.build.time=${GIT_BUILD_TIME}
LABEL git.run.number=${GITHUB_RUN_NUMBER}
LABEL git.run.id=${GITHUB_RUN_ID}
LABEL org.opencontainers.image.authors="support@sixsq.com"
LABEL org.opencontainers.image.created=${GIT_BUILD_TIME}
LABEL org.opencontainers.image.url=${PROJECT_URL}
LABEL org.opencontainers.image.vendor="SixSq SA"
LABEL org.opencontainers.image.title="NuvlaBox System Manager"
LABEL org.opencontainers.image.description="Manages the overall state of the NuvlaBox Engine"

RUN apk update && apk add --no-cache nmap nmap-scripts

COPY vulscan /usr/share/nmap/scripts/vulscan

COPY code LICENSE /opt/nuvlabox/

WORKDIR /opt/nuvlabox

RUN pip install -r requirements.txt

RUN cp -f patch/vulscan.nse /usr/share/nmap/scripts/vulscan/

ENV VULSCAN_DB_DIR /usr/share/nmap/scripts/vulscan
ENV DB_SLICE_SIZE 20000

ADD vuln-db/databases/all.aggregated.csv.gz ${VULSCAN_DB_DIR}

RUN gunzip -c ${VULSCAN_DB_DIR}/all.aggregated.csv.gz > ${VULSCAN_DB_DIR}/cve.csv && \
      rm -f ${VULSCAN_DB_DIR}/all.aggregated.csv.gz && \
      split -l ${DB_SLICE_SIZE} ${VULSCAN_DB_DIR}/cve.csv ${VULSCAN_DB_DIR}/cve.csv. && \
      rm -f ${VULSCAN_DB_DIR}/cve.csv

VOLUME /srv/nuvlabox/shared

ONBUILD RUN ./license.sh

ENTRYPOINT ["./app.py"]
