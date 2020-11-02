#!/usr/local/bin/python
# -*- coding: utf-8 -*-

"""NuvlaBox Security service

This service runs regular security scans, to find out vulnerabilities
worth reporting back to Nuvla

"""

import os
import logging
import sys
import json
import requests
import gzip
import io
import xml.etree.ElementTree as ET
from threading import Event
from subprocess import run, PIPE, STDOUT
from nuvla.api import Api
from datetime import datetime as dt


__copyright__ = "Copyright (C) 2020 SixSq"
__email__ = "support@sixsq.com"


# Shared volume
data_volume = "/srv/nuvlabox/shared"
# Vulnerabilities file
vulnerabilities_file = f'{data_volume}/vulnerabilities'


def set_logger():
    """ Configures logging """
    # give logger a name: app
    root = logging.getLogger("sec")
    root.setLevel(logging.DEBUG)

    # print to console
    c_handler = logging.StreamHandler(sys.stdout)
    c_handler.setLevel(logging.DEBUG)

    # format log messages
    formatter = logging.Formatter('%(levelname)s - %(funcName)s - %(message)s')
    c_handler.setFormatter(formatter)

    # add handlers
    root.addHandler(c_handler)


def run_cve_scan(cmd):
    """ Runs the vulscan nmap scan against localhost and
     save the result to an XML file

     :param cmd: nmap command to be executed, in exec format

     :returns """

    nmap_out = run(cmd, stdout=PIPE, stderr=STDOUT, encoding='UTF-8')

    if nmap_out.returncode != 0 or not nmap_out.stdout:
        return False
    else:
        return True


def parse_vulscan_xml(file):
    """ Parses the nmap output XML file and gives back the list of formatted vulnerabilities

    :param file: path to XML file
    :return: list of CVE vulnerabilities
    """

    log = logging.getLogger("sec")

    if not os.path.exists(file):
        return None

    root = ET.parse(file).getroot()
    ports = root.findall('host/ports/port')

    vulnerabilities = []
    for port in ports:
        service = port.find('service')
        service_attrs = service.attrib

        product = ''
        if service_attrs.get('product'):
            product += service_attrs['product']

        if service_attrs.get('version'):
            product += f' {service_attrs["version"]}'

        if not product:
            continue

        script = port.find('script')
        output = script.attrib.get('output')
        if output:
            output = output.lstrip('cve.csv:\n').replace(' |nb| \n\n', '')
            vulnerabilities_found = output.split(' |nb| ')
            log.info(f"Parsing list of found vulnerabilities for {product}")
            for vuln in vulnerabilities_found:
                vulnerability_info = {'product': product}
                vuln_attrs = vuln.split(' |,| ')

                try:
                    id, description = vuln_attrs[0:2]
                    score = vuln_attrs[-1]
                except (IndexError, ValueError):
                    log.exception(f"Failed to parse vulnerability {vuln_attrs}")
                    continue

                vulnerability_info['vulnerability-id'] = id
                # if description:
                #     vulnerability_info['vulnerability-description'] = description
                #
                if score:
                    try:
                        vulnerability_info['vulnerability-score'] = float(score)
                    except ValueError:
                        log.exception(f"Vulnerability score ({score}) not in a proper format. Score discarded...")

                vulnerabilities.append(vulnerability_info)

    return vulnerabilities


def authenticate(url, insecure):
    """ Uses the NB ApiKey credential to authenticate against Nuvla

    :return: Api client
    """
    api_instance = Api(endpoint='https://{}'.format(url),
                       insecure=insecure, reauthenticate=True)

    apikey_file = f'{data_volume}/.activated'
    if os.path.exists(apikey_file):
        with open(apikey_file) as apif:
            apikey = json.loads(apif.read())
    else:
        return None

    api_instance.login_apikey(apikey['api-key'], apikey['secret-key'])

    return api_instance


if __name__ == "__main__":
    """ Main """

    set_logger()
    log = logging.getLogger("sec")

    # Run scans every X seconds
    default_interval = 300
    intervals = {'SECURITY_SCAN_INTERVAL': default_interval,
                 'EXTERNAL_CVE_VULNERABILITY_DB_UPDATE_INTERVAL': default_interval}

    for env in intervals:
        try:
            intervals[env] = float(os.getenv(env))
        except (ValueError, TypeError):
            log.exception("Env var %s is not a number. Using default interval: %s seconds" % (env, default_interval))

    external_db = os.getenv('EXTERNAL_CVE_VULNERABILITY_DB').lstrip('"').rstrip('"')
    nuvla_endpoint = os.getenv('NUVLA_ENDPOINT')
    nuvla_insecure = os.getenv('NUVLA_ENDPOINT_INSECURE', False)
    api = None
    local_db_last_update = None     # Never at start. TODO: could be improved to check the local DB file timestamp

    e = Event()

    # nmap CVE variables
    vulscan_out_file = f'{data_volume}/nmap-vulscan-out-xml'

    vulscan_db_dir = os.getenv('VULSCAN_DB_DIR')
    offline_vulscan_db = "cve.csv"
    online_vulscan_db = "cve_online.csv"
    vulscan_db = offline_vulscan_db

    log.info("Starting NuvlaBox Security scanner...")
    previous_external_db_update = dt(1970, 1, 1)
    while True:
        if external_db and \
                nuvla_endpoint and \
                (dt.utcnow()-previous_external_db_update).total_seconds() > intervals['EXTERNAL_CVE_VULNERABILITY_DB_UPDATE_INTERVAL']:
            log.info(f"Checking for recent updates on the vulnerability DB {external_db}")
            try:
                if not api:
                    api = authenticate(nuvla_endpoint, nuvla_insecure)

                nuvla_vulns = []
                if api:
                    nuvla_vulns = api.search('vulnerability', orderby='modified:desc', last=1).resources

                if len(nuvla_vulns) > 0:
                    nuvla_db_last_update = nuvla_vulns[0].data.get('updated')

                    log.info(f"Nuvla's vulnerability DB was last updated on {nuvla_db_last_update}")

                    if not local_db_last_update or nuvla_db_last_update > local_db_last_update:
                        # need to update

                        # Get online DB
                        log.info(f"Fetching and extracting {external_db}")

                        external_db_gz = requests.get(external_db)
                        db_content = io.BytesIO(external_db_gz.content)
                        db_content_csv = gzip.GzipFile(fileobj=db_content, mode='rb').read()

                        try:
                            with open(f'{vulscan_db_dir}/{online_vulscan_db}', 'w') as dbw:
                                dbw.write(db_content_csv.decode())

                            vulscan_db = online_vulscan_db
                            local_db_last_update = nuvla_db_last_update
                            previous_external_db_update = dt.utcnow()
                            log.info(f"Local vulnerability DB {vulscan_db} updated")
                        except:
                            # if something goes wrong, just fallback to the offline DB
                            logging.exception(f"Failed to save external DB {online_vulscan_db}. Falling back to {offline_vulscan_db}")
                            vulscan_db = offline_vulscan_db
            except:
                log.exception(f"Could not check for updates on DB {external_db}. Moving on with existing DB")

        nmap_scan_cmd = ['sh', '-c',
                         'nmap -sV --script vulscan --script-args vulscandb=%s,vulscanoutput=nuvlabox-cve localhost -oX %s'
                         % (vulscan_db, vulscan_out_file)]
        # run security scans periodically

        # 1 - get CVE vulnerabilities
        log.info(f"Running nmap Vulscan: {nmap_scan_cmd}")
        cve_scan = run_cve_scan(nmap_scan_cmd)

        if cve_scan:
            log.info(f"Parsing nmap scan result from: {vulscan_out_file}")
            parsed_vulnerabilities = parse_vulscan_xml(vulscan_out_file)

            with open(vulnerabilities_file, 'w') as vf:
                vf.write(json.dumps(parsed_vulnerabilities))

        e.wait(timeout=intervals['SECURITY_SCAN_INTERVAL'])
