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
import signal
import time
from contextlib import contextmanager
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


@contextmanager
def timeout(time):
    # Register a function to raise a TimeoutError on the signal.
    signal.signal(signal.SIGALRM, raise_timeout)
    # Schedule the signal to be sent after ``time``.
    signal.alarm(time)

    try:
        yield
    except TimeoutError:
        pass
    finally:
        # Unregister the signal so it won't be triggered
        # if the timeout is not reached.
        signal.signal(signal.SIGALRM, signal.SIG_IGN)


def raise_timeout(signum, frame):
    raise TimeoutError


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
        try:
            output = script.attrib.get('output')
        except AttributeError:
            continue
        if output:
            output = output.replace('cve.csv:\n', '').replace('cve_online.csv:\n', '').replace(' |nb| \n\n', '')
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


def authenticate(url, insecure, apikey_file):
    """ Uses the NB ApiKey credential to authenticate against Nuvla

    :return: Api client
    """
    api_instance = Api(endpoint='https://{}'.format(url),
                       insecure=insecure, reauthenticate=True)

    if os.path.exists(apikey_file):
        with open(apikey_file) as apif:
            apikey = json.loads(apif.read())
    else:
        return None

    api_instance.login_apikey(apikey['api-key'], apikey['secret-key'])

    return api_instance


def wait_for_nuvlabox_ready(apikey_file, nuvla_conf_file):
    """ Waits on a loop for the NuvlaBox bootstrap and activation to be accomplished

    :param apikey_file: location of the api credentials file
    :param nuvla_conf_file: location of the Nuvla parameters file
    :return: nuvla endpoint and nuvla endpoint insecure boolean
    """
    log = logging.getLogger("sec")
    nuvla_endpoint = nuvla_endpoint_insecure = None

    # wait for 60 seconds max
    with timeout(60):
        log.info('Waiting for NuvlaBox to bootstrap')
        while not os.path.exists(apikey_file):
            time.sleep(5)

        log.info('Waiting and searching for Nuvla connection parameters after NuvlaBox activation')
        while not os.path.exists(nuvla_conf_file):
            time.sleep(5)

        # If we get here, it means both files have been written, and we can finally get Nuvla's conf parameters
        with open(nuvla_conf_file) as nuvla_conf:
            for line in nuvla_conf.read().split():
                try:
                    if line and 'NUVLA_ENDPOINT=' in line:
                        nuvla_endpoint = line.split('=')[-1]
                    if line and 'NUVLA_ENDPOINT_INSECURE=' in line:
                        nuvla_endpoint_insecure = bool(line.split('=')[-1])
                except IndexError:
                    pass

    return nuvla_endpoint, nuvla_endpoint_insecure


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

    external_db = os.getenv('EXTERNAL_CVE_VULNERABILITY_DB',
                            os.getenv('EXTERNAL_CSV_VULNERABILITY_DB')).lstrip('"').rstrip('"')

    apikey_file = f'{data_volume}/.activated'
    nuvla_conf_file = f'{data_volume}/.nuvla-configuration'
    # wait until the NuvlaBox is fully activated and configured
    # this service can run without this though, so set a timer and move on even if not ready
    nuvla_endpoint, nuvla_insecure = wait_for_nuvlabox_ready(apikey_file, nuvla_conf_file)

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
                    api = authenticate(nuvla_endpoint, nuvla_insecure, apikey_file)

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

        # We can --exclude-ports 5080 from the scan because that's the NB agent API,
        # which is only accessible from within the machine
        nmap_scan_cmd = ['sh', '-c',
                         'nmap -sV --script vulscan/ --script-args vulscandb=%s,vulscanoutput=nuvlabox-cve,vulscanshowall=1 localhost --exclude-ports 5080 -oX %s --release-memory'
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
