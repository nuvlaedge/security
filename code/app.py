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
import xml.etree.ElementTree as ET
from threading import Event
from subprocess import run, PIPE, STDOUT


__copyright__ = "Copyright (C) 2020 SixSq"
__email__ = "support@sixsq.com"


# Run scans every 3 minutes
interval = 180
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
            for vuln in vulnerabilities_found:
                vulnerability_info = {'product': product}
                vuln_attrs = vuln.split(' |,| ')

                try:
                    id, description = vuln_attrs[0:2]
                    link = vuln_attrs[-1]
                except (IndexError, ValueError):
                    log.exception(f"Failed to parse vulnerability {vuln_attrs}")
                    continue

                vulnerability_info['vulnerability-id'] = id
                if description:
                    vulnerability_info['vulnerability-description'] = description

                if link:
                    vulnerability_info['vulnerability-link'] = link

                vulnerabilities.append(vulnerability_info)

    return vulnerabilities


if __name__ == "__main__":
    """ Main """

    set_logger()
    log = logging.getLogger("sec")

    e = Event()

    # nmap CVE variables
    vulscan_out_file = f'{data_volume}/nmap-vulscan-out-xml'
    nmap_scan_cmd = ['sh', '-c',
                     'nmap -sV --script vulscan --script-args vulscandb=cve.csv,vulscanoutput=nuvlabox localhost -oX %s'
                        % vulscan_out_file]

    log.info("Starting NuvlaBox Security scanner...")
    while True:
        # run security scans periodically

        # 1 - get CVE vulnerabilities
        log.info(f"Running nmap Vulscan: {nmap_scan_cmd}")
        cve_scan = run_cve_scan(nmap_scan_cmd)

        if cve_scan:
            log.info(f"Parsing nmap scan result from: {vulscan_out_file}")
            parsed_vulnerabilities = parse_vulscan_xml(vulscan_out_file)

            with open(vulnerabilities_file, 'w') as vf:
                vf.write(json.dumps(parsed_vulnerabilities))

        e.wait(timeout=interval)
