"""
Module for the security scanner class
"""
from contextlib import contextmanager
from datetime import datetime
import json
import logging
import os
import re
import requests
import signal
from subprocess import run, PIPE, STDOUT, Popen, CompletedProcess, TimeoutExpired, \
    SubprocessError
from threading import Event
import time
from typing import List, Dict, Union
from xml.etree import ElementTree

from nuvla.api import Api
from pydantic import BaseSettings, Field


@contextmanager
def timeout(timeout_time):
    # Register a function to raise a TimeoutError on the signal.
    signal.signal(signal.SIGALRM, raise_timeout)
    # Schedule the signal to be sent after ``time``.
    signal.alarm(timeout_time)

    try:
        yield
    except TimeoutError:
        raise
    finally:
        # Unregister the signal so it won't be triggered
        # if the timeout is not reached.
        signal.signal(signal.SIGALRM, signal.SIG_IGN)


def raise_timeout(signum, frame):
    raise TimeoutError


class SecuritySettings(BaseSettings):
    # File locations
    data_volume: str = "/srv/nuvlabox/shared"
    vulnerabilities_file: str = f'{data_volume}/vulnerabilities'
    apikey_file: str = f'{data_volume}/.activated'
    nuvla_conf_file: str = f'{data_volume}/.nuvla-configuration'

    # Security configuration
    kubernetes_service_host: str = Field('', env='KUBERNETES_SERVICE_HOST')
    namespace: str = Field('nuvlabox', env='MY_NAMESPACE')

    # App periods
    default_interval: int = 300
    scan_period: int = Field(default_interval, env='SECURITY_SCAN_INTERVAL')
    external_db_update_period: int = Field(
        default_interval,
        env='EXTERNAL_CVE_VULNERABILITY_DB_UPDATE_INTERVAL')

    slice_size: int = Field(20, env='DB_SLICE_SIZE')

    # Database files
    vulscan_out_file: str = f'{data_volume}/nmap-vulscan-out-xml'
    vulscan_db_dir: str = Field('', env='VULSCAN_DB_DIR')
    online_vulscan_db_prefix: str = 'cve_online.csv.'
    external_db: str

    class Config:
        fields = {
            'external_db': {
                'env': ['EXTERNAL_CSV_VULNERABILITY_DB', 'EXTERNAL_CVE_VULNERABILITY_DB']
            }
        }


class Security:
    """ Security wrapper class """

    def __init__(self, logger: logging.Logger):
        self.logger: logging.Logger = logger

        self.settings: SecuritySettings = SecuritySettings()
        self.agent_api_endpoint: str = 'localhost:5080' if not \
            self.settings.kubernetes_service_host else f'agent.{self.settings.namespace}'

        self.nuvla_endpoint: str = ''
        self.nuvla_endpoint_insecure: bool = False
        self.logger.info(f'')
        self.wait_for_nuvlabox_ready()
        self.api: Api = self.authenticate()

        self.event: Event = Event()

        self.local_db_last_update = None
        self.previous_external_db_update = datetime(1970, 1, 1)

        self.offline_vulscan_db: List = \
            [db for db in os.listdir(self.settings.vulscan_db_dir) if
             db.startswith('cve.csv.')]

        self.vulscan_dbs: List = []

    def authenticate(self):
        """ Uses the NB ApiKey credential to authenticate against Nuvla

        :return: Api client
        """
        api_instance = Api(endpoint=f'https://{self.nuvla_endpoint}',
                           insecure=self.nuvla_endpoint_insecure,
                           reauthenticate=True)

        if os.path.exists(self.settings.apikey_file):
            with open(self.settings.apikey_file) as api_file:
                apikey = json.loads(api_file.read())
        else:
            return None

        api_instance.login_apikey(apikey['api-key'], apikey['secret-key'])

        return api_instance

    def wait_for_nuvlabox_ready(self):
        """ Waits on a loop for the NuvlaBox bootstrap and activation to be accomplished

        :return: nuvla endpoint and nuvla endpoint insecure boolean
        """

        # wait for 60 seconds max
        # with timeout(60):
        self.logger.info('Waiting for NuvlaBox to bootstrap')
        while not os.path.exists(self.settings.apikey_file):
            time.sleep(5)

        self.logger.info('Waiting and searching for Nuvla connection parameters '
                         'after NuvlaBox activation')

        while not os.path.exists(self.settings.nuvla_conf_file):
            time.sleep(5)

        # If we get here, it means both files have been written, and we can finally
        # get Nuvla's conf parameters
        with open(self.settings.nuvla_conf_file) as nuvla_conf:
            for line in nuvla_conf.read().split():
                try:
                    if line and 'NUVLA_ENDPOINT=' in line:
                        self.nuvla_endpoint = line.split('=')[-1]
                    if line and 'NUVLA_ENDPOINT_INSECURE=' in line:
                        self.nuvla_endpoint_insecure = bool(line.split('=')[-1])
                except IndexError:
                    pass

    @staticmethod
    def execute_cmd(command: List[str], method_flag: bool = True) \
            -> Union[Dict, CompletedProcess, None]:
        """ Shell wrapper to execute a command

        @param command: command to execute
        @param method_flag: flag to switch between run and Popen command execution
        @return: all outputs
        """
        try:
            if method_flag:
                return run(command, stdout=PIPE, stderr=STDOUT, encoding='UTF-8')

            with Popen(command, stdout=PIPE, stderr=PIPE) as shell_pipe:
                stdout, stderr = shell_pipe.communicate()

                return {'stdout': stdout,
                        'stderr': stderr,
                        'returncode': shell_pipe.returncode}

        except OSError as ex:
            logging.error(f"Trying to execute non existent file: {ex}")

        except ValueError as ex:
            logging.error(f"Invalid arguments executed: {ex}")

        except TimeoutExpired as ex:
            logging.error(f"Timeout {ex} expired waiting for command: {command}")

        except SubprocessError as ex:
            logging.error(f"Exception not identified: {ex}")

        return None

    def get_external_db_as_csv(self):
        download_command: List = ['wget',
                                  self.settings.external_db.lstrip('"').rstrip('"'),
                                  '-O', '/tmp/raw_vulnerabilities.gz']
        response = self.execute_cmd(download_command)
        if response.returncode != 0:
            self.logger.error(f'Not properly downloaded')

        unzip_command: List = ['gzip', '-d', '/tmp/raw_vulnerabilities.gz']
        response = self.execute_cmd(unzip_command)
        if response.returncode != 0:
            self.logger.error(f'Not properly uncompressed')

    def update_vulscan_db(self):
        """ Updates the local registry of the vulnerabilities data """

        def read_in_slices(file_object, batch_size=20):
            """
            Auxiliary generator function to read the file as and iterator. Receives the
            object to read and the memory size in MB to return per iteration
            """
            bytes_batch_size: int = batch_size*1024*1024
            while True:
                data = file_object.read(bytes_batch_size)
                if not data:
                    break
                yield data

        nuvla_vul_db: List = self.api.search('vulnerability',
                                             orderby='modified:desc',
                                             last=1).resources

        if not nuvla_vul_db:
            self.logger.warning(f'Nuvla endpoint {self.nuvla_endpoint} does not '
                                f'contain any vulnerability')
            return

        temp_db_last_update = nuvla_vul_db[0].data.get('updated')

        self.logger.info(f"Nuvla's vulnerability DB was last updated on "
                         f"{temp_db_last_update} {type(temp_db_last_update)}")

        if self.local_db_last_update and \
                temp_db_last_update < self.local_db_last_update:
            self.logger.info(f'Database recently updated')
            return

        self.logger.info(f"Fetching and extracting {self.settings.external_db}")
        self.get_external_db_as_csv()

        with open('/tmp/raw_vulnerabilities', 'r') as temp_vul_file:

            self.vulscan_dbs = []
            for i, current_slice in enumerate(read_in_slices(temp_vul_file)):

                online_db_slice = f'{self.settings.vulscan_db_dir}/' \
                                  f'{self.settings.online_vulscan_db_prefix}' \
                                  f'{i}'
                self.logger.info(f'Saving part {i} of the CVE DB at {online_db_slice}')

                with open(online_db_slice, 'w') as dbw:
                    dbw.write('\n'.join(current_slice))

                self.vulscan_dbs.append(online_db_slice.split('/')[-1])

            self.local_db_last_update = temp_db_last_update
            self.previous_external_db_update = datetime.utcnow()
            self.logger.info(f"Local vulnerability DB updated: "
                             f"{' '.join(self.vulscan_dbs)}")

    def parse_vulscan_xml(self):
        """ Parses the nmap output XML file and gives back the list of formatted
        vulnerabilities

        :param file: path to XML file
        :return: list of CVE vulnerabilities
        """

        if not os.path.exists(self.settings.vulscan_out_file):
            return None

        root = ElementTree.parse(self.settings.vulscan_out_file).getroot()
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
                output = re.sub('cve.*.csv.*:\n', '', output).replace(' |nb| \n\n', '')
                vulnerabilities_found = output.split(' |nb| ')
                self.logger.info(f"Parsing list of found vulnerabilities for {product}")
                for vuln in vulnerabilities_found:
                    vulnerability_info = {'product': product}
                    vuln_attrs = vuln.split(' |,| ')

                    try:
                        id, description = vuln_attrs[0:2]
                        score = vuln_attrs[-1]
                    except (IndexError, ValueError) as ex:
                        self.logger.error(
                            f"Failed to parse vulnerability {vuln_attrs}: {str(ex)}")
                        continue

                    vulnerability_info['vulnerability-id'] = id
                    # if description:
                    #     vulnerability_info['vulnerability-description'] = description
                    #
                    if score:
                        try:
                            vulnerability_info['vulnerability-score'] = float(score)
                        except ValueError:
                            self.logger.exception(
                                f"Vulnerability score ({score}) not in a proper "
                                f"format. Score discarded...")

                    vulnerabilities.append(vulnerability_info)

        return vulnerabilities

    @staticmethod
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

    def run_scan(self):
        temp_vulnerabilities: List = []

        for vulscan_db in self.vulscan_dbs:
            nmap_scan_cmd = ['sh', '-c',
                             'nmap -sV --script vulscan/ --script-args vulscandb=%s,vulscanoutput=nuvlabox-cve,vulscanshowall=1 localhost --exclude-ports 5080 -oX %s --release-memory'
                             % (vulscan_db, self.settings.vulscan_out_file)]
            # run security scans periodically

            # 1 - get CVE vulnerabilities
            self.logger.info(f"Running nmap Vulscan: {nmap_scan_cmd}")
            cve_scan = self.run_cve_scan(nmap_scan_cmd)

            if cve_scan:
                self.logger.info(f"Parsing nmap scan result from: "
                                 f"{self.settings.vulscan_out_file}")
                parsed_vulnerabilities = self.parse_vulscan_xml()
                temp_vulnerabilities += parsed_vulnerabilities

        self.logger.info(f'Found {len(temp_vulnerabilities)} vulnerabilities')
        if temp_vulnerabilities:
            try:
                send_vuln_url = f"http://{self.agent_api_endpoint}/" \
                                f"api/set-vulnerabilities"
                response = requests.post(send_vuln_url, json=temp_vulnerabilities)
            except:
                self.logger.exception(f"Unable to send vulnerabilities to Agent via "
                                      f"{send_vuln_url}")
                self.logger.warning(f"Saving vulnerabilities to local file instead: "
                                    f"{self.settings.vulnerabilities_file}")
                with open(self.settings.vulnerabilities_file, 'w') as vf:
                    vf.write(json.dumps(temp_vulnerabilities))
