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
import shutil
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
        raise TimeoutError
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
    security_folder: str = f'{data_volume}/security'
    external_db_update_file: str = f'{security_folder}/.vuln-db-update'
    external_db_names_file: str = f'{security_folder}/.file_locations'
    nmap_script_path: str = '/usr/share/nmap/scripts/vulscan/'

    date_format: str = '%d-%b-%Y (%H:%M:%S.%f)'
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
    raw_vulnerabilities_gz: str = f'/tmp/raw_vulnerabilities.gz'
    raw_vulnerabilities: str = f'/tmp/raw_vulnerabilities'
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

        self.vulscan_dbs: List = []
        self.previous_external_db_update: datetime = \
            self.get_previous_external_db_update()

        self.offline_vulscan_db: List = \
            [db for db in os.listdir(self.settings.vulscan_db_dir) if
             db.startswith('cve.csv.')]

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
        # Download external DB
        download_command: List = ['wget',
                                  self.settings.external_db.lstrip('"').rstrip('"'),
                                  '-O', self.settings.raw_vulnerabilities_gz]
        response = self.execute_cmd(download_command)
        if response.returncode != 0:
            self.logger.error(f'Not properly downloaded')

        # Uncompress external db
        unzip_command: List = ['gzip', '-d', self.settings.raw_vulnerabilities_gz]
        response = self.execute_cmd(unzip_command)
        if response.returncode != 0:
            self.logger.error(f'Not properly uncompressed')
            self.logger.error(f'{response.stdout}')
            self.logger.error(f'{response.stderr}')

        # Split file in smaller files
        split_command: List = ['split', '-l', '20000', '-d',
                               self.settings.raw_vulnerabilities,
                               '--additional-suffix=.cve_online.csv']
        response = self.execute_cmd(split_command)
        if response.returncode != 0:
            self.logger.error(f'Not properly split')

        else:
            split_files: List = \
                [f for f in os.listdir('/opt/nuvlabox') if f.startswith('x')]
            renamed_files: List = []
            for i, file_name in enumerate(split_files):
                renamed_files.append(self.settings.online_vulscan_db_prefix + str(i))

            self.logger.error(f'{split_files}')
            self.logger.error(f'{renamed_files}')

            for old, new in zip(split_files, renamed_files):
                shutil.move(f'/opt/nuvlabox/{old}',
                            f'{self.settings.vulscan_db_dir}/{new}')

            self.vulscan_dbs = renamed_files
        if os.path.exists(self.settings.raw_vulnerabilities):
            os.remove(self.settings.raw_vulnerabilities)
        self.set_previous_external_db_update()

    def set_previous_external_db_update(self):
        """
        Called when the external databased is updated. It updates a local variable and
        and persistent file with the update date of the external db
        """
        self.previous_external_db_update = datetime.utcnow()
        if not os.path.exists(self.settings.security_folder):
            os.mkdir(self.settings.security_folder)
        with open(self.settings.external_db_update_file, 'w', encoding="utf-8") \
                as date_file:
            date_file.write(
                self.previous_external_db_update.strftime(self.settings.date_format))

    def gather_external_db_file_names(self):
        it_content: List[str] = os.listdir(self.settings.nmap_script_path)
        it_content = [f for f in it_content if
                      f.startswith(self.settings.online_vulscan_db_prefix)]
        self.vulscan_dbs = sorted(it_content)

    def get_previous_external_db_update(self) -> datetime:
        self.logger.info(f'Retrieving previously updated db date')
        if os.path.exists(self.settings.external_db_update_file):
            with open(self.settings.external_db_update_file, 'r', encoding="utf-8") \
                    as date_file:
                try:
                    it_date = datetime.strptime(date_file.read(),
                                                self.settings.date_format)
                    self.gather_external_db_file_names()
                    if not self.vulscan_dbs:
                        return datetime(1970, 1, 1)
                    return it_date
                except ValueError:
                    return datetime(1970, 1, 1)
        else:
            return datetime(1970, 1, 1)

    def update_vulscan_db(self):
        """ Updates the local registry of the vulnerabilities data """

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

    def parse_vulscan_xml(self):
        """ Parses the nmap output XML file and gives back the list of formatted
        vulnerabilities

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
            nmap_scan_cmd: List[str] = \
                ['nice', '-n', '15',
                 'nmap',
                 '-sV',
                 '--script', 'vulscan/', '--script-args',
                 f'vulscandb={vulscan_db},vulscanoutput=nuvlabox-cve,vulscanshowall=1',
                 'localhost',
                 '--exclude-ports', '5080',
                 '-oX', self.settings.vulscan_out_file]

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
            send_vuln_url: str = ''
            try:
                send_vuln_url = f"http://{self.agent_api_endpoint}/" \
                                f"api/set-vulnerabilities"
                _ = requests.post(send_vuln_url, json=temp_vulnerabilities)

            except requests.exceptions.RequestException as ex:
                self.logger.warning(f"Unable to send vulnerabilities to Agent via "
                                    f"{send_vuln_url} due to {ex}")
                self.logger.warning(f"Saving vulnerabilities to local file instead: "
                                    f"{self.settings.vulnerabilities_file}")
                with open(self.settings.vulnerabilities_file, 'w') as vf:
                    vf.write(json.dumps(temp_vulnerabilities))
