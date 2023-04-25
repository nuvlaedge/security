"""
Test module for the main security class
"""
import logging
import subprocess

import mock
import requests.exceptions
from mock import patch, Mock
from unittest import TestCase

from security.security import Security
import os
from datetime import datetime


class TestSecurity(TestCase):
    security_open: str = 'security.security.open'

    @patch('security.Security.wait_for_nuvlaedge_ready')
    @patch('os.listdir')
    @patch('os.path.exists')
    def setup(self, exists, list_dir, wait):
        logger: logging.Logger = logging.getLogger('test_logger')
        os.environ['EXTERNAL_CSV_VULNERABILITY_DB'] = 'external_db'
        list_dir.return_value = ['cve.csv.1', 'cve.csv.2', 'cve.csv.3']
        exists.return_value = False
        return Security(logger)

    @patch('security.Security.wait_for_nuvlaedge_ready')
    @patch('os.listdir')
    def test_init(self, list_dir, wait_nb):
        test_security = self.setup()
        self.assertEqual(test_security.agent_api_endpoint, 'localhost:5080')
        self.assertEqual(len(test_security.offline_vulscan_db), 3)
        self.assertEqual(test_security.previous_external_db_update,
                         datetime(1970, 1, 1))

    @patch('nuvla.api.Api.login_apikey')
    @patch('os.path.exists')
    def test_authenticate(self, path_exists, api_init):
        test_security: Security = self.setup()
        path_exists.return_value = False
        # Test no API key file available
        self.assertIsNone(test_security.authenticate())

        path_exists.return_value = True
        with patch(self.security_open, mock.mock_open(read_data='{}')), \
                self.assertRaises(KeyError):
            test_security.authenticate()

        with patch('security.security.open', mock.mock_open(
                read_data='{"api-key": "KEY",'
                          '"secret-key": "Secret"}')):
            self.assertIsNotNone(test_security.authenticate())

    @patch('os.path.exists')
    def test_wait_for_nuvlaedge_ready(self, path_exists):
        test_security: Security = self.setup()
        path_exists.return_value = False
        test_security.timeout_wait_time = 3
        with self.assertRaises(TimeoutError):
            test_security.wait_for_nuvlaedge_ready()

        path_exists.return_value = True

        with patch(self.security_open, mock.mock_open(read_data='NU')):
            test_security.wait_for_nuvlaedge_ready()
            self.assertFalse(test_security.nuvla_endpoint)
            self.assertFalse(test_security.nuvla_endpoint_insecure)

        with patch(self.security_open, mock.mock_open(read_data='NUVLA_ENDPOINT=4 BU')):
            test_security.wait_for_nuvlaedge_ready()
            self.assertEqual(test_security.nuvla_endpoint, '4')
            self.assertFalse(test_security.nuvla_endpoint_insecure)

        with patch(self.security_open, mock.mock_open(
                read_data='NUVLA_ENDPOINT=4 NUVLA_ENDPOINT_INSECURE=1')):
            test_security.wait_for_nuvlaedge_ready()
            self.assertEqual(test_security.nuvla_endpoint, '4')
            self.assertTrue(test_security.nuvla_endpoint_insecure)

    @patch('security.security.run')
    def test_execute_cmd(self, run_ex):
        test_security: Security = self.setup()
        test_security.execute_cmd([])
        self.assertEqual(run_ex.call_count, 1)
        run_ex.reset_mock()

        run_ex.side_effect = OSError
        self.assertIsNone(test_security.execute_cmd([]))

        run_ex.side_effect = ValueError
        self.assertIsNone(test_security.execute_cmd([]))

        run_ex.side_effect = subprocess.TimeoutExpired(['cmd'], 10)
        self.assertIsNone(test_security.execute_cmd([]))

        run_ex.side_effect = subprocess.SubprocessError
        self.assertIsNone(test_security.execute_cmd([]))

    @patch('shutil.move')
    @patch('os.listdir')
    @patch('os.remove')
    @patch('os.path.exists')
    @patch('security.Security.execute_cmd')
    @patch('security.Security.set_previous_external_db_update')
    def test_get_external_db_as_csv(self, prev_set, execute, exists, remove,
                                    list_dir, sh_move):
        test_security: Security = self.setup()
        test_security.get_external_db_as_csv()
        exists.return_value = False
        self.assertEqual(execute.call_count, 3)

        response_mock = Mock()
        response_mock.returncode = 0
        execute.return_value = response_mock
        list_dir.return_value = ['x_1', 'x_2']
        test_security.get_external_db_as_csv()
        exists.return_value = True
        self.assertEqual(sh_move.call_count, 2)
        self.assertEqual(prev_set.call_count, 2)
        self.assertEqual(remove.call_count, 1)

    @patch('os.mkdir')
    @patch('os.path.exists')
    def test_set_previous_external_db_update(self, exists, make_dir):
        test_security: Security = self.setup()
        exists.return_value = False
        with patch(self.security_open, mock.mock_open()) as write_file:
            test_security.set_previous_external_db_update()
            self.assertEqual(make_dir.call_count, 1)

    @patch('os.listdir')
    def test_gather_external_db_file_names(self, list_dir):
        test_security: Security = self.setup()
        files: list = [test_security.settings.online_vulscan_db_prefix+'1',
                       test_security.settings.online_vulscan_db_prefix+'2']
        list_dir.return_value = files
        test_security.gather_external_db_file_names()
        self.assertEqual(test_security.vulscan_dbs, files)

    @patch('os.path.exists')
    @patch('security.Security.gather_external_db_file_names')
    def test_get_previous_external_db_update(self, gather, exists):
        test_security: Security = self.setup()
        exists.return_value = False
        self.assertEqual(test_security.get_previous_external_db_update(),
                         datetime(1970, 1, 1))

        exists.return_value = True
        with patch(self.security_open,
                   mock.mock_open(
                       read_data=datetime(1977, 1, 1).strftime(
                           test_security.settings.date_format))) as mock_open:
            test_security.vulscan_dbs = []
            self.assertEqual(test_security.get_previous_external_db_update(),
                             datetime(1970, 1, 1))

            test_security.vulscan_dbs = ['1']
            self.assertEqual(test_security.get_previous_external_db_update(),
                             datetime(1977, 1, 1))

            gather.side_effect = ValueError
            self.assertEqual(test_security.get_previous_external_db_update(),
                             datetime(1970, 1, 1))

    @patch('security.Security.authenticate')
    @patch('security.Security.get_external_db_as_csv')
    def test_update_vulscan_db(self, external_csv, authenticate):
        test_security: Security = self.setup()
        api_return = Mock()
        return_mock = Mock()
        return_mock.resources = []
        api_return.search.return_value = return_mock
        authenticate.return_value = api_return
        self.assertIsNone(test_security.update_vulscan_db())

        list_mock = Mock()
        list_mock.data.get.return_value = datetime(1975, 1, 1)
        return_mock.resources = [list_mock]
        api_return.search.return_value = return_mock
        authenticate.return_value = api_return
        test_security.local_db_last_update = datetime(1977, 1, 1)
        self.assertIsNone(test_security.update_vulscan_db())

        list_mock.data.get.return_value = datetime(1977, 1, 1)
        return_mock.resources = [list_mock]
        api_return.search.return_value = return_mock
        authenticate.return_value = api_return
        test_security.local_db_last_update = datetime(1975, 1, 1)
        test_security.update_vulscan_db()
        self.assertEqual(external_csv.call_count, 1)

    @patch('os.path.exists')
    @patch('xml.etree.ElementTree.parse')
    def test_parse_vulscan_xml(self, tree_parse, exists):
        test_security: Security = self.setup()
        exists.return_value = False
        self.assertIsNone(test_security.parse_vulscan_xml())

        exists.return_value = True
        tree_parse.return_value.getroot.return_value.findall.return_value = []
        self.assertFalse(test_security.parse_vulscan_xml())

        port_mock = Mock()
        attr_mock = Mock()
        attr_mock.attrib = {'product': 'nuvla',
                            'version': '1',
                            'script': 'sh',
                            'output': 'out'}
        port_mock.find.return_value = attr_mock
        tree_parse.return_value.getroot.return_value.findall.return_value = [port_mock]
        self.assertFalse(test_security.parse_vulscan_xml())

        attr_mock.attrib = {'product': 'nuvla',
                            'version': '1',
                            'script': 'sh',
                            'output': 'out |,| out_2 |,| out_3 |,| out_4'}
        port_mock.find.return_value = attr_mock
        tree_parse.return_value.getroot.return_value.findall.return_value = [port_mock]

        self.assertEqual(test_security.parse_vulscan_xml(),
                         [{'product': 'nuvla 1', 'vulnerability-id': 'out'}])

    @patch('security.security.Popen')
    def test_run_cve_scan(self, popen_ex):
        test_security: Security = self.setup()
        popen_ex.return_value.__enter__.return_value.communicate.return_value = \
            (Mock(), Mock())
        self.assertFalse(test_security.run_cve_scan('ls'))

        popen_ex.return_value.__enter__.return_value.returncode = 0
        self.assertTrue(test_security.run_cve_scan('ls'))

    @patch('security.Security.run_cve_scan')
    @patch('security.Security.parse_vulscan_xml')
    @patch('json.dumps')
    def test_run_scan(self, j_dump, parser, run_cve):
        test_security: Security = self.setup()
        test_security.vulscan_dbs = []
        test_security.run_scan()
        self.assertEqual(parser.call_count, 0)
        self.assertEqual(run_cve.call_count, 0)

        test_security.vulscan_dbs = ['cve_1.xml']
        run_cve.return_value = False
        test_security.run_scan()
        self.assertEqual(parser.call_count, 0)
        self.assertEqual(run_cve.call_count, 1)

        # run_cve.reset_mock()
        # run_cve.return_value = True
        # parser.return_value = 'cvxe_1.csv'
        # test_security.run_scan()
        # self.assertEqual(parser.call_count, 1)
        # self.assertEqual(req_post.call_count, 1)
        # self.assertEqual(run_cve.call_count, 1)

        with patch(self.security_open, mock.mock_open(read_data='{}')):
            run_cve.reset_mock()
            parser.reset_mock()
            run_cve.return_value = True
            parser.return_value = 'cvxe_1.csv'
            test_security.run_scan()
            self.assertEqual(parser.call_count, 1)
            self.assertEqual(run_cve.call_count, 1)
