"""
Test module for the main execution script
"""
import logging
from unittest import TestCase
from mock import patch
from security import security_main
import os


class TestSecurityMain(TestCase):
    """ Security Main Test"""

    def test_set_logger(self):
        self.assertIsInstance(security_main.set_logger('name'), logging.Logger)
        self.assertEqual(security_main.set_logger('name').name, 'name')

    @patch('security.Security.update_vulscan_db')
    @patch('security.Security.run_scan')
    @patch('security.Security.wait_for_nuvlaedge_ready')
    @patch('os.listdir')
    def test_main(self, list_dir, nb_ready, scan, update):
        os.environ['EXTERNAL_CSV_VULNERABILITY_DB'] = 'external_db'
        list_dir.return_value = []
        nb_ready.return_value = True
        scan.side_effect = SyntaxError
        with self.assertRaises(SyntaxError):
            security_main.main()
