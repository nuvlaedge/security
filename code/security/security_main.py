#!/usr/local/bin/python
# -*- coding: utf-8 -*-

""" Security scan Main script"""
from datetime import datetime
import logging
import sys

from .security import Security


def set_logger(logger_name: str = 'security', log_level: int = logging.INFO) \
        -> logging.Logger:
    """ Configures logging """
    # give logger a name: app
    root = logging.getLogger(logger_name)
    root.setLevel(log_level)

    # print to console
    c_handler = logging.StreamHandler(sys.stdout)
    c_handler.setLevel(log_level)

    # format log messages
    formatter = logging.Formatter('%(levelname)s - %(funcName)s - %(message)s')
    c_handler.setFormatter(formatter)

    # add handlers
    root.addHandler(c_handler)

    return root


def main():
    """
    Main wrapper to control the security class
    """
    # Wait before starting doing anything
    logger: logging.Logger = set_logger()

    security: Security = Security(logger)

    logger.info('Starting NuvlaEdge security scan')

    if security.settings.external_db and security.nuvla_endpoint and \
        (datetime.utcnow() - security.previous_external_db_update)\
            .total_seconds() > security.settings.external_db_update_period:
        logger.info('Checking for updates on the vulnerability DB')
        security.update_vulscan_db()

    logger.info('Running vulnerability scan')
    security.run_scan()


if __name__ == '__main__':
    main()
