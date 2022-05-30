""" Security scan Main script"""
from datetime import datetime
import logging
import sys
import threading
import time

from security import Security, SecuritySettings


def set_logger(logger_name: str = 'security') -> logging.Logger:
    """ Configures logging """
    # give logger a name: app
    root = logging.getLogger(logger_name)
    root.setLevel(logging.DEBUG)

    # print to console
    c_handler = logging.StreamHandler(sys.stdout)
    c_handler.setLevel(logging.DEBUG)

    # format log messages
    formatter = logging.Formatter('%(levelname)s - %(funcName)s - %(message)s')
    c_handler.setFormatter(formatter)

    # add handlers
    root.addHandler(c_handler)

    return root


db_list = []


def main():
    global db_list
    # Wait before starting doing anything
    logger: logging.Logger = set_logger()
    security_event: threading.Event = threading.Event()

    security: Security = Security(logger)
    local_settings: SecuritySettings = security.settings

    logger.info(f'Starting NuvlaEdge security scan in '
                f'{security.settings.scan_period} seconds')
    security_event.wait(timeout=security.settings.scan_period)

    logger.info(f'Updated local vulnerabilities scan database')
    security.update_vulscan_db()

    try:
        while True:
            if local_settings.external_db and security.nuvla_endpoint and \
                (datetime.utcnow() - security.previous_external_db_update)\
                    .total_seconds() > local_settings.external_db_update_period:
                logger.info(f'Checking for updates on the vulnerability DB')
                security.update_vulscan_db()

            logger.info(f'Running vulnerability scan')
            security.run_scan()

            security_event.wait(timeout=security.settings.scan_period)

    except KeyboardInterrupt:
        exit(0)


if __name__ == '__main__':

    main()
    time.sleep(10)

