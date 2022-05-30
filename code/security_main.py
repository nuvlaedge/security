""" Security scan Main script"""
import logging
import sys
import time

from security import Security


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
    logger: logging.Logger = set_logger()

    security: Security = Security(logger)
    db_list = security.update_vulscan_db()
    try:
        while True:
            security.run_scan(db_list)
            time.sleep(180)
    except KeyboardInterrupt:
        exit(0)


if __name__ == '__main__':

    main()
    time.sleep(10)

