__author__ = 'Daniel Sánchez'
# encoding:utf-8

import logging
import traceback

app_name = "socket_app_py"
# Logger configuration
logger = logging.getLogger(app_name)
logger.setLevel(logging.DEBUG)

# create file handler which logs even debug messages
fh = logging.FileHandler('socket.log')
fh.setLevel(logging.DEBUG)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)

# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)


def get_logger(file_handler='socket.log'):
    """This method will return the default logger ('logger') or a copy with the modified file handler ('new_logger')"""
    result = logger  # Default logger
    if file_handler != 'socket.log':
        new_logger = logger  # We create a copy so we don't modify the original
        new_logger.removeHandler(fh)
        fh2 = logging.FileHandler(file_handler)
        fh2.setFormatter(formatter)
        new_logger.addHandler(fh2)
        result = new_logger  # We change the return value to the copy
    return result


def generate_error_message(msg):
    logger.info(str(msg) + "\n\n")
    # traceback.print_exc()
    logger.debug(str(traceback.format_exc()) + "\n\n")