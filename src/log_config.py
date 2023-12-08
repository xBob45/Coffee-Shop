import logging
from flask import Flask


"""werkzeug_log = logging.getLogger('werkzeug')
werkzeug_log.disabled = True"""

#InsufficientLogging-1 - START
"""Vulnerability"""
#logging.basicConfig(level=logging.DEBUG, filename="../app.log",filemode="a",format="%(levelname)s %(message)s")
#InsufficientLogging-1 - END

