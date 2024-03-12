import logging
from flask import Flask
import requests


werkzeug_log = logging.getLogger('werkzeug')
werkzeug_log.disabled = True

#InsufficientLogging-1 - START
"""Vulnerability"""
logging.basicConfig(level=logging.DEBUG, filename="src/logs/app.log",filemode="a",format="%(levelname)s %(message)s")
#InsufficientLogging-1 - END
