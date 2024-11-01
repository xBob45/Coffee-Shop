import logging
from flask import Flask
import requests


werkzeug_log = logging.getLogger('werkzeug')
werkzeug_log.disabled = False

#InsufficientLogging-1 - START
"""Status: Fixed"""
#Description: CWE-778: Insufficient Logging -> https://cwe.mitre.org/data/definitions/778.html
log_format = '%(asctime)s - IP:%(ip_address)s - %(levelname)s - %(message)s'

#InsufficientLogging-1 - END

formatter = logging.Formatter(log_format)

# Handler is an object responsible for dispatching log messages to specific destiantion, in this case to the file 'app.log'
file_handler = logging.FileHandler("src/logs/app.log")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

logger = logging.getLogger("app_logger") #Responsible for creating log messages, that's why it's used like logging.logger across the application.
logger.addHandler(file_handler) #This determines to where the log messages should be sent. 
logger.setLevel(logging.DEBUG) #Determines log level for the 'logger' itself.
