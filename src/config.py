import os
from dotenv import load_dotenv
import datetime

#Load variables from .env file
load_dotenv()
class Config(object):
    #MaliciousFileUpload-2 - START
    #MaliciousFileUpload-2 - END

    #HardCodedKey-1 - START
    """Status: Fixed"""
    #Description: CWE-321: Use of Hard-coded Cryptographic Key -> https://cwe.mitre.org/data/definitions/321.html
    SECRET_KEY = os.environ.get('SECRET_KEY')
    #HardCodedKey-1 - END

    #DebugModeON-1 - START
    """Status: Fixed"""
    #Description: CWE-489: Active Debug Code -> https://cwe.mitre.org/data/definitions/489.html
    os.environ['WERKZEUG_DEBUG_PIN'] = 'on'
    #DebugModeON-1 - END

    #SensitiveCookiewithImproperSameSiteAttribute-1 - START
    """Status: Vulnerable"""
    #Description: CWE-1275: Sensitive Cookie with Improper SameSite Attribute -> https://cwe.mitre.org/data/definitions/1275.html
    SESSION_COOKIE_SECURE = True 
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'None'
    #SensitiveCookiewithImproperSameSiteAttribute-1 - END

    # Grabs the folder where the script runs.
    basedir = os.path.abspath(os.path.dirname(__file__))

    #HardCodedCredentials-1 - START
    """Status: Fixed"""
    #Description: CWE-798: Use of Hard-coded Credentials -> https://cwe.mitre.org/data/definitions/798.html
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')
    #HardCodedCredentials-1 - END
    

    # Turn off the Flask-SQLAlchemy event system and warning
    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')