import os
from dotenv import load_dotenv
import datetime

#Load variables from .env file
load_dotenv()
class Config(object):
    #MaliciousFileUpload-2 - START
    #MaliciousFileUpload-2 - END

    #HardCodedKey-1 - START
    """Status: Vulnerable"""
    #Description: CWE-321: Use of Hard-coded Cryptographic Key -> https://cwe.mitre.org/data/definitions/321.html
    SECRET_KEY = 'iamsecret'
    #HardCodedKey-1 - END

    #DebugModeON-1 - START
    """Status: Vulnerable"""
    #Description: CWE-489: Active Debug Code -> https://cwe.mitre.org/data/definitions/489.html
    os.environ['WERKZEUG_DEBUG_PIN'] = 'off'
    #DebugModeON-1 - END

    #CookiesWithoutSecurityAttributes-1 - START
    #CookiesWithoutSecurityAttributes-1 - END

    #CSRF-4 - START
    """Status: Fixed"""
    #Description: CWE-352: Cross-Site Request Forgery -> https://cwe.mitre.org/data/definitions/352.html
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    #CSRF-4 - END

    # Grabs the folder where the script runs.
    basedir = os.path.abspath(os.path.dirname(__file__))

    #HardCodedCredentials-1 - START
    """Status: Fixed"""
    #Description: CWE-798: Use of Hard-coded Credentials -> https://cwe.mitre.org/data/definitions/798.html
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')
    #HardCodedCredentials-1 - END
    

    # Turn off the Flask-SQLAlchemy event system and warning
    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')