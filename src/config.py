import os
from dotenv import load_dotenv
import datetime

#Load variables from .env file
load_dotenv()
class Config(object):

    #MaliciousFileUpload-2 - START
    """Fix"""
    MAX_CONTENT_LENGTH = 400 * 1024 #Accept max 400KB
    #MaliciousFileUpload-2 - END

    #HardCodedKey-1 - START
    """Vulnerability"""
    SECRET_KEY = 'iamsecret'
    #HardCodedKey-1 - END

    #DebugModeON-1 - START
    """Vulnerability"""
    DEBUG = True
    os.environ['WERKZEUG_DEBUG_PIN'] = 'off'
    #DebugModeON-1 - END

    #CookiesWithoutSecurityAttributes-1 - START
    #CookiesWithoutSecurityAttributes-1 - END

    #CSRF-4 - START
    """Vulnerability"""
    SESSION_COOKIE_SECURE = True 
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'None'
    #CSRF-4 - END

    # Grabs the folder where the script runs.
    basedir = os.path.abspath(os.path.dirname(__file__))

    #HardCodedCredentials-1 - START
    """Fix"""
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')
    #HardCodedCredentials-1 - END
    

    # Turn off the Flask-SQLAlchemy event system and warning
    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')