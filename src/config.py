import os
from dotenv import load_dotenv

#Load variables from .env file
load_dotenv()
#HardCodedKey-1 - START
"""Vulnerability"""
SECRET_KEY = 'iamsecret'
#HardCodedKey-1 - END

#DebugModeON-1 - START
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

SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')

# Turn off the Flask-SQLAlchemy event system and warning
SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')


#CSRF
"""SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'None'"""
