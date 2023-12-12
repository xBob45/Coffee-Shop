import os
from dotenv import load_dotenv

#Load variables from .env file
load_dotenv()

#HardCodedKey-1 - START
"""Vulnerability"""
SECRET_KEY = 'iamsecret'
#HardCodedKey-1 - END

#DebugModeON-1 - START
"""Vulnerability"""
os.environ["FLASK_DEBUG"] = "1"
#DebugModeON-1 - END

"""SameSite issues documented here"""
#CookiesWithoutSecurityAttributes-1 - START
"""Fix"""
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'  
#CookiesWithoutSecurityAttributes-1 - END

# Grabs the folder where the script runs.
basedir = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')

# Turn off the Flask-SQLAlchemy event system and warning
SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')


