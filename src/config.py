import os
from dotenv import load_dotenv
from attack import config

CookiesWithoutSecurityAttributes = config.getboolean('attacks', 'CookiesWithoutSecurityAttributes')

#Load variables from .env file
load_dotenv()


#HardCodedKey - START
#HardCodedKey - END

#DebugModeON - START
#DebugModeON - END

if CookiesWithoutSecurityAttributes:
    #---------------------------------------------A05 - Cookies without Security Attributes - START----------------------------------------------
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = False
else:
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'   
    #---------------------------------------------A05 - Cookies without Security Attributes - END------------------------------------------------



# Grabs the folder where the script runs.
basedir = os.path.abspath(os.path.dirname(__file__))


SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')


# Turn off the Flask-SQLAlchemy event system and warning
SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')


