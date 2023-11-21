import os
from dotenv import load_dotenv
from attacks import config

HardCodedKey = config.getboolean('attacks', 'HardCodedKey')
DebuggModeON = config.getboolean('attacks', 'DebuggModeON')
CookiesWithoutSecurityAttributes = config.getboolean('attacks', 'CookiesWithoutSecurityAttributes')

#Load variables from .env file
load_dotenv()


if HardCodedKey == True:
    #---------------------------------------------A02 - Hard Coded Crypto Ket - START----------------------------------------------
    SECRET_KEY = 'iamsecret'
    #print(SECRET_KEY)
else:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    #print(SECRET_KEY)
    #---------------------------------------------A02 - Hard Coded Crypto Ket - END------------------------------------------------

if DebuggModeON == True:
    #---------------------------------------------A05 - Debugg Mode ON - START----------------------------------------------
    os.environ["FLASK_DEBUG"] = 'True'
    FLASK_DEBUG = os.environ.get('FLASK_DEBUG')
else:
    os.environ["FLASK_DEBUG"] = 'False'
    FLASK_DEBUG = os.environ.get('FLASK_DEBUG')
     #----------------------------------------------A05 - Debugg Mode ON - END-----------------------------------------------

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


