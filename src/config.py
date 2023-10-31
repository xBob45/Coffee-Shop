import os
from dotenv import load_dotenv
from attacks import config

HardCodedKey = config.getboolean('attacks', 'HardCodedKey')


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



# Grabs the folder where the script runs.
basedir = os.path.abspath(os.path.dirname(__file__))

# Enable debug mode, that will refresh the page when you make changes.
DEBUG = os.environ.get('DEBUG')

# Configure the PostgreSQL database connection
SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')

# Turn off the Flask-SQLAlchemy event system and warning
SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')


