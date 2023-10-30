import os

SECRET_KEY = os.urandom(32)

# Grabs the folder where the script runs.
basedir = os.path.abspath(os.path.dirname(__file__))

# Enable debug mode, that will refresh the page when you make changes.
DEBUG = True

# Configure the PostgreSQL database connection
SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://postgres:postgres@127.0.0.1:5432/postgres'

# Turn off the Flask-SQLAlchemy event system and warning
SQLALCHEMY_TRACK_MODIFICATIONS = False


