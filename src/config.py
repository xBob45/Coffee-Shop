import os

SECRET_KEY = os.urandom(32)

# Grabs the folder where the script runs.
basedir = os.path.abspath(os.path.dirname(__file__))

# Enable debug mode, that will refresh the page when you make changes.
DEBUG = True

# Connect to the MYSQL database
#SQLALCHEMY_DATABASE_URI = 'mysql://root:<your_password>@localhost/<your_database_name>'

# Turn off the Flask-SQLAlchemy event system and warning
#SQLALCHEMY_TRACK_MODIFICATIONS = False