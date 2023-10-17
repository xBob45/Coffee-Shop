# Importing the necessary modules and libraries
from flask import Flask
#from flask_migrate import Migrate
from routes.authRoute import auth_blueprint
from routes.homeRoute import home_blueprint
#from models.machine import db


def create_app():
    app = Flask(__name__)  # flask app object
    app.config.from_object('config')  # Configuring from Python Files
    #db.init_app(app)  # Initializing the database

    return app


app = create_app()  # Creating the app
# Registering the blueprint
app.register_blueprint(auth_blueprint)
app.register_blueprint(home_blueprint)
#migrate = Migrate(app, db)  # Initializing the migration


if __name__ == '__main__':  # Running the app
    app.run(host='127.0.0.1', port=5000, debug=True)


#Following ENV variables has been set
"""set FLASK_ENV=development
set FLASK_APP=app
flask run"""