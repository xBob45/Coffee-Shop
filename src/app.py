# Importing the necessary modules and libraries
from flask import Flask
from routes.authRoute import auth_blueprint
from routes.homeRoute import home_blueprint
from models.User import db, User
from flask_login import LoginManager


def create_app():
    app = Flask(__name__)  # flask app object
    app.config.from_object('config')  # Configuring from Python Files
    db.init_app(app)  # Initializing the database

    #-------------------------Flask-Login-------------------------
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))
    #-------------------------Flask-Login-------------------------

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