from flask import Flask, render_template
from routes.authRoute import auth_blueprint
from routes.homeRoute import home_blueprint
from routes.adminRoute import admin_blueprint
from models.User import db, User
from flask_login import LoginManager
import logging

def page_not_found(e):
  return render_template('404.html'), 404

def create_app():
    app = Flask(__name__)  # flask app object
    app.register_error_handler(404, page_not_found)
    app.config.from_object('config')  # Configuring from Python Files
    db.init_app(app)  # Initializing the database

    #-------------------------Flask-Login-------------------------
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    #-------------------------Flask-Login-------------------------

    #Clickjacking-1 - START
    #Clickjacking-1 - END
    return app

app = create_app()


app.register_blueprint(auth_blueprint)
app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint)

if __name__ == '__main__':  # Running the app
    app.run(host='127.0.0.1', port=5000)
