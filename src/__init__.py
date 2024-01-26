from flask import Flask, render_template
from src.routes.authRoute import auth_blueprint
from src.routes.homeRoute import home_blueprint
from src.routes.adminRoute import admin_blueprint
from src.routes.accountRoute import account_blueprint
from src.models.User import db, User
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
import logging

def page_not_found(e):
  return render_template('404.html'), 404

def create_app():
    app = Flask(__name__)  # flask app object
    
    app.register_error_handler(404, page_not_found)
    app.config.from_object('src.config')  # Configuring from Python Files
    db.init_app(app)  # Initializing the database
    #-------------------------Flask-Login-------------------------
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)
    @login_manager.user_loader
    
    def load_user(user_id):
        return User.query.get(int(user_id))
    #-------------------------Flask-Login-------------------------


    #Flask-WTF
    csrf = CSRFProtect()
    csrf.init_app(app)
    #Flask-WTF

    #Clickjacking-1 - START
    #Clickjacking-1 - END
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(home_blueprint)
    app.register_blueprint(account_blueprint)
    app.register_blueprint(admin_blueprint)

    return app