from flask import Flask, render_template
from src.routes.authRoute import auth_blueprint
from src.routes.homeRoute import home_blueprint
from src.routes.adminRoute import admin_blueprint
from src.routes.accountRoute import account_blueprint
from src.routes.cartRoute import cart_blueprint
from src.auxiliary.context_processors import utility_processor
from src.models.User import db, User
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
import logging
from werkzeug.exceptions import Forbidden, BadRequest, NotFound, InternalServerError, HTTPVersionNotSupported, RequestEntityTooLarge, UnsupportedMediaType
from src.auxiliary.custom_error_responses import *
from werkzeug.debug import DebuggedApplication


def create_app():
    app = Flask(__name__)  # flask app object
    app.config.from_object('src.config.Config')  # Configuring from Python Files
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
    """Status: Fixed"""
    #Description: CWE-1021: Improper Restriction of Rendered UI Layers or Frames -> https://cwe.mitre.org/data/definitions/1021.html
    @app.after_request
    def security_measures(response):
        response.headers['X-Frame-Options'] = 'DENY'
        return response
    #Clickjacking-1 - END
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(home_blueprint)
    app.register_blueprint(account_blueprint)
    app.register_blueprint(admin_blueprint)
    app.register_blueprint(cart_blueprint)

    app.context_processor(utility_processor)

    #CustomErrorPages-2 - START
    #CustomErrorPages-2 - END
    
    #DebugModeON-3 - START
    """Status: Fixed"""
    #Description: CWE-489: Active Debug Code -> https://cwe.mitre.org/data/definitions/489.html
    app.register_error_handler(BadRequest, handle_400)
    app.register_error_handler(Forbidden, handle_403)
    app.register_error_handler(NotFound, handle_404)
    app.register_error_handler(RequestEntityTooLarge, handle_413)
    app.register_error_handler(UnsupportedMediaType, handle_415)
    app.register_error_handler(InternalServerError, handle_500)
    app.register_error_handler(HTTPVersionNotSupported, handle_505)
    #DebugModeON-3 - END
    return app
