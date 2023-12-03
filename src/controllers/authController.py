import functools
from models.User import User, Role, UserRoles
from models.User import db
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
import os
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy.sql import text
import log_config

#SQLInjection-1 - START
def login():
    """Fix"""
    if request.method == 'POST':
        username = request.form.get('username')
        print(username)
        password = request.form.get('password')
        print(password)
        remember = True if request.form.get('remember') else False
        user = User.query.filter_by(username=username).first()
        if user is None:
            #InsertionOfSensitiveInformationIntoLogFile-3 - START
            log_config.logging.info("User %s failed to login! Username doesn't exist." % username)
            #InsertionOfSensitiveInformationIntoLogFile-3 - END

            #ReflectedXSS-1 - START
            """Vulnerability"""
            flash("Incorrect credentials for %s." %(username))
            #ReflectedXSS-1 - END

        elif user.password != password:

            #InsertionOfSensitiveInformationIntoLogFile-2 - START
            log_config.logging.info("User %s failed to login! Wrong password entered." % username)
            #InsertionOfSensitiveInformationIntoLogFile-2 - END

            #SensitiveInformationDisclosure-1 - START
            """Vulnerability"""
            flash("Incorrect password.")
            #SensitiveInformationDisclosure-1 - END
        else:
            # Perform the login action or redirect to the home page
            login_user(user, remember=remember)

            #InsertionOfSensitiveInformationIntoLogFile-1 - START
            log_config.logging.info("User with %s username succesfully logged in with password %s password." % (username, password))
            #InsertionOfSensitiveInformationIntoLogFile-1 - END

            #SensitiveDatawithinCookie-1 - START
            """Vulnerability"""
            user_roles = db.session.query(Role.name).join(UserRoles, Role.id == UserRoles.role_id).filter(UserRoles.user_id == user.id).one()
            for role in user_roles:
                session['role'] = role
                break
            #SensitiveDatawithinCookie-1 - END
            
            return redirect(url_for('home.home')) 
    # If the request method is GET or the login was unsuccessful, render the login form
    return render_template('auth/login.html')
#SQLInjection-1 - END

def signup():
    return render_template("auth/signup.html")

#InsufficientSessionInvalidation-1 - START
def logout():
    """Fix"""
    #SensitiveDatawithinCookie-2 - START
    """Vulnerability"""
    session.pop('role')
    #SensitiveDatawithinCookie-2 - END
    username = current_user.username
    logout_user()
    log_config.logging.info("User %s logged out." % username)
    flash("You were logged out.")
    return redirect(url_for("auth.login"))
#InsufficientSessionInvalidation-1 - END