import functools
from models.User import User, Role
from models.User import db
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
import os
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy.sql import text
from psycopg2.errors import UniqueViolation
from sqlalchemy.exc import IntegrityError
import log_config
import re

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
            """Vulnerability"""
            log_config.logging.info("User %s failed to login! Username doesn't exist." % username)
            #InsertionOfSensitiveInformationIntoLogFile-3 - END

            #ReflectedXSS-1 - START
            """Vulnerability"""
            flash("Incorrect credentials for %s." %(username))
            #ReflectedXSS-1 - END

        elif user.password != password:

            #InsertionOfSensitiveInformationIntoLogFile-2 - START
            """Vulnerability"""
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
            """Vulnerability"""
            log_config.logging.info("User with %s username succesfully logged in with password %s password." % (username, password))
            #InsertionOfSensitiveInformationIntoLogFile-1 - END

            #SensitiveDatawithinCookie-1 - START
            """Fix -> Sensitive data as 'role' should not be stored within a cookie."""
            
            #SensitiveDatawithinCookie-1 - END
            
            return redirect(url_for('home.home')) 
    # If the request method is GET or the login was unsuccessful, render the login form
    return render_template('auth/login.html')
#SQLInjection-1 - END

def signup():
    if request.method == 'POST':
        try:
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            email = request.form.get('email')
            username= request.form.get('username')
            password = request.form.get('password')
            check_if_exists('email', email, 'Email')
            check_if_exists('username', username, 'Username')
            #WeakPasswordRequirements-1 - START
            """Vulnerability"""
            #There is no check of length and complexity of a password.
            #WeakPasswordRequirements-1 - END
            user = User(role_id=2, username=username, email=email, first_name=first_name, last_name=last_name, password=password)
            db.session.add(user)
            db.session.commit()
            db.session.close()
            flash("Account has been sucesfully created.")
            return redirect(url_for("auth.login"))
        except (ValueError, Exception):
            return redirect(request.referrer)
    return render_template("auth/signup.html")


#InsufficientSessionInvalidation-1 - START
def logout():
    """Fix"""
    #SensitiveDatawithinCookie-2 - START
    """Fix -> Since 'role' is not a part of a session there is no need to do anything at this point."""
    #SensitiveDatawithinCookie-2 - END
    username = current_user.username
    logout_user()
    log_config.logging.info("User %s logged out." % username)
    flash("You were logged out.")
    return redirect(url_for("auth.login"))
#InsufficientSessionInvalidation-1 - END


#WeakPasswordRequirements-2 - START
"""Vulnerability"""
def check_for_password_complexity(password):
    #There is no check of length and complexity of a password.
    pass
#WeakPasswordRequirements-2 - END

def check_if_exists(model_field, value, field):
    exists = User.query.filter_by(**{model_field: value}).first()
    if exists:
        flash("%s already exists. Please try again!" % field)
        raise ValueError
        