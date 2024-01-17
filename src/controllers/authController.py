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
from flask_wtf.csrf import validate_csrf, ValidationError
from hashlib import md5

#SQLInjection-1 - START
def login():
    """Fix"""
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            username = request.form.get('username')
            password = request.form.get('password')
            remember = True if request.form.get('remember') else False
            #CompleteOmissionOfHashFunction-1 - START
            #CompleteOmissionOfHashFunction-1 - END
            #WeakHashFunction-1 - START
            """Vulnerability"""
            password = md5(password.encode()).hexdigest()
            #WeakHashFunction-1 - END
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
        except ValidationError:
            log_config.logging.error("Missing or invalid CSRF token.") 
        except Exception:
            log_config.logging.info("Error occured, try again")
            flash("Unexpected error. Try again, please.")
    return render_template('auth/login.html')
#SQLInjection-1 - END

#StoredXSS-1 - START
def signup():
    """Fix"""
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            first_name = request.form.get('first_name')
            #Function compares user input against allowed pattern.
            input_validation(first_name, 'First name')
            last_name = request.form.get('last_name')
            #Function compares user input against allowed pattern.
            input_validation(last_name, 'Last name')
            email = request.form.get('email')
            #Function compares user input against allowed pattern.
            email_validation(email)
            username= request.form.get('username')
            #Function compares user input against allowed pattern.
            input_validation(username, 'Username')
            password = request.form.get('password')
            check_if_exists('email', email, 'Email')
            check_if_exists('username', username, 'Username')
            #WeakPasswordRequirements-1 - START
            """Vulnerability"""
            #There is no check of length and complexity of a password.
            #WeakPasswordRequirements-1 - END
            #CompleteOmissionOfHashFunction-1 - START
            #CompleteOmissionOfHashFunction-1 - END
            #WeakHashFunction-1 - START
            """Vulnerability"""
            password = md5(password.encode()).hexdigest()
            #WeakHashFunction-1 - END
            user = User(role_id=2, username=username, email=email, first_name=first_name, last_name=last_name, password=password)
            db.session.add(user)
            db.session.commit()
            db.session.close()
            log_config.logging.info("User %s has been sucessfully deleted." % username)
            flash("Account has been sucesfully created.")
            return redirect(url_for("auth.login"))
        except ValidationError:
            log_config.logging.error("Missing or invalid CSRF token.") 
        except ValueError:
            return redirect(request.referrer)
        except Exception:
            log_config.logging.info("Error occured.")
            flash("Error occured.")
            redirect(request.referrer)         
    return render_template("auth/signup.html")

#StoredXSS-1 - END


#InsufficientSessionInvalidation-1 - START
def logout():
    """Fix"""
    #SensitiveDatawithinCookie-2 - START
    """Fix -> Since 'role' is not a part of a session there is no need to do anything at this point."""
    #SensitiveDatawithinCookie-2 - END
    logout_user()
    log_config.logging.info("User logged out.")
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
        log_config.logging.error("%s already exists." % field)
        flash("%s already exists. Please try again!" % field)
        raise ValueError
    
def input_validation(input, field):
    """Function checks for malicious content in fname, lname and username"""
    allowed_pattern = "^[a-zA-Z\-']+$"
    if not re.match(allowed_pattern, input):
        log_config.logging.error("Invalid %s." % field)
        flash("Invalid %s. Only A-Z/a-z and 0-9 are allowed. Please, try again." % field)
        raise ValueError
    
def email_validation(input):
    """Function checks for malicious content in fname, lname and username"""
    allowed_pattern = "^[a-zA-Z0-9@.]+$"
    if not re.match(allowed_pattern, input):
        log_config.logging.error("Invalid email.")
        flash("Invalid email. Please, use only A-Z/a-z and 0-9 are allowed. Please, try again.")
        raise ValueError