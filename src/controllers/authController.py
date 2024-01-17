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
import secrets
from passlib.hash import md5_crypt
from argon2 import PasswordHasher
import argon2
ph = PasswordHasher()

#SQLInjection-1 - START
def login():
    """Vulnerability"""      
    #' OR 1=1; DELETE FROM users WHERE id=1; --
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            username = request.form.get('username')
            password = request.form.get('password')
            remember = True if request.form.get('remember') else False
            user_result = db.session.execute(text("SELECT * FROM users WHERE username = '%s'" % (username)))
            db.session.commit()
            user = user_result.fetchone()
            if user is not None:
                user = User(id=user[0], username=user[2], email= user[3], first_name=user[4], last_name=user[5],password=user[6])
                db.session.commit()
                #CompleteOmissionOfHashFunction-2 - START
                #CompleteOmissionOfHashFunction-2 - END
                #WeakHashFunction-2 - START
                #WeakHashFunction-2 - END
                #WeakHashFunctionWithSalt-2 - START
                db_passwd = user.password 
                if (md5_crypt.verify(password, db_passwd)) != True:
                #WeakHashFunctionWithSalt-2 - END 
                    #InsertionOfSensitiveInformationIntoLogFile-2 - START
                    """Vulnerability"""
                    log_config.logging.info("User %s failed to login! Wrong password entered." % username)
                    #InsertionOfSensitiveInformationIntoLogFile-2 - END
                    
                    #SensitiveInformationDisclosure-1 - START
                    """Vulnerability"""
                    flash("Incorrect password.")
                    #SensitiveInformationDisclosure-1 - END
                    return redirect(request.referrer)

                else:
                    # Perform the login action or redirect to the home page
                    login_user(user, remember=remember)

                    #InsertionOfSensitiveInformationIntoLogFile-1 - START
                    """Vulnerability"""
                    log_config.logging.info("User with %s username succesfully logged in with password %s password." % (username, password))
                    #InsertionOfSensitiveInformationIntoLogFile-1 - END

                    #SensitiveDatawithinCookie-1 - START
                    """Vulnerability"""
                    user_role = db.session.query(Role.name).join(User, Role.id == User.role_id).filter(User.id == user.id).first()
                    session['role'] = user_role[0]
                    #SensitiveDatawithinCookie-1 - END
                    return redirect(url_for('home.home'))
                 
            else:
                #ReflectedXSS-1 - START
                """Fix"""
                flash("Incorrect credentials, try again.")
                #ReflectedXSS-1 - END
                #InsertionOfSensitiveInformationIntoLogFile-3 - START
                """Vulnerability"""
                log_config.logging.info("User %s failed to login! Username doesn't exist." % username)
                #InsertionOfSensitiveInformationIntoLogFile-3 - END   
                return redirect(request.referrer)

        except ValidationError:
            log_config.logging.error("Missing or invalid CSRF token.") 
        except argon2.exceptions.VerifyMismatchError:
            #InsertionOfSensitiveInformationIntoLogFile-2 - START
            """Vulnerability"""
            log_config.logging.info("User %s failed to login! Wrong password entered." % username)
            #InsertionOfSensitiveInformationIntoLogFile-2 - END
            #SensitiveInformationDisclosure-1 - START
            """Vulnerability"""
            flash("Incorrect password.")
            #SensitiveInformationDisclosure-1 - END
        except Exception as e:
            print(e)
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
            #WeakHashFunction-1 - END

            #WeakHashFunctionWithSalt-1 - START
            password = md5_crypt.using(salt_size=8).hash(password)
            #WeakHashFunctionWithSalt-1 - END            
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
    """Vulnerability"""
    session.pop('role')
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
    
def md5_salted(password):
    salt = secrets.token_bytes(16)
    hashed_password = md5(password.encode() + salt).hexdigest()
    return "%s:%s" % (salt.hex(), hashed_password)

def md5_salted_verify(salt, password):
    hashed_password = md5(password.encode() + bytes.fromhex(salt)).hexdigest()
    return hashed_password


