import functools
from src.models.User import User, Role
from src.models.User import db
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for)
from werkzeug.exceptions import Forbidden
from werkzeug.security import check_password_hash, generate_password_hash
import os
import requests
from dotenv import load_dotenv
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy.sql import text
from psycopg2.errors import UniqueViolation
from sqlalchemy.exc import IntegrityError
import src.log_config as log_config
import re
from flask_wtf.csrf import validate_csrf, ValidationError
from hashlib import md5
import secrets
from passlib.hash import md5_crypt
from argon2 import PasswordHasher
import argon2
ph = PasswordHasher()


load_dotenv()
SITE_KEY = os.getenv("CAPTCHA_SITE_KEY")
SECRET_KEY = os.getenv("CAPTCHA_SECRET_KEY")
VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'


#SQLInjection-1 - START
def login():
    """Fix"""
    if request.method == 'POST':
        try:
            #BruteForce-2 - START
            """Vulnerability"""
            """No reCAPTCHA"""
            #BruteForce-2 - END
            validate_csrf(request.form.get('csrf_token'))
            username = request.form.get('username')
            password = request.form.get('password')
            remember = True if request.form.get('remember') else False
            user = User.query.filter_by(username=username).first()  
            if user is not None:
                #CompleteOmissionOfHashFunction-2 - START
                #CompleteOmissionOfHashFunction-2 - END
                #WeakHashFunction-2 - START
                #WeakHashFunction-2 - END
                #WeakHashFunctionWithSalt-2 - START
                """Fix"""
                db_passwd = user.password 
                if (ph.verify(db_passwd, password)) != True:
                
                #WeakHashFunctionWithSalt-2 - END 
                    #InsertionOfSensitiveInformationIntoLogFile-2 - START
                    """Vulnerability"""
                    log_config.logger.error("User %s failed to login! Wrong password entered." % username, extra={'ip_address': request.remote_addr})
                    #InsertionOfSensitiveInformationIntoLogFile-2 - END

                    #SensitiveInformationDisclosure-1 - START
                    """Vulnerability"""
                    flash("Incorrect password.")
                    #SensitiveInformationDisclosure-1 - END
                    return redirect(request.referrer)
                else:
                    # Perform the login action or redirect to the home page
                    login_user(user, remember=remember)
                    session['cart'] = {}
                    session['total'] = 0

                    #InsertionOfSensitiveInformationIntoLogFile-1 - START
                    """Vulnerability"""
                    log_config.logger.info("User with %s username successfully logged in with password %s password." % (username, password), extra={'ip_address': request.remote_addr})
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
                log_config.logger.error("User %s failed to login! Username doesn't exist." % username, extra={'ip_address': request.remote_addr})
                #InsertionOfSensitiveInformationIntoLogFile-3 - END   
                return redirect(request.referrer)
        except ValidationError:
            log_config.logger.error("User was not updated. Missing or invalid CSRF token.", extra={'ip_address': request.remote_addr})
            return Forbidden()
        except argon2.exceptions.VerifyMismatchError:
            #InsertionOfSensitiveInformationIntoLogFile-2 - START
            """Vulnerability"""
            log_config.logger.error("User %s failed to login! Wrong password entered." % username, extra={'ip_address': request.remote_addr})
            #InsertionOfSensitiveInformationIntoLogFile-2 - END
            #SensitiveInformationDisclosure-1 - START
            """Vulnerability"""
            flash("Incorrect password.")
            #SensitiveInformationDisclosure-1 - END
        except Exception as e:
            log_config.logger.error("User was not updated. Exception: %s" % e, extra={'ip_address': request.remote_addr})
            flash("Error occured, try again.")
            return redirect(request.referrer)  
    #BruteForce-3 - START
    """Vulnerability"""
    return render_template('auth/login.html')
    #BruteForce-3 - END
#SQLInjection-1 - END

#StoredXSS-1 - START
def signup():
    """Fix"""
    if request.method == 'POST':
        try:
            response = request.form.get('g-recaptcha-response')
            verify_response = requests.post(url='%s?secret=%s&response=%s' % (VERIFY_URL, SECRET_KEY, response)).json()
            if verify_response.get('success') != True:
                log_config.logger.error("Failed reCAPTCHA.", extra={'ip_address': request.remote_addr})
                return Forbidden()
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
            """Fix"""
            password = ph.hash(password)
            #WeakHashFunctionWithSalt-1 - END            
            user = User(role_id=2, username=username, email=email, first_name=first_name, last_name=last_name, password=password)
            db.session.add(user)
            db.session.commit()
            db.session.close()
            log_config.logger.info("New user with username %s was successfully created." % username, extra={'ip_address': request.remote_addr})
            flash("Account has been sucesfully created.")
            return redirect(url_for("auth.login"))
        except ValidationError:
            log_config.logger.error("User was not created. Missing or invalid CSRF token.", extra={'ip_address': request.remote_addr})
            return Forbidden() 
        except ValueError:
            return redirect(request.referrer)
        except Exception as e:
            log_config.logger.error("User was not successfully created. Exception: %s" % e, extra={'ip_address': request.remote_addr})
            flash("Error occured, try again.")
            redirect(request.referrer)         
    return render_template('auth/signup.html', site_key = SITE_KEY)

#StoredXSS-1 - END


#InsufficientSessionInvalidation-1 - START
def logout():
    """Fix"""
    #SensitiveDatawithinCookie-2 - START
    """Vulnerability"""
    session.pop('role')
    #SensitiveDatawithinCookie-2 - END
    session.pop('cart')
    session.pop('total')
    username = current_user.username
    logout_user()
    log_config.logger.info("User with username %s logged out." % username, extra={'ip_address': request.remote_addr})
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
        log_config.logger.error("%s already exists." % field, extra={'ip_address': request.remote_addr})
        flash("%s already exists. Please try again!" % field, "danger")
        raise ValueError
    
def input_validation(input, field):
    """Function checks for malicious content in fname, lname and username"""
    allowed_pattern = "^[a-zA-Z\-']+$"
    if not re.match(allowed_pattern, input):
        log_config.logger.error("User entered an invalid %s." % (field), extra={'ip_address': request.remote_addr})
        flash("Invalid %s. Only A-Z/a-z are allowed. Please, try again." % field, "danger")
        raise ValueError
    
def email_validation(input):
    """Function checks for malicious content in fname, lname and username"""
    allowed_pattern = "^[a-zA-Z0-9@.]+$"
    if not re.match(allowed_pattern, input):
        log_config.logger.error("User entered an invalid email.", extra={'ip_address': request.remote_addr})
        flash("Invalid email. Please, use only A-Z/a-z and 0-9 are allowed. Please, try again.", "danger")
        raise ValueError
    
def md5_salted(password):
    salt = secrets.token_bytes(16)
    hashed_password = md5(password.encode() + salt).hexdigest()
    return "%s:%s" % (salt.hex(), hashed_password)

def md5_salted_verify(salt, password):
    hashed_password = md5(password.encode() + bytes.fromhex(salt)).hexdigest()
    return hashed_password


