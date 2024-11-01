import functools
from flask import (flash, redirect, render_template, request, abort, url_for, jsonify)
from flask_login import current_user
from src.models.User import User, Role
from src.models.User import db
import subprocess
from src.controllers.authController import check_for_password_complexity, check_if_exists, email_validation, input_validation, ph
import requests
from urllib.request import urlopen
from urllib.error import URLError
from urllib.parse import urlparse
import src.log_config as log_config
from flask_wtf.csrf import validate_csrf, ValidationError
from hashlib import md5
from passlib.hash import md5_crypt
from werkzeug.exceptions import Forbidden, BadRequest
import bleach

from src.auxiliary.custom_decorators import check_if_admin


#OSCommandInjection-1 - START
"""Status: Fixed"""
#Description: CWE-78: OS Command Injection -> https://cwe.mitre.org/data/definitions/78.html
@check_if_admin
def execute_command():
    try:
        command_value = request.args.get('command')
        if len(command_value) != 1:
            log_config.logger.error("User %s tried to run command %s and failed." % (bleach.clean(current_user.username), bleach.clean(command_value)), extra={'ip_address': request.remote_addr})
            raise BadRequest()
        else:
            if command_value == '1':
                command = 'service apache2 status'
            elif command_value == '2':
                command = 'pg_isready -h postgresql'
            else:
                log_config.logger.error("User %s tried to run command %s->None and failed." % (bleach.clean(current_user.username), bleach.clean(command_value), bleach.clean(command)), extra={'ip_address': request.remote_addr})
                raise BadRequest()
            result = subprocess.check_output([command], universal_newlines=True, stderr=subprocess.STDOUT, shell=True)
            log_config.logger.info("User %s ran %s command" % (bleach.clean(current_user.username), bleach.clean(command)), extra={'ip_address': request.remote_addr})
            return jsonify(result=result)
    except BadRequest:
        abort(400)
    except Exception as e:
        log_config.logger.error("User %s failed to run command %s. Exception: %s" % (bleach.clean(current_user.username), bleach.clean(command_value), e), extra={'ip_address': request.remote_addr})
        abort(400)
#OSCommandInjection-1 - END

@check_if_admin
def admin_panel():
    """Function renders main page of admin panel."""
    try:
        postgre = subprocess.check_output(['pg_isready -h postgresql'], universal_newlines=True, stderr=subprocess.STDOUT, shell=True) 
        if 'accepting connections' in postgre:
            postgre_message = "PostgreSQL is running correctly."
            log_config.logger.info(postgre_message, extra={'ip_address': request.remote_addr})
        else:
            postgre_message = "PostgreSQL is not accepting connections."
            log_config.logger.critical(postgre_message, extra={'ip_address': request.remote_addr})
    except:
        postgre_message = "PostgreSQL is not accepting connections."
        log_config.logger.info(apache_message, extra={'ip_address': request.remote_addr})
    try:        
        apache = subprocess.check_output(['service apache2 status'], universal_newlines=True, stderr=subprocess.STDOUT, shell=True)
        if 'running' in apache:
            apache_message = "Apache is running correctly."
            log_config.logger.info(apache_message, extra={'ip_address': request.remote_addr})
        else:
            apache_message = "Apache down"
            log_config.logger.critical(apache_message, extra={'ip_address': request.remote_addr})
    except:
        apache_message = "Apache is down"
        log_config.logger.info(apache_message, extra={'ip_address': request.remote_addr})
    try:
        log_file = "src/logs/app.log"
        with open(log_file, 'r') as file:
            log_content = file.read()
            file.close()
    except FileNotFoundError:
        log_content = "Error occured while loading the file."
        log_config.logger.info(log_content, extra={'ip_address': request.remote_addr})
    except Exception as e:
            log_config.logger.error("Error occured, try again. Exception: %s" % e, extra={'ip_address': request.remote_addr})
            flash("Error occured, try again.","danger")
            redirect(request.referrer)

    return render_template("admin/admin_panel.html", postgre_message=postgre_message, apache_message=apache_message, log_content=log_content)

@check_if_admin
def add_user():
    """Functionallows to add new entry to User table."""
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            username = request.form.get("add_username")
            input_validation(username, 'Username')

            email = request.form.get("email")
            email_validation(email)

            first_name = request.form.get("add_fname")
            input_validation(first_name, 'First name')

            last_name = request.form.get("add_lname")
            input_validation(last_name, 'Last name')

            password = request.form.get("add_pass")
            #WeakPasswordRequirements-1 - START
            """Status: Vulnerable"""
            #Description: CWE-521: Weak Password Requirements -> https://cwe.mitre.org/data/definitions/521.html
            #There is no check of length and complexity of a password.
            #WeakPasswordRequirements-1 - END

            #CompleteOmissionOfHashFunction-1 - START
            #CompleteOmissionOfHashFunction-1 - END

            #WeakHashFunction-1 - START
            #WeakHashFunction-1 - END

            #WeakHashFunctionWithSalt-1 - START
            """Status: Fixed"""
            #Description: CWE-327: Use of a Broken or Risky Cryptographic Algorithm -> https://cwe.mitre.org/data/definitions/327.html
            password = ph.hash(password)
            #WeakHashFunctionWithSalt-1 - END  

            role_name = request.form.get("add_role")

            check_if_exists('username', username, 'Username')
            check_if_exists('email', email, 'Email')
            
            role = Role.query.filter_by(name=role_name).first().id
            user = User(role_id=role, username=username, email=email, first_name=first_name, last_name=last_name, password=password)
            db.session.add(user)
            db.session.commit()
            log_config.logger.info("User %s created a new user with username %s." % (bleach.clean(current_user.username), bleach.clean(username)), extra={'ip_address': request.remote_addr})
            flash("User has sucesfully been created.","success")
            #This implements the  Post/Redirect/Get (PRG) to prevent data re-insertion when reload.
            return redirect(url_for('admin.add_user'))
        except ValidationError:
            log_config.logger.error("New user was not created. Missing or invalid CSRF token.", extra={'ip_address': request.remote_addr})
            abort(400)
        except ValueError:
            return redirect(request.referrer)
        except Exception as e:
            log_config.logger.error("Failed to create a new user. Exception: %s" % e, extra={'ip_address': request.remote_addr})
            flash("Error occured, try again.", "danger")
            redirect(request.referrer)
    return render_template("admin/admin_panel_add.html")

@check_if_admin
def view_user():
    """Function allows to view an arbitrary entry in User table."""
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            username = request.form.get("view_username")
            if username:
                user = User.query.filter_by(username=username).first()
                if user is not None:
                    return render_template("admin/admin_panel_view_and_update.html", user=user)
                else:
                    flash("User doesn't exists.", "danger")  
                    log_config.logger.error("User %s failed to view user with username %s. User doesn't exists." % (bleach.clean(current_user.username), bleach.clean(username)), extra={'ip_address': request.remote_addr})  
            else:
                log_config.logger.error("User %s failed to view user. No username supplied." % bleach.clean(current_user.username), extra={'ip_address': request.remote_addr})
                flash("No username provided, try again.","danger")
                return redirect(request.referrer)
        except ValidationError:
            log_config.logger.error("Failed to view user with username %s. Missing or invalid CSRF token." % bleach.clean(username), extra={'ip_address': request.remote_addr})
            abort(400)
        except Exception as e:
            log_config.logger.error("Failed to view user with username.\nException: %s" % e, extra={'ip_address': request.remote_addr})
            flash("Error occured. Please try again.","danger")
            return redirect(request.referrer)
    return render_template("admin/admin_panel_view_and_update.html")

@check_if_admin
def update_user():
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            id = request.form.get("edit_id")
            username = request.form.get("edit_username")
            email = request.form.get("edit_email")
            first_name = request.form.get("edit_fn")
            last_name = request.form.get("edit_ln")
            password = request.form.get("edit_password")
            role = request.form.get("edit_role")
    
            user = User.query.filter_by(id=id).first()
            current_username = user.username
            current_email = user.email
            if current_username != username:
                input_validation(username, "Username")
                check_if_exists('username', username, 'Username')
                user.username = username
            if current_email != email:
                email_validation(email)
                check_if_exists('email', email, 'Email')
                user.email = email 
            user.first_name = first_name
            input_validation(user.first_name, "First Name")
            user.last_name = last_name
            input_validation(user.last_name, "Last Name")
            if password == '':
                pass
            else:
                #WeakPasswordRequirements-4 - START
                """Status: Vulnerable"""
                #Description: CWE-521: Weak Password Requirements -> https://cwe.mitre.org/data/definitions/521.html
                #There is no check of length and complexity of a password.
                #WeakPasswordRequirements-4 - END
                #CompleteOmissionOfHashFunction-1 - START
                #CompleteOmissionOfHashFunction-1 - END
                #WeakHashFunction-1 - START
                #WeakHashFunction-1 - END
                #WeakHashFunctionWithSalt-1 - START
                """Status: Fixed"""
                #Description: CWE-327: Use of a Broken or Risky Cryptographic Algorithm -> https://cwe.mitre.org/data/definitions/327.html
                password = ph.hash(password)
                #WeakHashFunctionWithSalt-1 - END  
                user.password = password
            user.role_id = role
            db.session.commit()
            log_config.logger.info("User %s succesfully updated user with username %s." % (bleach.clean(current_user.username), bleach.clean(username)), extra={'ip_address': request.remote_addr})
            flash("User has been updated.", "success")
        except ValidationError:
            log_config.logger.error("User was not updated. Missing or invalid CSRF token.", extra={'ip_address': request.remote_addr})
            abort(400)
        except ValueError:
            return redirect(request.referrer)
        except Exception as e:
            log_config.logger.error("User was not updated. Exception: %s" % e, extra={'ip_address': request.remote_addr})
            flash("Error occured, try again.","danger")
            redirect(request.referrer)    
    return render_template("admin/admin_panel_view_and_update.html")

@check_if_admin
def delete_user():
    """Function allows to delete arbitrary entry from User table."""
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            username = request.form.get("delete_username")
            user = User.query.filter_by(username=username).first()
            print(user)
            if user is not None:
                db.session.delete(user)
                db.session.commit()
                log_config.logger.info("User with username %s was deleted." %  bleach.clean(username), extra={'ip_address': request.remote_addr})
                flash("User has been deleted.","danger")
            else:
                log_config.logger.error("User with username %s could not be deleted due to non-existence." % bleach.clean(username), extra={'ip_address': request.remote_addr})
                flash("User doesn't exists.","danger")
                redirect(request.referrer)
        except ValidationError:
            log_config.logger.error("User was not deleted. Missing or invalid CSRF token.", extra={'ip_address': request.remote_addr})
            abort(400)
        except Exception as e:
            log_config.logger.error("User was not deleted. Exception: %s" % e, extra={'ip_address': request.remote_addr})
            flash("Error occured.","danger")
            redirect(request.referrer)
    return render_template("admin/admin_panel_delete.html")


#SSRF-1 - START
#SSRF-1 - END