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

#OSCommandInjection-1 - START
def execute_command():
    """Fix"""
    try:
        command_value = request.args.get('command')
        if len(command_value) != 1:
            log_config.logger.error("User %s tried to run command %s and failed." % (current_user.username, command_value), extra={'ip_address': request.remote_addr})
            return BadRequest()
        else:
            if command_value == '1':
                command = 'service apache2 status'
            elif command_value == '2':
                command = 'pg_isready -h postgresql'
            else:
                log_config.logger.error("User %s tried to run command %s->None and failed." % (current_user.username, command_value, command), extra={'ip_address': request.remote_addr})
                return BadRequest()
            result = subprocess.check_output([command], universal_newlines=True, stderr=subprocess.STDOUT, shell=True)
            log_config.logger.info("User %s ran %s command" % (current_user.username, command), extra={'ip_address': request.remote_addr})
            return jsonify(result=result)
    except Exception as e:
        log_config.logger.error("User %s failed to run command %s. Exception: %s" % (current_user.username, command_value, e), extra={'ip_address': request.remote_addr})
        return BadRequest()
#OSCommandInjection-1 - END

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

            role_name = request.form.get("add_role")

            check_if_exists('username', username, 'Username')
            check_if_exists('email', email, 'Email')
            
            role = Role.query.filter_by(name=role_name).first().id
            user = User(role_id=role, username=username, email=email, first_name=first_name, last_name=last_name, password=password)
            db.session.add(user)
            db.session.commit()
            log_config.logger.info("User %s created a new user with username %s." % (current_user.username, username), extra={'ip_address': request.remote_addr})
            flash("User has sucesfully been created.","success")
            #This implements the  Post/Redirect/Get (PRG) to prevent data re-insertion when reload.
            return redirect(url_for('admin.add_user'))
        except ValidationError:
            log_config.logger.error("New user was not created. Missing or invalid CSRF token.", extra={'ip_address': request.remote_addr})
            return Forbidden()
        except ValueError:
            return redirect(request.referrer)
        except Exception as e:
            log_config.logger.error("Failed to create a new user. Exception: %s" % e, extra={'ip_address': request.remote_addr})
            flash("Error occured, try again.", "error")
            redirect(request.referrer)
    return render_template("admin/admin_panel_add.html")


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
                    log_config.logger.error("User %s failed to view user with username %s. User doesn't exists." % (current_user.username, username), extra={'ip_address': request.remote_addr})  
            else:
                log_config.logger.error("User %s failed to view user. No username supplied." % current_user.user, extra={'ip_address': request.remote_addr})
                flash("No username provided, try again.","danger")
                return redirect(request.referrer)
        except ValidationError:
            log_config.logger.error("Failed to view user with username %s. Missing or invalid CSRF token." % username, extra={'ip_address': request.remote_addr})
        except Exception as e:
            log_config.logger.error("Failed to view user with username.\nException: %s" % e, extra={'ip_address': request.remote_addr})
            flash("Error occured. Please try again.","danger")
            return redirect(request.referrer)
    return render_template("admin/admin_panel_view_and_update.html")

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
                """Vulnerability"""
                #There is no check of length and complexity of a password.
                #WeakPasswordRequirements-4 - END
                #CompleteOmissionOfHashFunction-1 - START
                #CompleteOmissionOfHashFunction-1 - END
                #WeakHashFunction-1 - START
                #WeakHashFunction-1 - END
                #WeakHashFunctionWithSalt-1 - START
                """Fix"""
                password = ph.hash(password)
                #WeakHashFunctionWithSalt-1 - END  
                user.password = password
            user.role_id = role
            db.session.commit()
            log_config.logger.info("User %s succesfully updated user with username %s." % (current_user.username, username), extra={'ip_address': request.remote_addr})
            flash("User has been updated.", "success")
        except ValidationError:
            log_config.logger.error("User was not. Missing or invalid CSRF token.", extra={'ip_address': request.remote_addr})
            return Forbidden()
        except ValueError:
            return redirect(request.referrer)
        except Exception as e:
            log_config.logger.error("User has not been sucessfully updated. Exception: %s" % e, extra={'ip_address': request.remote_addr})
            flash("Error occured, try again.","danger")
            redirect(request.referrer)    
    return render_template("admin/admin_panel_view_and_update.html")

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
                log_config.logger.info("User with username %s was deleted." % username, extra={'ip_address': request.remote_addr})
                flash("User has been deleted.","danger")
            else:
                log_config.logger.error("User with username %s could not be deleted due to non-existence." % username, extra={'ip_address': request.remote_addr})
                flash("User doesn't exists.","danger")
                redirect(request.referrer)
        except ValidationError:
            log_config.logger.error("User was not deleted. Missing or invalid CSRF token.", extra={'ip_address': request.remote_addr})
            return Forbidden()
        except Exception as e:
            log_config.logger.error("User was not deleted. Exception: %s" % e, extra={'ip_address': request.remote_addr})
            flash("Error occured.","danger")
            redirect(request.referrer)
    return render_template("admin/admin_panel_delete.html")


#SSRF-1 - START
def development():
    """Fix"""
    if request.method == 'GET':

        #Get data from 'url' parameter
        url = request.args.get('url')
        if url is not None:
            log_config.logger.info("URL: %s." % url)
            parsed_url = urlparse(url)

            #Get scheme used in a request
            scheme = parsed_url.scheme
            print(scheme)

            #Get domain in a request
            domain = parsed_url.netloc
            print(domain)

            #Get path in a request
            path = parsed_url.path
            print(path)
            
            #Unused URL schemas (file, ftp, . . .) are disabled
            SCHEMES_ALLOWLIST = ['http']  #TODO <-- Adjust before deployment.
            #Whitelist only IPs and DNS names that the application requires access to.
            DOMAINS_ALLOWLIST = ['127.0.0.1:5000', 'localhost:5000'] #TODO <-- Adjust before deployment.

            try:
                if scheme in SCHEMES_ALLOWLIST:
                    if domain in DOMAINS_ALLOWLIST:
                        log_config.logger.info("User %s successfully opened URL %s." % (current_user.username, url), extra={'ip_address': request.remote_addr})
                        response = urlopen(url)
                        return response.read()
                    else:
                        log_config.logger.error("User %s tried to open URL %s and failed. Provided domain is prohibited." % (current_user.username, url), extra={'ip_address': request.remote_addr}) 
                        return Forbidden()
                else:
                    log_config.logger.error("User %s tried to open URL %s and failed. Provided scheme is prohibited." % (current_user.username, url), extra={'ip_address': request.remote_addr})
                    return Forbidden()
            except Exception as e:
                log_config.logger.error("User %s tried to open URL %s and failed. Exception: %s" % (current_user.username, url, e), extra={'ip_address': request.remote_addr})
                return Forbidden()
    return 'This section is currently under development.'
#SSRF-1 - END