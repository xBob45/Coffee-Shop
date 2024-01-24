import functools
from flask import (flash, redirect, render_template, request, abort, url_for, jsonify)
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

#OSCommandInjection-1 - START
def execute_command():
    """Vulnerability"""
    command = request.args.get('command')
    log_config.logging.info("Command: %s." % command)
    result = subprocess.check_output([command], universal_newlines=True, stderr=subprocess.STDOUT, shell=True)
    return jsonify(result=result)
#OSCommandInjection-1 - END

def admin_panel():
    """Function renders main page of admin panel."""
    try:
        postgre = subprocess.check_output(['pg_isready'], universal_newlines=True, stderr=subprocess.STDOUT, shell=True) 
        if 'accepting connections' in postgre:
            postgre_message = "PostgreSQL is running correctly."
            log_config.logging.info(postgre_message)
        else:
            postgre_message = "PostgreSQL is not accepting connections."
            log_config.logging.info(postgre_message)
    except:
        postgre_message = "PostgreSQL is not accepting connections."
        log_config.logging.info(apache_message)
    try:        
        apache = subprocess.check_output(['systemctl status apache2'], universal_newlines=True, stderr=subprocess.STDOUT, shell=True)
        if 'running' in apache:
            apache_message = "Apache is running correctly."
            log_config.logging.info(apache_message)
        else:
            apache_message = "Apache down"
            log_config.logging.info(apache_message)
    except:
        apache_message = "Apache is down"
        log_config.logging.info(apache_message)
    try:
        log_file = "../app.log"
        with open(log_file, 'r') as file:
            log_content = file.read()
            file.close()
    except:
        log_content = "Error occured while loading the file."
        log_config.logging.info(log_content)
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
            log_config.logging.info("New has been created.")
            flash("User has sucesfully been added to the database.")
            #This implements the  Post/Redirect/Get (PRG) to prevent data re-insertion when reload.
            return redirect(url_for('admin.add_user'))
        except ValidationError:
            log_config.logging.error("Missing or invalid CSRF token.")
        except ValueError:
            return redirect(request.referrer)
        except Exception:
            log_config.logging.info("Error, new user hasn't been created.")
            flash("Error occured, try again.")
            redirect(request.referrer)
    return render_template("admin/admin_panel_add.html")


def view_user():
    """Function allows to view an arbitrary entry in User table."""
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            username = request.form.get("view_username")
            user = User.query.filter_by(username=username).first()
            print(user)
            if user is not None:
                return render_template("admin/admin_panel_view_and_update.html", user=user)
            else:
                flash("User doesn't exists.")  
        except ValidationError:
            log_config.logging.error("Missing or invalid CSRF token.")
        except Exception:
            log_config.logging.error("Error occured.")
            flash("Error occured.")
            redirect(request.referrer)
    return render_template("admin/admin_panel_view_and_update.html")

def update_user():
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            id = request.form.get("edit_id")
            print(id)
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
            log_config.logging.info("User has been sucessfully updated.")
            flash("User has been updated.")
        except ValidationError:
            log_config.logging.error("Missing or invalid CSRF token.")
        except ValueError:
            return redirect(request.referrer)
        except Exception:
            log_config.logging.info("Error, user has not been updated.")
            flash("Error occured, try again.")
            redirect(request.referrer)    
    return render_template("admin/admin_panel_view_and_update.html")

def delete_user():
    """Function allows to delete arbitrary entry from User table."""
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            username = request.form.get("delete_username")
            print(username)
            user = User.query.filter_by(username=username).first()
            print(user)
            if user is not None:
                db.session.delete(user)
                db.session.commit()
                log_config.logging.info("User has been deleted.")
                flash("User has been deleted.")
            else:
                log_config.logging.error("User could not be deleted.")
                flash("User doesn't exists.")
                redirect(request.referrer)
        except ValidationError:
            log_config.logging.error("Missing or invalid CSRF token.")
        except Exception:
            log_config.logging.error("Error occured.")
            flash("Error occured.")
            redirect(request.referrer)
    return render_template("admin/admin_panel_delete.html")


#SSRF-1 - START
def development():
    """Fix"""
    if request.method == 'GET':

        #Get data from 'url' parameter
        url = request.args.get('url')
        if url is not None:
            log_config.logging.info("URL: %s." % url)
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
                        log_config.logging.info("URL was opened.")
                        response = urlopen(url)
                        return response.read()
                else:
                    raise Exception
            except Exception as e:
                log_config.logging.error("URL was rejected")
                return render_template('404.html')
    return 'This is the development section.'
#SSRF-1 - END