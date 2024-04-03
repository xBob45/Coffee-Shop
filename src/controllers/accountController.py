from flask import (flash, redirect, render_template, request, abort, url_for, jsonify, session)
from src.models.User import User, Role, Order, OrderItems, Product
from src.models.User import db
from dotenv import load_dotenv
from flask_login import logout_user, current_user
from src.controllers.authController import check_for_password_complexity, check_if_exists, input_validation, email_validation, ph
import src.log_config as log_config
from flask_wtf.csrf import validate_csrf, ValidationError
from hashlib import md5
from passlib.hash import md5_crypt
from werkzeug.exceptions import Forbidden, BadRequest
from werkzeug.utils import secure_filename
import uuid
import os
import mimetypes



load_dotenv()
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER")

#IDOR-3 - START
def setting():
    """Fix"""
    return render_template("account/setting.html")
#IDOR-3 - END

#StoredXSS-2 - START
def update_user():
    """Fix"""
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            id = current_user.id
            username = request.form.get("edit_username")
            email = request.form.get("edit_email")
            first_name = request.form.get("edit_fn")
            last_name = request.form.get("edit_ln")
            password = request.form.get("edit_password")

            user = User.query.filter_by(id=id).first()
            current_username = user.username
            current_email = user.email
            if current_username != username:
                #Function compares user input against allowed pattern.
                input_validation(username, "Username")
                check_if_exists('username', username, 'Username')
                user.username = username
            if current_email != email:
                #Function compares user input against allowed pattern.
                email_validation(email)
                check_if_exists('email', email, 'Email')
                user.email = email 
            user.first_name = first_name
            #Function compares user input against allowed pattern.
            input_validation(user.first_name, "First Name")
            user.last_name = last_name
            #Function compares user input against allowed pattern.
            input_validation(user.last_name, "Last Name")
            if password == '':
                pass
            else:
                #WeakPasswordRequirements-3 - START
                """Vulnerability"""
                #There is no check of length and complexity of a password.
                #WeakPasswordRequirements-3 - END
                #CompleteOmissionOfHashFunction-1 - START
                #CompleteOmissionOfHashFunction-1 - END
                #WeakHashFunction-1 - START
                #WeakHashFunction-1 - END
                #WeakHashFunctionWithSalt-1 - START
                """Fix"""
                password = ph.hash(password)
                #WeakHashFunctionWithSalt-1 - END 
                user.password = password
            db.session.commit()
            log_config.logger.info("User with username %s was sucessfully updated." % username, extra={'ip_address': request.remote_addr})
            flash("User has been updated.", 'success')
        except ValidationError:
            log_config.logger.error("User was not updated. Missing or invalid CSRF token.", extra={'ip_address': request.remote_addr})
            return Forbidden()
        except ValueError:
            return redirect(request.referrer)
        except Exception as e:
            log_config.logger.error("User was not successfully updated. Exception: %s" % e, extra={'ip_address': request.remote_addr})
            flash("Error occured, try again.", 'danger')
            return redirect(request.referrer)     
    return render_template("account/setting.html")
#StoredXSS-2 - END


#CSRF-3 - START
def delete_user():
    """ Vulnerability """
    if request.method == 'GET':
        try:
            id = current_user.id
            user = User.query.filter_by(id=id).first()
            if user is not None:
                #SensitiveDatawithinCookie-2 - START
                """Vulnerability"""
                session.pop('role')
                #SensitiveDatawithinCookie-2 - END
                session.pop('cart')
                session.pop('total')
                logout_user()
                db.session.delete(user)
                db.session.commit()
                db.session.close()
                log_config.logger.info("User with username %s was deleted." % user.username, extra={'ip_address': request.remote_addr})
                flash("User has been deleted.", 'danger')
                return redirect(url_for("auth.login"))
            else:
                flash("User doesn't exists.", 'danger')
                return redirect(request.referrer)
        except Exception as e:
            flash("Error occureed. Please try again.", 'danger')
            log_config.logger.error("User with username %s was not deleted. Exception: %s." % (user.username, e), extra={'ip_address': request.remote_addr})
            return redirect(request.referrer)
    return redirect(request.referrer)
#CSRF-3 - END


def orders():
    id = current_user.id
    order = Order.query.filter_by(user_id=id).all()
    return render_template("account/orders.html", orders=order)


#MaliciousFileUpload-1 - START  
"""Fix"""
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg'}
ALLOWED_MIME = {'image/png','image/jpg','image/jpeg', 'image/svg+xml'}

def check_extension(filename):
    """Function returns True if extension is all right, and False if otherwise."""
    filename_split = filename.split('.')
    if len(filename_split) != 2:
        return False
    else:
        extension = filename_split[-1]
        if extension in ALLOWED_EXTENSIONS:
            return True
        else:
            return False

def check_mime(picture):
    if mimetypes.guess_type(picture.filename)[0] in ALLOWED_MIME:
        return True
    else:
        return False

def upload_picture():
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            id = current_user.id
            user = User.query.filter_by(id=id).first()
            # check if the post request has the file part
            if 'profile_picture' not in request.files:
                flash('No file part', 'danger')
                print('No file part')
                return redirect(request.referrer)
            picture = request.files['profile_picture']
            #print("Filename: ", picture.filename)
            # If the user does not select a file, the browser submits an
            # empty file without a filename.
            if picture.filename == '':
                flash('No selected file', 'danger')
                print('No selected file')
                return redirect(request.referrer)
            filename_sanitized = secure_filename(picture.filename)
            print("Sanitized: ", filename_sanitized)
            if picture and check_extension(filename_sanitized) and check_mime(picture):
                file_to_store = str(uuid.uuid1())+filename_sanitized
                if user.profile_picture:
                    original_picture = user.profile_picture
                    print(original_picture)
                    path_to_original_picture = os.path.join(UPLOAD_FOLDER,original_picture)
                    print(path_to_original_picture)
                    os.remove(path_to_original_picture)
                user.profile_picture = file_to_store
                db.session.commit()
                upload_path = os.path.join(UPLOAD_FOLDER,file_to_store)
                picture.save(upload_path)
                flash('Profile picture has been updated.', 'success')
                log_config.logger.info("User %s successfully updated his profile picture." % user.username, extra={'ip_address': request.remote_addr})
                return redirect(request.referrer)
            else:
                return BadRequest()
        except ValidationError:
            log_config.logger.error("User was not updated. Missing or invalid CSRF token.", extra={'ip_address': request.remote_addr})
            return Forbidden()
        except Exception as e:
            flash("Error occureed. Please try again.",'danger')
            log_config.logger.error("User was not successfully updated. Exception: %s" % e, extra={'ip_address': request.remote_addr})
            return redirect(request.referrer) 
#MaliciousFileUpload-1 - END  

    
    