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
from werkzeug.exceptions import Forbidden, BadRequest, RequestEntityTooLarge, UnsupportedMediaType
from werkzeug.utils import secure_filename
import uuid
import os
import mimetypes
import bleach



load_dotenv()
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER")

#IDOR-3 - START
"""Status: Fixed"""
#Description: CWE-639: Authorization Bypass Through User-Controlled Key -> https://cwe.mitre.org/data/definitions/639.html
def setting():
    return render_template("account/setting.html")
#IDOR-3 - END

#StoredXSS-2 - START
"""Status: Vulnerable"""
#Description: CWE-79: Cross-site Scripting -> https://cwe.mitre.org/data/definitions/79.html
def update_user():
    #referrer_url = request.referrer
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            #IDOR-4 - START
            """Status: Fixed"""
            #Description: CWE-639: Authorization Bypass Through User-Controlled Key -> https://cwe.mitre.org/data/definitions/639.html
            id = current_user.id
            #IDOR-4 - END
            username = request.form.get("edit_username")
            email = request.form.get("edit_email")
            first_name = request.form.get("edit_fn")
            last_name = request.form.get("edit_ln")
            password = request.form.get("edit_password")
            user = User.query.filter_by(id=id).first()
            current_username = user.username
            current_email = user.email
            if current_username != username:
                #User input is not beeing validated in any way.
                check_if_exists('username', username, 'Username')
                user.username = username
            if current_email != email:
                #User input is not beeing validated in any way.
                check_if_exists('email', email, 'Email')
                user.email = email 
            #User input is not beeing validated in any way.     
            user.first_name = first_name
            #User input is not beeing validated in any way.
            user.last_name = last_name
            if password == '':
                pass
            else:
                #WeakPasswordRequirements-3 - START
                """Status: Vulnerable"""
                #Description: CWE-521: Weak Password Requirements -> https://cwe.mitre.org/data/definitions/521.html
                #There is no check of length and complexity of a password.
                #WeakPasswordRequirements-3 - END
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
            db.session.commit()
            log_config.logger.info("User with username %s was sucessfully updated." % bleach.clean(username), extra={'ip_address': request.remote_addr})
            flash("User has been updated.", 'success')
            return redirect(request.referrer)  
        except ValidationError:
            log_config.logger.error("User was not updated. Missing or invalid CSRF token.", extra={'ip_address': request.remote_addr})
            abort(400)
        except ValueError:
            return redirect(request.referrer)
        except Exception as e:
            log_config.logger.error("User was not sucessfully updated. Exception: %s" % e, extra={'ip_address': request.remote_addr})
            flash("Error occured, try again.", 'danger')
            return redirect(request.referrer)
    return redirect(request.referrer)
#StoredXSS-2 - END


#CSRF-3 - START
"""Status: Fixed"""
#Description: CWE-352: Cross-Site Request Forgery -> https://cwe.mitre.org/data/definitions/352.html
def delete_user():
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            id = current_user.id
            user = User.query.filter_by(id=id).first()
            if user is not None:
                #SensitiveDatawithinCookie-2 - START
                """Status: Fixed"""
                #Description: CWE-315: Cleartext Storage of Sensitive Information in a Cookie -> https://cwe.mitre.org/data/definitions/315.html
                """Since 'role' is not a part of a session, there is no need to do anything at this point."""
                #SensitiveDatawithinCookie-2 - END
                session.pop('cart')
                session.pop('total')
                logout_user()
                db.session.delete(user)
                db.session.commit()
                db.session.close()
                log_config.logger.info("User with ID %s was deleted." % bleach.clean(user.username), extra={'ip_address': request.remote_addr})
                flash("User has been deleted.", 'danger')
                return redirect(url_for("auth.login"))
            else:
                flash("User doesn't exists.", 'danger')
                return redirect(request.referrer)
        except ValidationError:
            log_config.logger.error("User was not deleted. Missing or invalid CSRF token.", extra={'ip_address': request.remote_addr})
            abort(400)
        except Exception as e:
            flash("Error occureed. Please try again.", 'danger')
            log_config.logger.error("User with ID %s was not deleted. Exception: %s." % (bleach.clean(user.username), e), extra={'ip_address': request.remote_addr})
            return redirect(request.referrer)
    return redirect(request.referrer)
#CSRF-3 - END


def orders():
    id = current_user.id
    order = Order.query.filter_by(user_id=id).all()
    return render_template("account/orders.html", orders=order)


#MaliciousFileUpload-1 - START  
"""Status: Fixed"""
#Description: CWE-434: Unrestricted Upload of File with Dangerous Type -> https://cwe.mitre.org/data/definitions/434.html
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
                log_config.logger.info("User %s successfully updated his profile picture." % bleach.clean(user.username), extra={'ip_address': request.remote_addr})
                return redirect(request.referrer)
            else:
                raise UnsupportedMediaType()
        except ValidationError:
            log_config.logger.error("User was not updated. Missing or invalid CSRF token.", extra={'ip_address': request.remote_addr})
            abort(400)
        except RequestEntityTooLarge:
            log_config.logger.error("User %s tried to upload file that exceeded allowed length limit." % bleach.clean(user.username), extra={'ip_address': request.remote_addr})
            abort(413)
        except UnsupportedMediaType:
            abort(415)
        except Exception as e:
            flash("Error occureed. Please try again.",'danger')
            log_config.logger.error("User was not successfully updated. Exception: %s" % e, extra={'ip_address': request.remote_addr})
            return redirect(request.referrer) 
#MaliciousFileUpload-1 - END  

    
    