from flask import (flash, redirect, render_template, request, abort, url_for, jsonify, session)
from src.models.User import User, Role, Order, OrderItems, Product
from src.models.User import db
from flask_login import logout_user, current_user
from src.controllers.authController import check_for_password_complexity, check_if_exists, input_validation, email_validation, ph
import src.log_config as log_config
from flask_wtf.csrf import validate_csrf, ValidationError
from hashlib import md5
from passlib.hash import md5_crypt
from werkzeug.exceptions import Forbidden

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
            log_config.logging.info("User with username %s has been sucessfully updated." % username)
            flash("User has been updated.")
        except ValidationError:
            log_config.logging.error("User has not beed updated. Missing or invalid CSRF token.")
            return Forbidden()
        except ValueError:
            return redirect(request.referrer)
        except Exception as e:
            log_config.logging.error("User has not been sucessfully updated.\nException: %s" % e)
            flash("Error occured, try again.")
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
            user_id = user.id
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
                log_config.logging.info("User with username %s has been deleted." % username)
                return redirect(url_for("auth.login"))
            else:
                flash("User doesn't exists.")
                return redirect(request.referrer)
        except Exception as e:
            flash("Error occureed. Please try again.")
            log_config.logging.error("User with username %s has not been deleted.\nException: %s." % (username, e))
            return redirect(request.referrer)
    return redirect(request.referrer)
#CSRF-3 - END


def orders():
    id = current_user.id
    order = Order.query.filter_by(user_id=id).all()
    return render_template("account/orders.html", orders=order)

def upload_picture():
    pass