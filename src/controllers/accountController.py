from flask import (flash, redirect, render_template, request, abort, url_for, jsonify, session)
from models.User import User, Role
from models.User import db
from flask_login import logout_user, current_user
from controllers.authController import check_for_password_complexity, check_if_exists

#IDOR-3 - START
def setting():
    """Vulnerability"""
    id = request.args.get("id")
    user = User.query.filter_by(id=id).first()
    return render_template("account/setting.html", user=user)
#IDOR-3 - END

def update_user():
    if request.method == 'POST':
        id = request.form.get("edit_id")
        username = request.form.get("edit_username")
        email = request.form.get("edit_email")
        first_name = request.form.get("edit_fn")
        last_name = request.form.get("edit_ln")
        password = request.form.get("edit_password")

        user = User.query.filter_by(id=id).first()
        current_username = user.username
        current_email = user.email
        try:
            if current_username != username:
                check_if_exists('username', username, 'Username')
                user.username = username
            if current_email != email:
                check_if_exists('email', email, 'Email')
                user.email = email 
            user.first_name = first_name
            user.last_name = last_name
            user.password = password
            #WeakPasswordRequirements-3 - START
            """Vulnerability"""
            #There is no check of length and complexity of a password.
            #WeakPasswordRequirements-3 - END
            db.session.commit()
            flash("User has been updated.")
        except (ValueError, Exception):
            redirect(request.referrer)
    return redirect(request.referrer)

#CSRF-4 - START
def delete_user():
    """Vulnerability"""
    if request.method == 'GET':
        id = current_user.id
        print(id)
        user = User.query.filter_by(id=id).first()
        if user is not None:
            logout_user()
            db.session.delete(user)
            db.session.commit()
            db.session.close()
            return redirect(url_for("auth.login"))
        else:
            flash("User doesn't exists.")
            return redirect(request.referrer)
    return redirect(request.referrer)
#CSRF-4 - END


def upload_picture():
    pass