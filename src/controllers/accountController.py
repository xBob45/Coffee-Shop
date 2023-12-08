from flask import (flash, redirect, render_template, request, abort, url_for, jsonify, session)
from models.User import User, Role
from models.User import db

def setting():
    return render_template("account/setting.html")

def update_user():
    if request.method == 'POST':
        id = request.form.get("edit_id")
        user = User.query.filter_by(id=id).first()
        user.username = request.form.get("edit_username")
        user.email = request.form.get("edit_email")
        user.first_name = request.form.get("edit_fn")
        user.last_name = request.form.get("edit_ln")
        user.password = request.form.get("edit_password")

        #Update a user with new values
        try:
            user.username = request.form.get("edit_username")
            user.email = request.form.get("edit_email")
            user.first_name = request.form.get("edit_fn")
            user.last_name = request.form.get("edit_ln")
            user.password = request.form.get("edit_password")
            db.session.commit()
            flash("User has been updated.")
        except:
            flash("Error occurred")
    return redirect(request.referrer)

def delete_user():
    """Function allows to delete arbitrary entry from User table."""
    if request.method == 'POST':
        id = request.form.get("delete_id")
        print(id)
        user = User.query.filter_by(id=id).first()
        if user is not None:
            db.session.delete(user)
            db.session.commit()
            db.session.close()
            flash("User has been deleted.")
        else:
            flash("User doesn't exists.")
            return redirect(request.referrer)
    return redirect(request.referrer)

def upload_picture():
    pass