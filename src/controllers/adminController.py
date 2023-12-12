import functools
from flask import (flash, redirect, render_template, request, abort, url_for, jsonify)
from models.User import User, Role
from models.User import db
import subprocess


#OSCommandInjection-1 - START
#OSCommandInjection-1 - END

def admin_panel():
    """Function renders main page of admin panel."""
    try:
        postgre = subprocess.check_output(['pg_isready'], universal_newlines=True, stderr=subprocess.STDOUT, shell=True)
        if 'accepting connections' in postgre:
            postgre_message = "PostgreSQL is running correctly."
        else:
            postgre_message = "PostgreSQL is not accepting connections."
    except:
        postgre_message = "PostgreSQL is not accepting connections."
    try:        
        apache = subprocess.check_output(['systemctl status apache2'], universal_newlines=True, stderr=subprocess.STDOUT, shell=True)
        if 'running' in apache:
            apache_message = "Apache is running correctly."
        else:
            apache_message = "Apache down"
    except:
        apache_message = "Apache is down"
    try:
        log_file = "../app.log"
        with open(log_file, 'r') as file:
            log_content = file.read()
            file.close()
    except:
        log_content = "Error occured while loading the file."
    return render_template("admin/admin_panel.html", postgre_message=postgre_message, apache_message=apache_message, log_content=log_content)

def add_user():
    """Functionallows to add new entry to User table."""
    if request.method == 'POST':
        username = request.form.get("add_username")
        email = request.form.get("email")
        first_name = request.form.get("add_fname")
        last_name = request.form.get("add_lname")
        password = request.form.get("add_pass")
        role_name = request.form.get("add_role")
        role = Role.query.filter_by(name=role_name).first().id
        #print(role)
        user = User(role_id=role, username=username, email=email, first_name=first_name, last_name=last_name, password=password)
        db.session.add(user)
        db.session.commit()
        db.session.close()
        flash("User has sucesfully been added to the database.")
        #This implements the  Post/Redirect/Get (PRG) to prevent data re-insertion when reload.
        return redirect(url_for('admin.add_user'))
    return render_template("admin/admin_panel_add.html")

def view_user():
    """Function allows to view an arbitrary entry in User table."""
    if request.method == 'POST':
        username = request.form.get("view_username")
        print(username)
        user = User.query.filter_by(username=username).first()
        print(user)
        if user is not None:
            return render_template("admin/admin_panel_view_and_update.html", user=user)
        else:
            flash("User doesn't exists.")   
    return render_template("admin/admin_panel_view_and_update.html")

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
            user.role_id = int(request.form.get("edit_role"))
            db.session.commit()
            flash("User has been updated.")
        except:
            flash("Error occurred")
    return redirect(request.referrer)

def delete_user():
    """Function allows to delete arbitrary entry from User table."""
    if request.method == 'POST':
        username = request.form.get("delete_username")
        print(username)
        user = User.query.filter_by(username=username).first()
        if user is not None:
            db.session.delete(user)
            db.session.commit()
            db.session.close()
            flash("User has been deleted.")
        else:
            flash("User doesn't exists.")
            return redirect(url_for('admin.delete_user'))
    return render_template("admin/admin_panel_delete.html")