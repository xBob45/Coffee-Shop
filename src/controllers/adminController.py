import functools
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify)
from models.User import User, Role, UserRoles
from models.User import db
import subprocess


def execute_command():
    command = request.args.get('command')
    result = subprocess.check_output([command], universal_newlines=True, stderr=subprocess.STDOUT, shell=True)
    return jsonify(result=result)
    


def admin_panel():
    """Function renders main page of admin panel."""
    try:
        result = subprocess.check_output(['pg_isready'], universal_newlines=True, stderr=subprocess.STDOUT, shell=True)
        if 'accepting connections' in result:
            message = "PostgreSQL is running correctly."
        else:
            message = "PostgreSQL is not accepting connections."

    except:
        message = "PostgreSQL is not accepting connections."

    return render_template("admin/admin_panel.html", result=message)



def add_user():
    """Functionallows to add new entry to User table."""
    if request.method == 'POST':
        username = request.form.get("add_username")
        first_name = request.form.get("add_fname")
        last_name = request.form.get("add_lname")
        password = request.form.get("add_pass")
        role_name = request.form.get("add_role")
        role = Role.query.filter_by(name=role_name).first()
        print(role)
        user = User(username=username, first_name=first_name, last_name=last_name, password=password)
        user.roles.append(role)
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
        user.first_name = request.form.get("edit_fn")
        user.last_name = request.form.get("edit_ln")
        user.password = request.form.get("edit_password")

        #1) Take the role id from the HTML form
        new_role_id = int(request.form.get("edit_role"))

        #2) Fetch asociation (line) of user-user's role from user_role table based on user's ID
        user_role = UserRoles.query.filter_by(user_id=id).first()

        if user_role:
            user_role.role_id = new_role_id  # Update the role_id
            db.session.commit()
            flash("User has been updated.")
        else:
            flash("Error occurred")

    return render_template("admin/admin_panel_view_and_update.html")


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