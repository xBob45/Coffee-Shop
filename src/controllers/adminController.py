import functools

from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for)
from models.User import User, Role
from models.User import db
def admin_panel():
    return render_template("admin/admin_panel.html")


def add_user():
    if request.method == 'POST':
        username = request.form.get("add_username")
        first_name = request.form.get("add_fname")
        last_name = request.form.get("add_lname")
        password = request.form.get("add_pass")
        role_name = request.form.get("gridRadios")
        role = Role.query.filter_by(name=role_name).first()
        print(role)
        user = User(username=username, first_name=first_name, last_name=last_name, password=password)
        user.roles.append(role)
        db.session.add(user)
        db.session.commit()
        #-------------------------------------------Reflected XSS - START--------------------------------------------
        flash("User <strong>%s</strong> has sucesfully been added to the database." % (username))
        #-------------------------------------------Reflected XSS - END--------------------------------------------
        #This implements the  Post/Redirect/Get (PRG) to prevent data re-insertion when reload.
        return redirect(url_for('admin.add_user'))
    return render_template("admin/admin_panel_add.html")


def view_user():
    if request.method == 'POST':
        username = request.form.get("view_username")
        print(username)
        user = User.query.filter_by(username=username).first()
        print(user)
        if user:
            return render_template("admin/admin_panel_view_and_update.html", user=user)

    return render_template("admin/admin_panel_view_and_update.html")

def update_user():
    flash("User has been updated.")
    username = request.form.get("edit_username")
    print(username)
    return render_template("admin/admin_panel_view_and_update.html")

def delete_user():
    return render_template("admin/admin_panel_delete.html")