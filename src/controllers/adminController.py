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
        role_name = request.form.get("add_role")
        role = Role.query.filter_by(name=role_name).first()
        print(role)
        user = User(username=username, first_name=first_name, last_name=last_name, password=password)
        user.roles.append(role)
        db.session.add(user)
        db.session.commit()
        db.session.close()
        #-------------------------------------------Reflected XSS - START--------------------------------------------
        flash("User <strong>%s</strong> has sucesfully been added to the database." % (username))
        #-------------------------------------------Reflected XSS - END----------------------------------------------
        #This implements the  Post/Redirect/Get (PRG) to prevent data re-insertion when reload.
        return redirect(url_for('admin.add_user'))
    return render_template("admin/admin_panel_add.html")


def view_user():
    if request.method == 'POST':
        username = request.form.get("view_username")
        print(username)
        user = User.query.filter_by(username=username).first()
        print(user)
        if user is not None:
            return render_template("admin/admin_panel_view_and_update.html", user=user)
        else:
            flash("User <strong>%s</strong> doesn't exists." % (username))   
    return render_template("admin/admin_panel_view_and_update.html")


def update_user():
    if request.method == 'POST':
        id = request.form.get("edit_id")
        user = User.query.filter_by(id=id).first()
        user.username = request.form.get("edit_username")
        user.first_name = request.form.get("edit_fn")
        user.last_name = request.form.get("edit_ln")
        user.password = request.form.get("edit_password")

        new_role_name = request.form.get("edit_role")
        
        new_role = Role.query.filter_by(name=new_role_name).first()
        
        if new_role:
            if new_role not in user.roles:
                for user_role in user.roles:
                    user.roles.remove(user_role)
                user.roles.append(new_role)
                db.session.commit()
                db.session.close()
                flash("User has been updated.")
            else:
                flash("Error occured")
        else:
            flash("Error occured")

    return render_template("admin/admin_panel_view_and_update.html")



def delete_user():
    if request.method == 'POST':
        username = request.form.get("delete_username")
        print(username)
        user = User.query.filter_by(username=username).first()
        if user is not None:
            db.session.delete(user)
            db.session.commit()
            db.session.close()
            #-------------------------------------------Reflected XSS - START--------------------------------------------
            flash("User <strong>%s</strong> has been deleted." % (username))
        else:
            flash("User <strong>%s</strong> doesn't exists." % (username))
            #-------------------------------------------Reflected XSS - END----------------------------------------------
            return redirect(url_for('admin.delete_user'))
    
    return render_template("admin/admin_panel_delete.html")