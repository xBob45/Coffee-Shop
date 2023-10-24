import functools

from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for)
from models.User import User
from models.User import db
def admin_panel():
    return render_template("admin/admin_panel.html")


def add_user():
    pass

def edit_user():

    username = request.form.get("edit_username")
    print(username)
    user = User.query.filter_by(username=username).first()
    print(user)
    if user:
        return render_template("admin/admin_panel.html", user=user)
    else:
        return render_template("admin/admin_panel.html")


def delete_user():
    pass