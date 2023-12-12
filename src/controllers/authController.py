import functools
from models.User import User, Role
from models.User import db
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
import os
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy.sql import text
from psycopg2.errors import UniqueViolation
from sqlalchemy.exc import IntegrityError
import log_config
import re

#SQLInjection-1 - START
#SQLInjection-1 - END

def signup():
    if request.method == 'POST':
        try:
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            email = request.form.get('email')
            username= request.form.get('username')
            password = request.form.get('password')
            check_if_exists('email', email, 'Email')
            check_if_exists('username', username, 'Username')
            check_for_password_complexity(password)
            user = User(role_id=2, username=username, email=email, first_name=first_name, last_name=last_name, password=password)
            db.session.add(user)
            db.session.commit()
            db.session.close()
            flash("Account has been sucesfully created.")
            return redirect(url_for("auth.login"))
        except (ValueError, Exception):
            return redirect(request.referrer)
    return render_template("auth/signup.html")


#InsufficientSessionInvalidation-1 - START
#InsufficientSessionInvalidation-1 - END


def check_for_password_complexity(password):
    password_pattern = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$"
    if not re.match(password_pattern, password):
        flash("Insufficiently complex password!\nPlease try again!\nRemeber password has to be at least 10 characters long and contains some special cahracters\n!#$%&*_^ and digits.")
        raise ValueError

def check_if_exists(model_field, value, field):
    exists = User.query.filter_by(**{model_field: value}).first()
    if exists:
        flash("%s already exists. Please try again!" % field)
        raise ValueError
        