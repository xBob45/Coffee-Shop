import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash


bp = Blueprint('auth', __name__)
@bp.route("/login")
def login():
    return render_template("login.html")

@bp.route("/logout")
def logout():
    return redirect(url_for("auth.login"))

@bp.route("/signup")
def signup():
    return render_template("signup.html")