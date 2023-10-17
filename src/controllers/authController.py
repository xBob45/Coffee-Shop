import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash


def login():
    return render_template("auth/login.html")

def signup():
    return render_template("auth/signup.html")

def logout():
    return redirect(url_for("auth.login"))