import functools
from models.User import User, Role, UserRoles
from models.User import db
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
import os
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy.sql import text
import log_config

#SQLInjection-1 - START
#SQLInjection-1 - END

def signup():
    return render_template("auth/signup.html")

#InsufficientSessionInvalidation-1 - START
#InsufficientSessionInvalidation-1 - END