import functools
from models.User import User
from models.User import db

from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
import configparser
from flask_login import login_user, logout_user, login_required

config = configparser.ConfigParser()
config.read('attacks.ini')

def login():
    """if request.method == 'POST':
        username = request.form.get('username')
        print(username)
        password = request.form.get('password')
        print(password)
        remember = True if request.form.get('remember') else False
        user = User.query.filter_by(username=username).first()
        if user is None or user.password != password:
            flash('Please check your login details and try again.')
        else:
            # Perform the login action or redirect to the home page
            login_user(user, remember=remember)
            return redirect(url_for('home.home')) 

    # If the request method is GET or the login was unsuccessful, render the login form
    return render_template('auth/login.html')"""

    """if user:
        roles = user.roles  # This will give you a list of roles associated with the user
        for role in roles:
            print(role.name)  # Print the name of each role"""
    #----------------------------------SQL Injection - START----------------------------------
    import psycopg2
    conn = psycopg2.connect(host='localhost',database='postgres', user='postgres', password='postgres')
    #admin
    #' OR 1=1 --
    if request.method == 'POST':
        username = request.form.get('username')
        print(username)
        password = request.form.get('password')
        print(password)
        remember = True if request.form.get('remember') else False
        cursor = conn.cursor()
        cursor.execute("SELECT EXISTS (SELECT 1 FROM users WHERE username = '%s')" % (username))
        username_checks = cursor.fetchone()[0]
        print(username_checks)
        if username_checks:
            cursor.execute("SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password))
            user_data = cursor.fetchone()
            print(user_data)
            if user_data:
                #Turning retrieved user data into User object because Flas-Login requires it.
                user = User(id=user_data[0], username=user_data[1], first_name=user_data[2], last_name=user_data[3],
                        password=user_data[4], active=user_data[5], salt=user_data[6])
                login_user(user, remember=remember)
                cursor.close()
                conn.close()
                return redirect(url_for('home.home'))
        else:
            #flash("Wrong credentials, please try again.")
            #----------------------------------SENSITIVE INFORMATION EXPOSURE - START----------------------------------
            #----------------------------------Reflected XSS - START----------------------------------
            flash("<strong>%s</strong> is not in out database, try again." % (username))
            return render_template('auth/login.html')

    #flash("Wrong credentials, please try again.")    
    flash("Wrong password for <strong>%s</strong> user, try again." % (username))
    #----------------------------------Reflected XSS - START----------------------------------
    #----------------------------------SENSITIVE INFORMATION EXPOSURE - END----------------------------------  
    return render_template('auth/login.html') 
    #----------------------------------SQL Injection - END----------------------------------






def signup():
    return render_template("auth/signup.html")

def logout():
    logout_user()
    flash("You were logged out.")
    return redirect(url_for("auth.login"))