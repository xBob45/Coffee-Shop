import functools
from models.User import User, Role, UserRoles
from models.User import db
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from attacks import config
from dotenv import load_dotenv
import os
from flask_login import login_user, logout_user, login_required, current_user


SQLInjection = config.getboolean('attacks', 'SQLInjection')
ReflectedXSS = config.getboolean('attacks', 'ReflectedXSS')
SensitiveInformationDisclosure = config.getboolean('attacks', 'SensitiveInformationDisclosure')
InsufficientSessionInvalidation = config.getboolean('attacks', 'InsufficientSessionInvalidation')
SensitiveDatawithinCookie = config.getboolean('attacks', 'SensitiveDatawithinCookie')

def login():
    if SQLInjection == False:
        if request.method == 'POST':
            username = request.form.get('username')
            print(username)
            password = request.form.get('password')
            print(password)
            remember = True if request.form.get('remember') else False
            user = User.query.filter_by(username=username).first()
            if user is None:
                if ReflectedXSS == True and SensitiveInformationDisclosure == True:
                    #---------------------------------------------A03 - Reflected XSS - START----------------------------------------------
                    #-------------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - START-----------------------------------  
                    flash("<strong>%s</strong> is not in out database, try again." % (username))
                    #---------------------------------------------A03 - Reflected XSS - END------------------------------------------------
                    #-------------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - END-------------------------------------
                elif ReflectedXSS == False and SensitiveInformationDisclosure == True:
                    #-------------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - START----------------------------------- 
                    flash("Wrong username, try again.")
                    #-------------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - END-------------------------------------
                elif ReflectedXSS == True and SensitiveInformationDisclosure == False:
                    #----------------------------------------------A03 - Reflected XSS - START--------------------------------------------- 
                    flash("Incorrect username %s or password, try again.")
                    #----------------------------------------------A03 - Reflected XSS - END----------------------------------------------- 
                else:
                    flash("Wrong credentials, try again.")
            elif user.password != password:
                if ReflectedXSS == True and SensitiveInformationDisclosure == True:
                    #-------------------------------------------A03 - Reflected XSS - START--------------------------------------------
                    #-----------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - START---------------------------------  
                    flash("Wrong password for <strong>%s</strong> user, try again." % (username))
                    #-------------------------------------------A03 - Reflected XSS - END----------------------------------------------
                    #-----------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - END-----------------------------------
                elif ReflectedXSS == False and SensitiveInformationDisclosure == True:
                    #-----------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - START--------------------------------- 
                    flash("Wrong password, try again.")
                    #-----------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - END----------------------------------- 
                elif ReflectedXSS == True and SensitiveInformationDisclosure == False:
                    #--------------------------------------------A03 - Reflected XSS - START------------------------------------------- 
                    flash("Incorrect username %s or password, try again.")
                    #--------------------------------------------A03 - Reflected XSS - END--------------------------------------------- 
                else:
                        flash("Wrong credentials, try again.")
            else:
                # Perform the login action or redirect to the home page
                login_user(user, remember=remember)
                if SensitiveDatawithinCookie == True:
                #----------------------------------------------A04 - Sensitive Data within a Cookie - START--------------------------------------------
                #Fetch a role from DB
                    user_roles = db.session.query(Role.name).join(UserRoles, Role.id == UserRoles.role_id).filter(UserRoles.user_id == user.id).one()
                    for role in user_roles:
                        session['role'] = role
                        break
                 #----------------------------------------------A04 - Sensitive Data within a Cookie - END----------------------------------------------
                else:
                    pass
                return redirect(url_for('home.home')) 

        # If the request method is GET or the login was unsuccessful, render the login form
        return render_template('auth/login.html', ReflectedXSS=ReflectedXSS)

   
    else:
        #----------------------------------------------------A03 - SQL Injection - START---------------------------------------------------
        import psycopg2
        from urllib.parse import urlparse

        params = urlparse(os.environ["SQLALCHEMY_DATABASE_URI"])
        #This extracts parameters from SQLALCHEMY_DATABASE_URI and makes connection accordingly.
        connection = {'user': params.username, 'password': params.password, 'host': params.hostname, 'port': params.port, 'database': params.path.lstrip('/')}
        conn = psycopg2.connect(**connection)
        
        username = ''
        #admin
        #' OR 1=1 --
        if request.method == 'POST':
            #print("SQL Injection: %s" % SQLInjection)
            username = request.form.get('username')
            #print(username)
            password = request.form.get('password')
            #print(password)
            remember = True if request.form.get('remember') else False
            cursor = conn.cursor()
            cursor.execute("SELECT EXISTS (SELECT 1 FROM users WHERE username = '%s')" % (username))
            username_checks = cursor.fetchone()[0]
            #print(username_checks)
            if username_checks:
                #print("SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password))
                cursor.execute("SELECT *FROM users WHERE username = '%s' AND password = '%s'" % (username, password))
                user_data = cursor.fetchone()
                #print(user_data)
                if user_data:
                    #Turning retrieved user data into User object because Flas-Login requires it.
                    user = User(id=user_data[0], username=user_data[1], first_name=user_data[2], last_name=user_data[3],
                            password=user_data[4], salt=user_data[5])
                    login_user(user, remember=remember)
                    if SensitiveDatawithinCookie == True:
                        #----------------------------------------------A04 - Sensitive Data within a Cookie - START--------------------------------------------
                        #Fetch a role from DB (IDK why fetching it using 'current_user' doesn't work)
                        cursor.execute("SELECT roles.name FROM roles JOIN user_roles ON roles.id = user_roles.role_id WHERE user_roles.user_id = %s", (user.id,))
                        user_roles = cursor.fetchone()
                        for role in user_roles:
                            session['role'] = role
                            break
                        #----------------------------------------------A04 - Sensitive Data within a Cookie - END----------------------------------------------
                    else:
                        pass
                    cursor.close()
                    conn.close()
                    return redirect(url_for('home.home'))
                else:
                    if ReflectedXSS == True and SensitiveInformationDisclosure == True:
                        #-------------------------------------------A03 - Reflected XSS - START--------------------------------------------
                        #-----------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - START---------------------------------  
                        flash("Wrong password for <strong>%s</strong> user, try again." % (username))
                        #-------------------------------------------A03 - Reflected XSS - END----------------------------------------------
                        #-----------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - END-----------------------------------
                    elif ReflectedXSS == False and SensitiveInformationDisclosure == True:
                        #-----------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - START--------------------------------- 
                        flash("Wrong password, try again.")
                        #-----------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - END----------------------------------- 
                    elif ReflectedXSS == True and SensitiveInformationDisclosure == False:
                        #--------------------------------------------A03 - Reflected XSS - START------------------------------------------- 
                        flash("Incorrect username %s or password, try again.")
                        #--------------------------------------------A03 - Reflected XSS - END--------------------------------------------- 
                    else:
                        flash("Wrong credentials, try again.")
            else:
                if ReflectedXSS == True and SensitiveInformationDisclosure == True:
                    #---------------------------------------------A03 - Reflected XSS - START----------------------------------------------
                    #-------------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - START-----------------------------------  
                    flash("<strong>%s</strong> is not in out database, try again." % (username))
                    #---------------------------------------------A03 - Reflected XSS - END------------------------------------------------
                    #-------------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - END-------------------------------------
                elif ReflectedXSS == False and SensitiveInformationDisclosure == True:
                    #-------------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - START----------------------------------- 
                    flash("Wrong username, try again." % (username))
                    #-------------------------------------A04 - SENSITIVE INFORMATION DISCLOSURE - END-------------------------------------
                elif ReflectedXSS == True and SensitiveInformationDisclosure == False:
                    #----------------------------------------------A03 - Reflected XSS - START--------------------------------------------- 
                    flash("Incorrect username %s or password, try again.")
                    #----------------------------------------------A03 - Reflected XSS - END----------------------------------------------- 
                else:
                    flash("Wrong credentials, try again.")

        return render_template('auth/login.html') 
        #----------------------------------------------------A03 - SQL Injection - END-----------------------------------------------------

def signup():
    return render_template("auth/signup.html")

def logout():
    if InsufficientSessionInvalidation == True:
        #----------------------------------A07 - INSUFFICIENT SESSION INVALIDATION - START----------------------------------
        flash("You were logged out.")
        #----------------------------------A07 - INSUFFICIENT SESSION INVALIDATION - END----------------------------------
    else:
        try:
            session.pop('role')
        except KeyError:
            pass
        logout_user()
        flash("You were logged out.")

    return redirect(url_for("auth.login"))