import functools
import os
from flask import (Blueprint, flash, g, redirect, render_template, render_template_string, request, session, url_for, send_file, abort)
from flask_login import current_user
import re
from urllib.request import urlopen
from urllib.error import URLError
from urllib.parse import urlparse
from src.models.User import Product, Category, ProductCategory
from src.models.User import db
from sqlalchemy.sql import text
import src.log_config as log_config
from werkzeug.exceptions import BadRequest, NotFound
import bleach

def home():
    return render_template("public/home.html")

def tips_and_tricks():
    return render_template("public/tips_and_tricks.html")

#PathTraversal-1 - START
"""Status: Fixed"""
#Description: CWE-35: Path Traversal -> https://cwe.mitre.org/data/definitions/35.html
def check_path(basedir, path, follow_symlinks=True):
    #Function checks for safety of a given path.
    # basedir - base dir against which 'path' is compared -> /home/vojta/Bakalarka/Coffee-Shop/src/guides
    # path - path that subject of control -> /home/vojta/Bakalarka/Coffee-Shop/src/guides/guide1.txt[OK] or /etc/passwd[NOT OK]
    # follow_symlinks - if 'True' function will also resolve symbolic links and checks if it safe.
    if follow_symlinks:
        #Resolves the symbolic links if any
        matchpath = os.path.realpath(path)
    else:
        matchpath = os.path.abspath(path)
         
    #Return 'True' or 'False' based on if base directory is the common directory between 'basedir' and 'matchpath'
    if ((basedir == os.path.commonpath((basedir, matchpath))) == True):
        return basedir == os.path.commonpath((basedir, matchpath))
    else:
        raise Exception

def check_file(file_name):
    allowed_pattern = r'^[guide0-9.txt]+$'
    if re.match(allowed_pattern, file_name):
        guides_dir = os.path.join(os.getcwd(), 'src', 'guides')
        requested_file = os.path.join(guides_dir, file_name)
        log_config.logger.info("User requested: %s" % bleach.clean(requested_file), extra={'ip_address': request.remote_addr})
        return guides_dir, requested_file
    else:
        return str(None), str(None)

def guide_reader():
    try:
        file_name = request.args.get('file_name')
        #FIRST MEASURE OF PROTECTION -> ALLOWED PATTERN
        guides_dir, requested_file = check_file(file_name)
        print(guides_dir)
        print(requested_file)
        #SECOND MEASURE OF PROTECTION -> PATH VALIDATION
        if check_path(guides_dir, requested_file):
            try:
                with open(requested_file, 'r') as file:
                    log_config.logger.info("User opened: %s" % bleach.clean(requested_file), extra={'ip_address': request.remote_addr})
                    content = file.read()
                return render_template("public/guide.html", content=content)
            except FileNotFoundError:
                #SSTI-1 - START
                """Status: Fixed"""
                #Description: CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine -> https://cwe.mitre.org/data/definitions/1336.html
                log_config.logger.error("User failed to open: %s" % bleach.clean(requested_file), extra={'ip_address': request.remote_addr})
                abort(400)
                #SSTI-1 - END
        else:
            #SSTI-1 - START
            """Status: Fixed"""
            #Description: CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine -> https://cwe.mitre.org/data/definitions/1336.html
            log_config.logger.error("User failed to open: %s" % bleach.clean(requested_file), extra={'ip_address': request.remote_addr})
            abort(400)
            #SSTI-1 - END
    except Exception:
        #SSTI-1 - START
        """Status: Fixed"""
        #Description: CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine -> https://cwe.mitre.org/data/definitions/1336.html
        log_config.logger.error("User failed to open: %s" % bleach.clean(requested_file), extra={'ip_address': request.remote_addr})
        abort(400)
        #SSTI-1 - END
#PathTraversal-1 - END


#SSRF-1 - START
"""Status: Vulnerable"""
#Description: CWE-918: Server-Side Request Forgery -> https://cwe.mitre.org/data/definitions/918.html
def development():
    #http://127.0.0.1:5000/development?url=file:///etc/passwd
    #http://127.0.0.1:5000/development?url=http://scanme.nmap.org:22
    if request.method == 'GET':
        url = request.args.get('url')
        if url is not None:
            print(url)
            try:
                response = urlopen(url)
                log_config.logger.info("User opened URL %s." % bleach.clean(url), extra={'ip_address': request.remote_addr})
                return response.read()
            except Exception as e:
                return str(e)
    return "This section is currently under development!"
#SSRF-1 - END

def product_info():
    product_id = request.args.get('id')
    #SQLi#2 - http://127.0.0.1:5000/product?id=1'; UPDATE products SET price = 0.01 WHERE id = 1; --
    #StoredXSS - http://127.0.0.1:5000/product?id=15'; UPDATE products SET name = '<script>alert(1333)</script>Ginger Tea' WHERE id = 15; --
    #SQLInjection2-1 - START
    """Status: Fixed"""
    #Description: CWE-89: SQL Injecttion -> https://cwe.mitre.org/data/definitions/89.html
    product = db.session.query(Product).filter_by(id=product_id).first()
    #SQLInjection2-1 - END
    db.session.commit()
    return render_template("public/product.html", product=product)

def coffee():
    coffee_category_id = db.session.query(Category).filter_by(name='coffee').first().id
    #print(coffee_category_id)
    coffee_products = db.session.query(Product).join(ProductCategory).filter_by(category_id=coffee_category_id).all()
    return render_template("public/coffee.html", products=coffee_products)

def tea():
    tea_category_id = db.session.query(Category).filter_by(name='tea').first().id
    #print(tea_category_id)
    tea_products = db.session.query(Product).join(ProductCategory).filter_by(category_id=tea_category_id).all()
    return render_template("public/tea.html", products=tea_products)

def accessories():
    accessories_category_id = db.session.query(Category).filter_by(name='accessories').first().id
    accessory_products = db.session.query(Product).join(ProductCategory).filter_by(category_id=accessories_category_id).all()
    return render_template("public/accessories.html", products=accessory_products)

