import functools
import os
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for, send_file, abort)
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

def home():
    return render_template("public/home.html")

def tips_and_tricks():
    return render_template("public/tips_and_tricks.html")

#PathTraversal-1 - START
def check_path(basedir, path, follow_symlinks=True):
    """Fix"""
    #Function checks for safety of a given path.
    # basedir - base dir against which 'path' is compared -> /home/vojta/Bakalarka/Coffee-Shop/src/guides
    # path - path that subject of control -> /home/vojta/Bakalarka/Coffee-Shop/src/guides/guide1.txt[OK] or /etc/passwd[NOT OK]
    # follow_symlinks - if 'True' function will also resolve symbolic links and checks if it safe.
    if follow_symlinks:
        #Resolves the symbolic links if any
        matchpath = os.path.realpath(path)
        #print(matchpath)
    else:
        matchpath = os.path.abspath(path)
        #print(matchpath)
            
    #Return 'True' or 'False' based on if base directory is the common directory between 'basedir' and 'matchpath'
    #print(basedir)
    print(basedir == os.path.commonpath((basedir, matchpath)))
    return basedir == os.path.commonpath((basedir, matchpath))

def guide_reader():
    file_name = request.args.get('file_name')
    #FIRST MEASURE OF PROTECTION -> ALLOWED PATTERN
    allowed_pattern = r'^[guide0-9.txt]+$'
    if re.match(allowed_pattern, file_name):
        guides_dir = os.path.join(os.getcwd(), 'src', 'guides')
        requested_file = os.path.join(guides_dir, file_name)
        log_config.logger.info("User %s requested: %s" % (current_user.username, requested_file), extra={'ip_address': request.remote_addr})

    #SECOND MEASURE OF PROTECTION -> PATH VALIDATION
        if check_path(guides_dir, requested_file):
            try:
                with open(requested_file, 'r') as file:
                    log_config.logger.info("User %s opened: %s" % (current_user.username, requested_file), extra={'ip_address': request.remote_addr})
                    content = file.read()
                return render_template("public/guide.html", content=content)
            except FileNotFoundError:
                log_config.logger.error("User %s failed to open: %s." % (current_user.username, requested_file), extra={'ip_address': request.remote_addr})
                return NotFound()
        else:
            log_config.logger.error("User %s failed to open: %s" % (current_user.username, requested_file), extra={'ip_address': request.remote_addr})
            return BadRequest()
    else:
        log_config.logger.error("User %s failed to open: %s" % (current_user.username, file_name), extra={'ip_address': request.remote_addr})
        return BadRequest()
#PathTraversal-1 - END


#SSRF-1 - START
#SSRF-1 - END

def product_info():
    product_id = request.args.get('id')
    #SQLi#2 - http://127.0.0.1:5000/product?id=1'; UPDATE products SET price = 0.01 WHERE id = 1; --
    #StoredXSS - http://127.0.0.1:5000/product?id=1'; UPDATE products SET name = '<script>alert(1)Cappuccino</script>' WHERE id = 1; --
    #SQLInjection2-1 - START
    """Vulnerability"""
    product = db.session.execute(text("SELECT * FROM products WHERE id = '%s'" % (product_id)))
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

