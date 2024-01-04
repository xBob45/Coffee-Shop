import functools
import os
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for, send_file, abort)
import re
from urllib.request import urlopen
from urllib.error import URLError
from urllib.parse import urlparse
from models.User import Product, Category, ProductCategory
from models.User import db
from sqlalchemy.sql import text

def home():
    return render_template("public/home.html")

def tips_and_tricks():
    return render_template("public/tips_and_tricks.html")

#PathTraversal-1 - START
def guide_reader():
    """Vulnerability"""
    #../../../../../../etc/passwd
    #Extracts file from 'file_name' parameter
    file_name = request.args.get('file_name')

    #Creates a path by concatenating '/home/vojta/Bakalarka/Coffee-Shop/src/' and 'guides'
    guides_dir = os.path.join(os.getcwd(), 'guides')

    #Creates path to the requested file by concatenating '/home/vojta/Bakalarka/Coffee-Shop/src/guides' and '<file_name>'
    requested_file = os.path.join(guides_dir, file_name)
        
    #Opens the file located at the location of 'requested_file' for reading ('r')
    with open(requested_file, 'r') as file:
        content = file.read()
    
    return render_template("public/guide.html", content=content)
#PathTraversal-1 - END


#SSRF-1 - START
#SSRF-1 - END

def product_info():
    product_id = request.args.get('id')
    #http://127.0.0.1:5000/product?id=1'; UPDATE products SET price = 0.01 WHERE id = 1; --

    product = db.session.execute(text("SELECT * FROM products WHERE id = '%s'" % (product_id)))
    db.session.commit()
    return render_template("public/example.html", content=product)

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
    return render_template("public/accessories.html")