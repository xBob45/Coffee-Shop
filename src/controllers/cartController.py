from flask import session, request
from src.models.User import db
from flask_wtf.csrf import validate_csrf, ValidationError
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for)
from src.models.User import Product, Category, ProductCategory

def add_to_cart():
    #session.pop('cart')
    if request.method == 'POST':
        validate_csrf(request.form.get('csrf_token'))
        product_id = request.form.get('product_id')
        if product_id in session['cart'].keys():
            print(True)
            print(session['cart'][product_id])
            session['cart'][product_id] = session['cart'][product_id] + 1
        else:
            session['cart'][product_id] = 1
        session.modified = True
        print(session)
        return redirect(request.referrer)


    
