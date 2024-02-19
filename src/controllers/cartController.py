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
        product = db.session.query(Product).filter_by(id=product_id).first()
        if product_id in session['cart'].keys():
            session['cart'][product_id] = session['cart'][product_id] + 1
        else:
            session['cart'][product_id] = 1
        
        session['total'] += product.price
        session.modified = True
        print(session)
        print(len(session['cart']))
        return redirect(request.referrer)

def delete_from_cart():
    if request.method == 'POST':
        validate_csrf(request.form.get('csrf_token'))
        product_id = request.form.get('product_id')
        product = db.session.query(Product).filter_by(id=product_id).first()
        quantity = session['cart'].get(product_id)
        session['cart'].pop(product_id)
        session['total'] -= (product.price*quantity)
        session.modified = True
        return redirect(request.referrer)
    

def checkout():
    return render_template("public/checkout.html")

def create_order():
    pass