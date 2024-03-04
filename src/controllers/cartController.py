import datetime
from flask import session, request
from flask_login import  current_user
from src.models.User import db
from flask_wtf.csrf import validate_csrf, ValidationError
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for)
from src.models.User import db
from src.models.User import Product, Category, ProductCategory, Order, OrderItems
import src.log_config as log_config
from werkzeug.exceptions import Forbidden, BadRequest

def add_to_cart():
    if request.method == 'POST':
        validate_csrf(request.form.get('csrf_token'))
        product_id = request.form.get('product_id')
        quantity = request.form.get('quantity')
        product = db.session.query(Product).filter_by(id=product_id).first()
        if int(quantity) <= 0 or int(quantity) > product.stock:
            log_config.logging.error("User with username %s tried to put an invalid %s amount of product into the cart." % (current_user.username, quantity))
            return BadRequest() #This cannot happen unless a user manually tempers with the quantity value via Burp or whatever proxy.
        else:
            if product_id in session['cart'].keys():
                if session['cart'][product_id] + int(quantity) > product.stock:
                    session['cart'][product_id] += 0
                    log_config.logging.error("User with username %s tried to put an invalid amount of %s %s  pinto the cart." % (current_user.username, quantity, product.name))
                    flash("Invalid amount.", 'danger')
                else:
                    session['cart'][product_id] += int(quantity)
                    log_config.logging.info("User with username %s added amount of %s of product into the cart." % (current_user.username, quantity))
                    flash("Product added to cart.", 'success')
            else:
                if int(quantity) > product.stock:
                    session['cart'][product_id] = 0
                    log_config.logging.error("User with username %s tried to put an invalid %s amount of product into the cart." % (current_user.username, quantity))
                    flash("Invalid amount.", "danger")
                else:
                    session['cart'][product_id] = int(quantity)
                    log_config.logging.info("User with username %s added amount of %s of product into the cart." % (current_user.username, quantity))
                    flash("Product added to cart.", 'success')
            
            session['total'] += product.price*float(quantity)
            session.modified = True
            print(session)
            return redirect(request.referrer)

def delete_from_cart():
    if request.method == 'POST':
        validate_csrf(request.form.get('csrf_token'))
        product_id = request.form.get('product_id')
        product = db.session.query(Product).filter_by(id=product_id).first()
        quantity = session['cart'].get(product_id)
        session['cart'].pop(product_id)
        session['total'] -= (product.price*float(quantity))
        session.modified = True
        log_config.logging.info("User with username %s removed a product %s from the cart." % (current_user.username, product.name))
        flash("Product removed from the cart.", 'danger')
        return redirect(request.referrer)
    

def checkout():
    return render_template("order/cart.html")

def order_success():
    return render_template('order/order_success.html')

def create_order():
    if request.method == 'POST':
        print(len(session['cart']))
        if 'cart' in session and len(session['cart']) > 0:
            try:
                validate_csrf(request.form.get('csrf_token'))
                user_id = current_user.id
                date = datetime.datetime.now()
                total_price = round(session['total'],2)
                order = Order(user_id=user_id, date=date, total_price=total_price)
                db.session.add(order)
                for product_id, product_quantity in session['cart'].items():
                    print(product_id)
                    print(product_quantity)
                    product = db.session.query(Product).filter_by(id=product_id).first()
                    product_price = product.price * product_quantity
                    updated_stock = product.stock - product_quantity
                    product.stock = updated_stock
                    order_item = OrderItems(product_id=product_id, order_id=order.id, quantity=product_quantity,total=product_price)
                    db.session.add(order_item)
                db.session.commit()
                session['cart'] = {}
                session['total'] = 0
                return redirect(url_for("cart.order_success"))
            except ValidationError:
                log_config.logging.error("Missing or invalid CSRF token.")
            except Exception as e:
                log_config.logging.error("Error occured, try again")
                return BadRequest()
        return BadRequest()