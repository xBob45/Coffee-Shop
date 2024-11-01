from src.controllers.cartController import add_to_cart, delete_from_cart, checkout, create_order, order_success
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for, abort)
import bleach
from flask_login import login_required


cart_blueprint = Blueprint('cart', __name__, url_prefix='/cart')

cart_blueprint.route('/add', methods=['POST'])(add_to_cart)
cart_blueprint.route('/delete', methods=['POST'])(delete_from_cart)
cart_blueprint.route('/checkout')(checkout)
cart_blueprint.route('/create_order',  methods=['POST'])(create_order)
cart_blueprint.route('/sucess')(order_success)


