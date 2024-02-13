from src.controllers.cartController import add_to_cart, delete_from_cart
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for)

cart_blueprint = Blueprint('cart', __name__, url_prefix='/cart')
cart_blueprint.route('/add', methods=['POST'])(add_to_cart)
cart_blueprint.route('/delete', methods=['POST'])(delete_from_cart)