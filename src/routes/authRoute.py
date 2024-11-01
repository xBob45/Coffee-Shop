from flask import Blueprint, abort
from src.controllers.authController import login, logout, signup

auth_blueprint = Blueprint('auth', __name__)

auth_blueprint.route('/login', methods=['POST', 'GET'])(login)
auth_blueprint.route('/signup', methods=['POST', 'GET'])(signup)
auth_blueprint.route('/logout', methods=['POST', 'GET'])(logout)

