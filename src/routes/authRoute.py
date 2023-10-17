from flask import Blueprint
from controllers.authController import login, logout, signup


auth_blueprint = Blueprint('auth', __name__)

#auth.route('/', methods=['GET'])(index)

auth_blueprint.route('/login', methods=['POST', 'GET'])(login)
auth_blueprint.route('/signup', methods=['POST', 'GET'])(signup)
#auth.route('auth/logout', methods=['POST'])(logout)

