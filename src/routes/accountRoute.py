from flask import Blueprint, redirect, url_for, session
from src.controllers.accountController import setting, update_user, delete_user
from flask_login import current_user

account_blueprint = Blueprint('account', __name__, url_prefix='/account')


account_blueprint.route('', methods=['GET'])(setting)
account_blueprint.route('/update', methods=['POST', 'GET'])(update_user)
account_blueprint.route('/delete', methods=['POST', 'GET'])(delete_user)