from flask import Blueprint, redirect, url_for, session, abort, request
from src.controllers.adminController import admin_panel, add_user, update_user, view_user, delete_user, execute_command
from flask_login import current_user
import src.log_config as log_config
import bleach
from werkzeug.exceptions import Forbidden, BadRequest
admin_blueprint = Blueprint('admin', __name__, url_prefix='/admin')


#SensitiveDatawithinCookie-3 - START
#SensitiveDatawithinCookie-3 - END

#ForcedBrowsing-1 - START
"""Status: Vulnerable"""
#Description: CWE-425: Forced Browsings -> https://cwe.mitre.org/data/definitions/425.html
"""Application doesn't perform any kind of check whether or not user who's trying to access these endpoints has 'admin' role."""
#ForcedBrowsing-1 - END

admin_blueprint.route('', methods=['GET'])(admin_panel)
admin_blueprint.route('/execute_command', methods=['POST', 'GET'])(execute_command)
admin_blueprint.route('/add', methods=['POST', 'GET'])(add_user)
admin_blueprint.route('/view', methods=['POST', 'GET'])(view_user)
admin_blueprint.route('/update', methods=['POST', 'GET'])(update_user)
admin_blueprint.route('/delete', methods=['POST', 'GET'])(delete_user)
#SSRF-2 - START
#SSRF-2 - END

