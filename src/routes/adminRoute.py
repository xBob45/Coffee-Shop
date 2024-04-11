from flask import Blueprint, redirect, url_for, session, abort, request
from src.controllers.adminController import admin_panel, add_user, update_user, view_user, delete_user, execute_command
from flask_login import current_user
import src.log_config as log_config
from werkzeug.exceptions import Forbidden, BadRequest
admin_blueprint = Blueprint('admin', __name__, url_prefix='/admin')


#SensitiveDatawithinCookie-3 - START
"""Status: Vulnerable"""
#Description: Cookie containes user's role in the application. Via cookie manipulation an attacker can elevate it's privileges.
@admin_blueprint.before_request
def check_if_admin():
    try:
        if current_user.is_authenticated:
            role = session.get('role')
            if role == 'admin':
                log_config.logger.info("User %s accessed the admin panel." % current_user.username, extra={'ip_address': request.remote_addr})
                return #If everything is OK, let user proceed.
            else:
                log_config.logger.error("User %s tried to access the admin panel and was blocked due to insufficient privileges." % current_user.username, extra={'ip_address': request.remote_addr})
                raise Forbidden()
        return redirect(url_for('auth.login'))
    except Forbidden:
        abort(403)
    except Exception as e:
        log_config.logger.error("Error occured while accessing the admin panel. Exception: %s" % e, extra={'ip_address': request.remote_addr})
        abort(400)
#SensitiveDatawithinCookie-3 - END

#ForcedBrowsing-1 - START
#ForcedBrowsing-1 - END

admin_blueprint.route('', methods=['GET'])(admin_panel)
admin_blueprint.route('/execute_command', methods=['POST', 'GET'])(execute_command)
admin_blueprint.route('/add', methods=['POST', 'GET'])(add_user)
admin_blueprint.route('/view', methods=['POST', 'GET'])(view_user)
admin_blueprint.route('/update', methods=['POST', 'GET'])(update_user)
admin_blueprint.route('/delete', methods=['POST', 'GET'])(delete_user)
#SSRF-2 - START
"""Status: Fixed"""
#Description: CWE-918: Server-Side Request Forgery -> https://cwe.mitre.org/data/definitions/918.html
from src.controllers.adminController import development
admin_blueprint.route('/development', methods=['POST', 'GET'])(development)
#SSRF-2 - END

