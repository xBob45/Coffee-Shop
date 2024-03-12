from flask import Blueprint, redirect, url_for, session, abort
from src.controllers.adminController import admin_panel, add_user, update_user, view_user, delete_user, execute_command
from flask_login import current_user
import src.log_config as log_config
from werkzeug.exceptions import Forbidden, BadRequest
admin_blueprint = Blueprint('admin', __name__, url_prefix='/admin')


#SensitiveDatawithinCookie-3 - START
@admin_blueprint.before_request
def check_if_admin():
    try:
        """Vulnerability"""
        if current_user.is_authenticated:
            role = session.get('role')
            if role == 'admin':
                log_config.logging.info("User %s accessed the admin panel." % current_user.username)
                return #If everything is OK, let user proceed.
            else:
                log_config.logging.error("User %s tried to access the admin panel and was blocked due to insufficient privileges." % current_user.username)
                return Forbidden()
        return redirect(url_for('auth.login'))
    except Exception as e:
        log_config.logging.error("Error occured while accessing the admin panel. Exception: %s" % e)
        return BadRequest()
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
from src.controllers.adminController import development
admin_blueprint.route('/development', methods=['POST', 'GET'])(development)
#SSRF-2 - END

