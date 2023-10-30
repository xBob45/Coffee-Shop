from flask import Blueprint, redirect, url_for, flash
from controllers.adminController import admin_panel, add_user, update_user, view_user, delete_user
from flask_login import current_user

admin_blueprint = Blueprint('admin', __name__)

#-------------------------------------------Forced Browsing - START--------------------------------------------
@admin_blueprint.before_request
def check_admin_access():
    """Function checks if user trying to access has 'admin' role."""
    if not current_user.is_authenticated or not any(role.name == 'admin' for role in current_user.roles):
        return redirect(url_for('home.home'))
#-------------------------------------------Forced Browsing - START--------------------------------------------

admin_blueprint.route('/admin', methods=['POST', 'GET'])(admin_panel)
admin_blueprint.route('/admin/add', methods=['POST', 'GET'])(add_user)
admin_blueprint.route('/admin/view', methods=['POST', 'GET'])(view_user)
admin_blueprint.route('/admin/update', methods=['POST', 'GET'])(update_user)
admin_blueprint.route('/admin/delete', methods=['POST', 'GET'])(delete_user)