from flask import Blueprint, redirect, url_for
from controllers.adminController import admin_panel, add_user, update_user, view_user, delete_user
from flask_login import current_user
from attacks import config


ForcedBrowsing = config.getboolean('attacks', 'ForcedBrowsing')


admin_blueprint = Blueprint('admin', __name__, url_prefix='/admin')


if ForcedBrowsing == True:
    #-------------------------------------------A01 - Forced Browsing - START--------------------------------------------
    pass
else:
    @admin_blueprint.before_request
    def check_if_admin():
        """Function checks if user trying to access has 'admin' role and thus provides solution for Forced Browsing."""
        #If current user is not authenticated or not of the role function loops through is 'admin'
        if not current_user.is_authenticated or not any(role.name == 'admin' for role in current_user.roles):
            return redirect(url_for('home.home'))
    #-------------------------------------------A01 - Forced Browsing - END--------------------------------------------


admin_blueprint.route('', methods=['POST', 'GET'])(admin_panel)
admin_blueprint.route('/add', methods=['POST', 'GET'])(add_user)
admin_blueprint.route('/view', methods=['POST', 'GET'])(view_user)
admin_blueprint.route('/update', methods=['POST', 'GET'])(update_user)
admin_blueprint.route('/delete', methods=['POST', 'GET'])(delete_user)