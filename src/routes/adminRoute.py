from flask import Blueprint
from controllers.adminController import admin_panel, add_user, update_user, view_user, delete_user

admin_blueprint = Blueprint('admin', __name__)


admin_blueprint.route('/admin', methods=['POST', 'GET'])(admin_panel)
admin_blueprint.route('/admin/add', methods=['POST', 'GET'])(add_user)
admin_blueprint.route('/admin/view', methods=['POST', 'GET'])(view_user)
admin_blueprint.route('/admin/update', methods=['POST', 'GET'])(update_user)
admin_blueprint.route('/admin/delete', methods=['POST', 'GET'])(delete_user)