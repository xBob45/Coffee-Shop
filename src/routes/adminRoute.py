from flask import Blueprint
from controllers.adminController import admin_panel, add_user, edit_user, delete_user

admin_blueprint = Blueprint('admin', __name__)


admin_blueprint.route('/admin', methods=['POST', 'GET'])(admin_panel)
admin_blueprint.route('/add', methods=['POST', 'GET'])(add_user)
admin_blueprint.route('/edit', methods=['POST', 'GET'])(edit_user)
admin_blueprint.route('/delete', methods=['POST', 'GET'])(delete_user)