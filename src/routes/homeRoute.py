from flask import Blueprint
from controllers.homeController import home
home_blueprint = Blueprint('home', __name__)
home_blueprint.route('/')(home)
